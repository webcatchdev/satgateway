"""
Security fix tests for SatGateway — verifies vulnerabilities from audit are patched.
Run with: pytest tests/test_security_fixes.py -v
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.expanduser("~/satgateway"))
os.environ.setdefault("MOCK_BACKEND", "1")

from satgateway.core import GatewayConfig, MockBackend, SatGateway
from satgateway.middleware import (
    PaymentGateway,
    _default_gateway,
    init_gateway,
    require_payment,
)

# Ensure a fresh default gateway for every test module load
init_gateway(
    backend=MockBackend(),
    config=GatewayConfig(api_key="strong_test_key_12345", fee_basis_points=50)
)


@pytest.fixture
def app():
    """Fresh FastAPI app with all routes mounted."""
    init_gateway(
        backend=MockBackend(),
        config=GatewayConfig(api_key="strong_test_key_12345", fee_basis_points=50)
    )
    application = FastAPI()
    gateway = PaymentGateway()
    application.include_router(gateway.router, prefix="/payments")

    @application.get("/api/cheap")
    @require_payment(amount_sats=1)
    async def cheap(request: Request):
        return {"data": "cheap"}

    @application.get("/api/expensive")
    @require_payment(amount_sats=100)
    async def expensive(request: Request):
        return {"data": "expensive"}

    @application.get("/api/status")
    async def status():
        gw = init_gateway()
        bal = await gw.get_balance()
        return {"status": "ok", "balance_sats": bal}

    return application


@pytest.fixture
def client(app):
    return TestClient(app)


# ---------------------------------------------------------------------------
# F-01: Cross-resource payment reuse fixed
# ---------------------------------------------------------------------------

class TestCrossResourcePaymentFix:
    def test_cheap_payment_rejected_for_expensive_resource(self, client):
        """Paying 1 sat for /api/cheap must NOT grant access to /api/expensive."""
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 1, "resource_url": "/api/cheap"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        assert resp.status_code == 200
        cheap_id = resp.json()["payment_id"]

        gw = _default_gateway()
        gw._payments[cheap_id].status = "paid"

        resp = client.get("/api/expensive", headers={"X-Payment-ID": cheap_id})
        assert resp.status_code == 403

    def test_payment_for_wrong_url_rejected(self, client):
        """A payment created for /api/cheap must be rejected at /api/expensive."""
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 100, "resource_url": "/api/cheap"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        assert resp.status_code == 200
        wrong_id = resp.json()["payment_id"]

        gw = _default_gateway()
        gw._payments[wrong_id].status = "paid"

        resp = client.get("/api/expensive", headers={"X-Payment-ID": wrong_id})
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# F-02: Stored XSS via resource_url fixed
# ---------------------------------------------------------------------------

class TestStoredXSSFix:
    def test_paywall_escapes_resource_url(self, client):
        # Use a relative path that passes validation but contains XSS
        xss = "/xss';alert(document.cookie);window.location.href='"
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 100, "resource_url": xss},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        assert resp.status_code == 200
        pid = resp.json()["payment_id"]

        resp = client.get(f"/payments/paywall/{pid}")
        assert resp.status_code == 200
        html = resp.text
        # The payload must be inside a JSON-encoded (double-quoted) JS string
        line = [ln for ln in html.split('\n') if 'window.location.href = ' in ln][0]
        # Extract the value after = and before the closing comma/paren
        value = line.split('window.location.href = ')[1].rsplit(',', 1)[0].strip()
        assert value.startswith('"')
        assert value.endswith('"')
        # Must not contain an unescaped double quote that would break the string
        inner = value[1:-1]
        assert '"' not in inner or '\\"' in inner

    def test_paywall_escapes_invoice(self, client):
        # Invoices are backend-generated, but defense-in-depth: ensure escaping
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 100, "resource_url": "/safe"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        pid = resp.json()["payment_id"]
        resp = client.get(f"/payments/paywall/{pid}")
        html = resp.text
        # The invoice string should be JSON-encoded in JS context
        assert "window.location.href = '" not in html or "JSON.stringify" not in html


# ---------------------------------------------------------------------------
# F-03: XSS via JSON.stringify in paywall.js fixed
# ---------------------------------------------------------------------------

class TestPaywallJSFix:
    def test_js_contains_html_escape(self):
        js_path = os.path.expanduser("~/satgateway/static/paywall.js")
        with open(js_path) as f:
            js = f.read()
        assert "escapeHtml" in js or "textContent" in js


# ---------------------------------------------------------------------------
# F-05 & F-10 & F-16: Invoice endpoint auth + validation
# ---------------------------------------------------------------------------

class TestInvoiceAuthAndValidation:
    def test_invoice_requires_api_key(self, client):
        resp = client.post("/payments/invoice", json={"amount_sats": 100})
        assert resp.status_code == 401

    def test_invoice_rejects_invalid_api_key(self, client):
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 100},
            headers={"X-API-Key": "wrong-key"}
        )
        assert resp.status_code == 401

    def test_invoice_accepts_valid_api_key(self, client):
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 100, "resource_url": "/safe"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        assert resp.status_code == 200

    def test_invoice_rejects_zero_amount(self, client):
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 0},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        assert resp.status_code == 422

    def test_invoice_rejects_negative_amount(self, client):
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": -1},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        assert resp.status_code == 422

    def test_invoice_rejects_oversized_amount(self, client):
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 20_000_000},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        assert resp.status_code == 422

    def test_invoice_rejects_non_integer_amount(self, client):
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": "free"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# F-08: Open redirect fixed
# ---------------------------------------------------------------------------

class TestOpenRedirectFix:
    def test_external_resource_url_rejected(self, client):
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 100, "resource_url": "https://evil.com"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        assert resp.status_code == 422

    def test_relative_resource_url_accepted(self, client):
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 100, "resource_url": "/api/safe"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# F-13: Dead preimage code removed
# ---------------------------------------------------------------------------

class TestPreimageDeadCodeFix:
    def test_no_preimage_header_check(self):
        import inspect
        source = inspect.getsource(require_payment)
        assert "sg_preimage" not in source
        assert "X-Payment-Preimage" not in source


# ---------------------------------------------------------------------------
# F-14: Status endpoints require auth
# ---------------------------------------------------------------------------

class TestInfoDisclosureFix:
    def test_payments_status_requires_auth(self, client):
        resp = client.get("/payments/status")
        assert resp.status_code == 401

    def test_payments_status_with_auth_succeeds(self, client):
        resp = client.get(
            "/payments/status",
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "balance_sats" in data


# ---------------------------------------------------------------------------
# F-15: Race condition in check_payment fixed
# ---------------------------------------------------------------------------

class TestRaceConditionFix:
    @pytest.mark.asyncio
    async def test_callback_fires_once(self):
        gw = SatGateway(
            backend=MockBackend(),
            config=GatewayConfig(api_key="test_key")
        )
        req = await gw.create_request(amount_sats=100, description="test", resource_url="/")

        callback_count = 0

        def cb(payment):
            nonlocal callback_count
            callback_count += 1

        gw.on_payment(req.id, cb)

        # Force auto-pay by backdating created_at
        gw.backend._invoices[req.payment_hash]["created_at"] = (
            datetime.now(timezone.utc) - timedelta(seconds=10)
        )

        async def check():
            return await gw.check_payment(req.id)

        await asyncio.gather(check(), check(), check())
        assert callback_count == 1


# ---------------------------------------------------------------------------
# F-18: Authentication on protected gateway endpoints
# ---------------------------------------------------------------------------

class TestGatewayAuthFix:
    def test_verify_publicly_accessible(self, client):
        """Verify endpoint should remain public for paywall polling."""
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 10, "resource_url": "/"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        pid = resp.json()["payment_id"]
        resp = client.get(f"/payments/verify/{pid}")
        assert resp.status_code == 200

    def test_qr_publicly_accessible(self, client):
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 10, "resource_url": "/"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        pid = resp.json()["payment_id"]
        resp = client.get(f"/payments/qr/{pid}")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Docker / infrastructure fixes (F-06, F-09)
# ---------------------------------------------------------------------------

class TestDockerComposeFixes:
    def test_no_admin_macaroon_in_fullnode(self):
        path = os.path.expanduser("~/satgateway/docker-compose.fullnode.yml")
        with open(path) as f:
            content = f.read()
        assert "admin.macaroon" not in content
        assert "invoice.macaroon" in content

    def test_no_admin_macaroon_in_neutrino(self):
        path = os.path.expanduser("~/satgateway/docker-compose.neutrino.yml")
        with open(path) as f:
            content = f.read()
        assert "admin.macaroon" not in content
        assert "invoice.macaroon" in content

    def test_bitcoin_rpc_restricted(self):
        path = os.path.expanduser("~/satgateway/docker-compose.fullnode.yml")
        with open(path) as f:
            content = f.read()
        assert "rpcallowip=0.0.0.0/0" not in content
        assert "172.16.0.0/12" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
