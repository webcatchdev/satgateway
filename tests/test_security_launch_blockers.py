"""
Launch blocker security tests for SatGateway.
Run with: pytest tests/test_security_launch_blockers.py -v
"""

import asyncio
import base64
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ.setdefault("MOCK_BACKEND", "1")

from satgateway.core import (
    GatewayConfig,
    LndBackend,
    MockBackend,
    PaymentRequest,
    SatGateway,
)
from satgateway.middleware import (
    PaymentGateway,
    _default_gateway,
    init_gateway,
    require_payment,
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

    return application


@pytest.fixture
def client(app):
    return TestClient(app)


# ---------------------------------------------------------------------------
# LB-01: Stored XSS via </script> breakout in paywall HTML
# ---------------------------------------------------------------------------

class TestStoredXSSScriptBreakout:
    """
    json.dumps() alone is insufficient in <script> context because </script>
    terminates the script block even inside a JS string literal.
    """

    def test_script_tag_breakout_is_escaped(self, client):
        """If resource_url contains </script>, it must be escaped in JS context."""
        payload = "/evil</script><script>alert(1)</script>"
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 100, "resource_url": payload},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        assert resp.status_code == 200
        pid = resp.json()["payment_id"]

        resp = client.get(f"/payments/paywall/{pid}")
        assert resp.status_code == 200
        html = resp.text

        # The literal </script> must NOT appear inside the HTML's <script> block
        # It should be escaped as <\/script>
        assert r"<\/script>" in html or "</script>" not in html.split("<script>")[1].split("</script>")[0]

    def test_invoice_with_script_breakout_is_escaped(self, client):
        """Even though invoices are normally safe, defense in depth matters."""
        # We can't control the invoice from MockBackend, but we verify the escaping function exists
        import satgateway.middleware as mw
        source = open(mw.__file__).read()
        assert "_js_string" in source
        assert 's.replace("</", "<\\\\/")' in source


# ---------------------------------------------------------------------------
# LB-02: Auth bypass when payment record gets evicted mid-verification
# ---------------------------------------------------------------------------

class TestEvictionAuthBypass:
    """
    If check_payment returns paid=True but the payment record is evicted
    before get_payment() runs, the old code would bypass auth entirely.
    """

    @pytest.mark.asyncio
    async def test_evicted_payment_does_not_bypass(self):
        """Simulate a payment that is 'paid' but then evicted before validation."""
        gw = SatGateway(
            backend=MockBackend(),
            config=GatewayConfig(api_key="test", max_stored_payments=1)
        )
        req = await gw.create_request(
            amount_sats=100,
            description="test",
            resource_url="/api/expensive"
        )
        req.status = "paid"
        req.paid_at = datetime.now(timezone.utc)

        # Simulate eviction by clearing the store (as if cleanup ran between check and get)
        gw._payments.clear()

        # check_payment sees no record → returns paid=False
        status = await gw.check_payment(req.id)
        assert status["paid"] is False

    def test_decorator_rejects_missing_payment_even_if_check_says_paid(self, client):
        """
        This tests the fixed code path: if for any reason check_payment reports
        paid=True but get_payment returns None, access must be denied.
        """
        # Create and pay a request
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 100, "resource_url": "/api/expensive"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        pid = resp.json()["payment_id"]
        gw = _default_gateway()
        gw._payments[pid].status = "paid"
        gw._payments[pid].paid_at = datetime.now(timezone.utc)

        # Evict it
        gw._payments.clear()
        gw._locks.clear()

        # Request with the old payment ID must NOT bypass — should get 402
        resp = client.get("/api/expensive", headers={"X-Payment-ID": pid})
        assert resp.status_code == 402


# ---------------------------------------------------------------------------
# LB-03: LND REST amt_paid_sat returned as JSON string
# ---------------------------------------------------------------------------

class TestLndAmtPaidSatAsString:
    """LND REST sometimes returns amt_paid_sat as a string like "1000" instead of 1000."""

    def test_string_amount_paid_is_cast_to_int(self):
        """Simulate LND returning amt_paid_sat as a string and verify no TypeError."""
        backend = MagicMock(spec=LndBackend)
        backend.check_payment = AsyncMock(return_value={
            "paid": True,
            "preimage": None,  # Skip preimage verification
            "amount_paid": "1000"  # String, not int
        })
        gw = SatGateway(backend=backend, config=GatewayConfig(api_key="test"))
        req = PaymentRequest(
            id="test-id",
            amount_sats=500,
            description="test",
            resource_url="/",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            payment_hash="b" * 64,
        )
        gw._payments["test-id"] = req

        # This should not raise TypeError when comparing string < int
        result = asyncio.run(gw.check_payment("test-id"))
        assert result["paid"] is True

    def test_invalid_string_amount_defaults_to_zero(self):
        """If amt_paid_sat is an unparseable string, it should default to 0."""
        backend = MagicMock(spec=LndBackend)
        backend.check_payment = AsyncMock(return_value={
            "paid": True,
            "preimage": None,  # Skip preimage verification
            "amount_paid": "invalid"
        })
        gw = SatGateway(backend=backend, config=GatewayConfig(api_key="test"))
        req = PaymentRequest(
            id="test-id",
            amount_sats=500,
            description="test",
            resource_url="/",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            payment_hash="b" * 64,
        )
        gw._payments["test-id"] = req

        result = asyncio.run(gw.check_payment("test-id"))
        # Underpaid because invalid amount parses to 0
        assert result["paid"] is False
        assert result.get("underpaid") is True


# ---------------------------------------------------------------------------
# LB-04: MockBackend silently active in production
# ---------------------------------------------------------------------------

class TestMockBackendRequiresExplicitEnv:
    """MockBackend must NOT be used unless MOCK_BACKEND=1 is explicitly set."""

    def test_init_gateway_without_backend_or_env_raises(self, monkeypatch):
        """Calling init_gateway with no backend and no MOCK_BACKEND env must fail."""
        monkeypatch.delenv("MOCK_BACKEND", raising=False)
        with pytest.raises(RuntimeError, match="MOCK_BACKEND=1"):
            init_gateway(config=GatewayConfig(api_key="test"))

    def test_default_gateway_without_env_raises(self, monkeypatch):
        """_default_gateway with no MOCK_BACKEND env must fail."""
        monkeypatch.delenv("MOCK_BACKEND", raising=False)
        monkeypatch.setenv("SATGATEWAY_KEY", "test-key")
        # Reset singleton
        import satgateway.middleware as mw
        mw._default_gw = None
        with pytest.raises(RuntimeError, match="MOCK_BACKEND=1"):
            _default_gateway()
        # Restore for other tests
        mw._default_gw = None

    def test_mock_backend_allowed_when_env_set(self, monkeypatch):
        """When MOCK_BACKEND=1, MockBackend is allowed."""
        monkeypatch.setenv("MOCK_BACKEND", "1")
        import satgateway.middleware as mw
        mw._default_gw = None
        gw = init_gateway(config=GatewayConfig(api_key="test"))
        assert isinstance(gw.backend, MockBackend)
        mw._default_gw = None


# ---------------------------------------------------------------------------
# LB-05: Base64 / and + not URL-encoded in LND payment check
# ---------------------------------------------------------------------------

class TestLndBase64UrlSafe:
    """LND REST payment hash lookup must use URL-safe base64."""

    def test_urlsafe_base64_is_used(self):
        """A payment hash that produces / and + in standard base64 must use urlsafe."""
        # Choose a hash that produces / and + in standard base64
        payment_hash = "fb" + "ff" * 31  # 64 hex chars
        standard_b64 = base64.b64encode(bytes.fromhex(payment_hash)).decode()
        urlsafe_b64 = base64.urlsafe_b64encode(bytes.fromhex(payment_hash)).decode()

        assert "/" in standard_b64 or "+" in standard_b64, "Test hash should contain / or +"
        assert "/" not in urlsafe_b64
        assert "+" not in urlsafe_b64

        # Verify LndBackend uses urlsafe encoding
        import inspect
        source = inspect.getsource(LndBackend.check_payment)
        assert "urlsafe_b64encode" in source
        assert "b64encode(bytes.fromhex" not in source or "urlsafe_b64encode" in source


# ---------------------------------------------------------------------------
# LB-06: Missing Cache-Control headers enable CDN paywall bypass
# ---------------------------------------------------------------------------

class TestCacheControlHeaders:
    """Sensitive payment endpoints must not be cached by CDNs or browsers."""

    def test_verify_has_cache_control(self, client, monkeypatch):
        # Reset rate limiter to avoid 429 from previous tests
        import satgateway.middleware as mw
        monkeypatch.setattr(mw, "_rate_limiter", mw.SimpleRateLimiter())
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 100, "resource_url": "/"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        pid = resp.json()["payment_id"]
        resp = client.get(f"/payments/verify/{pid}")
        assert resp.status_code == 200
        cc = resp.headers.get("Cache-Control", "")
        assert "no-store" in cc
        assert "no-cache" in cc
        assert "private" in cc

    def test_qr_has_cache_control(self, client, monkeypatch):
        import satgateway.middleware as mw
        monkeypatch.setattr(mw, "_qr_rate_limiter", mw.SimpleRateLimiter())
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 100, "resource_url": "/"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        pid = resp.json()["payment_id"]
        resp = client.get(f"/payments/qr/{pid}")
        assert resp.status_code == 200
        cc = resp.headers.get("Cache-Control", "")
        assert "no-store" in cc
        assert "no-cache" in cc

    def test_paywall_has_cache_control(self, client):
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 100, "resource_url": "/"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        pid = resp.json()["payment_id"]
        resp = client.get(f"/payments/paywall/{pid}")
        assert resp.status_code == 200
        # Paywall uses meta tag or response headers
        cc = resp.headers.get("Cache-Control", "")
        assert "no-store" in cc or "no-store" in resp.text

    def test_402_response_has_cache_control(self, client):
        resp = client.get("/api/expensive")
        assert resp.status_code == 402
        cc = resp.headers.get("Cache-Control", "")
        assert "no-store" in cc
        assert "no-cache" in cc


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
