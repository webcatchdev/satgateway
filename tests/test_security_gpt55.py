"""
Security regression tests for SatGateway — GPT-5.5 findings.
These tests verify that the vulnerabilities identified by GPT-5.5 are FIXED.

Run with: pytest tests/test_security_gpt55.py -v
"""

import asyncio
import base64
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, AsyncMock, MagicMock

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.expanduser("~/satgateway"))

from satgateway.core import SatGateway, GatewayConfig, MockBackend, PaymentRequest, LndBackend
from satgateway.middleware import require_payment, PaymentGateway, init_gateway, verify_api_key, InvoiceRequest

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

    @application.get("/", response_class=HTMLResponse)
    def home():
        return "<html><body>Home</body></html>"

    # Add security headers middleware (mirrors main.py)
    @application.middleware("http")
    async def add_security_headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        return response

    return application


@pytest.fixture
def client(app):
    return TestClient(app)


# ---------------------------------------------------------------------------
# NEW-01: Unbounded in-memory payment storage — FIXED
# ---------------------------------------------------------------------------

class TestUnboundedMemoryStorage:
    """
    _payments dict no longer grows without bound. Expired payments are
    evicted by cleanup_expired() and create_request() enforces max_stored_payments.
    """

    @pytest.mark.asyncio
    async def test_expired_payments_are_cleaned_up(self):
        gw = SatGateway(
            backend=MockBackend(),
            config=GatewayConfig(api_key="***", fee_basis_points=50)
        )
        for i in range(500):
            req = await gw.create_request(
                amount_sats=1,
                description=f"spam {i}",
                resource_url="/"
            )
            # Backdate so they are already expired
            req.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

        # Before cleanup: all 500 are in memory
        assert len(gw._payments) == 500
        # After cleanup: expired payments removed
        removed = gw.cleanup_expired()
        assert removed == 500
        assert len(gw._payments) == 0
        assert len(gw._locks) == 0

    @pytest.mark.asyncio
    async def test_storage_cap_is_enforced(self):
        gw = SatGateway(
            backend=MockBackend(),
            config=GatewayConfig(api_key="***", fee_basis_points=50, max_stored_payments=50)
        )
        for i in range(100):
            await gw.create_request(amount_sats=1, description="x", resource_url="/")

        # Cap enforced: only 50 stored
        assert len(gw._payments) == 50

    @pytest.mark.asyncio
    async def test_locks_are_cleaned_up_with_payments(self):
        gw = SatGateway(
            backend=MockBackend(),
            config=GatewayConfig(api_key="***", fee_basis_points=50)
        )
        for i in range(100):
            req = await gw.create_request(amount_sats=1, description="x", resource_url="/")
            # Force lock creation via check_payment
            await gw.check_payment(req.id)

        # Locks created
        assert len(gw._locks) == 100
        # Backdate all and clean up
        for p in gw._payments.values():
            p.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        gw.cleanup_expired()
        assert len(gw._locks) == 0


# ---------------------------------------------------------------------------
# NEW-02: LND TLS verification enforced by default — FIXED
# ---------------------------------------------------------------------------

class TestLndTlsVerificationEnforced:
    """
    LndBackend now requires a valid TLS certificate by default (verify_tls=True).
    It raises ValueError when cert is missing, instead of silently disabling TLS.
    """

    def test_tls_requires_cert_by_default(self):
        with pytest.raises(ValueError, match="LND TLS certificate is required"):
            LndBackend(
                host="https://lnd:8080",
                macaroon_hex="deadbeef"
            )

    def test_tls_requires_existing_cert_path(self):
        with pytest.raises(ValueError, match="LND TLS certificate is required"):
            LndBackend(
                host="https://lnd:8080",
                macaroon_hex="deadbeef",
                cert_path="/nonexistent/tls.cert"
            )

    def test_tls_can_be_disabled_for_dev(self):
        backend = LndBackend(
            host="https://lnd:8080",
            macaroon_hex="deadbeef",
            verify_tls=False
        )
        assert backend._ssl is False


# ---------------------------------------------------------------------------
# NEW-03: Paid payments expire after validity window — FIXED
# ---------------------------------------------------------------------------

class TestPaidPaymentExpires:
    """
    Once a payment is marked 'paid', it is only valid for
    payment_valid_for_seconds (default 1 hour). After that, check_payment
    returns paid=False with an expired flag.
    """

    @pytest.mark.asyncio
    async def test_old_paid_payment_is_rejected(self):
        gw = SatGateway(
            backend=MockBackend(),
            config=GatewayConfig(api_key="***", fee_basis_points=50)
        )
        req = await gw.create_request(amount_sats=100, description="test", resource_url="/api/expensive")
        req.status = "paid"
        req.paid_at = datetime.now(timezone.utc) - timedelta(days=365)

        status = await gw.check_payment(req.id)
        assert status["paid"] is False
        assert status.get("expired") is True

    def test_cookie_expires_and_header_also_respects_validity(self, client):
        from satgateway.middleware import _default_gateway
        gw = _default_gateway()
        req = gw.create_request(
            amount_sats=100,
            description="test",
            resource_url="http://testserver/api/expensive"
        )
        import asyncio
        req = asyncio.get_event_loop().run_until_complete(req)
        req.status = "paid"
        req.paid_at = datetime.now(timezone.utc) - timedelta(days=1)

        # Even with valid payment ID, old paid payment is rejected
        resp = client.get("/api/expensive", headers={"X-Payment-ID": req.id})
        # 402 because payment validity expired
        assert resp.status_code == 402


# ---------------------------------------------------------------------------
# NEW-04: Lightning preimage is cryptographically verified — FIXED
# ---------------------------------------------------------------------------

class TestPreimageVerified:
    """
    check_payment now verifies that SHA256(preimage) == payment_hash.
    A fake preimage from a malicious backend is rejected.
    """

    @pytest.mark.asyncio
    async def test_fake_preimage_is_rejected(self):
        gw = SatGateway(
            backend=MockBackend(),
            config=GatewayConfig(api_key="***", fee_basis_points=50)
        )
        req = await gw.create_request(amount_sats=100, description="test", resource_url="/")

        fake_preimage = "a" * 64
        with patch.object(gw.backend, "check_payment", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = {
                "paid": True,
                "preimage": fake_preimage,
                "amount_paid": 100
            }
            status = await gw.check_payment(req.id)

        # Fake preimage fails verification
        assert status["paid"] is False
        assert "fraud" in status.get("detail", "")
        assert req.preimage is None

    @pytest.mark.asyncio
    async def test_valid_preimage_is_accepted(self):
        gw = SatGateway(
            backend=MockBackend(),
            config=GatewayConfig(api_key="***", fee_basis_points=50)
        )
        req = await gw.create_request(amount_sats=100, description="test", resource_url="/")

        # Use the MockBackend's built-in valid preimage
        # Force auto-pay by backdating
        gw.backend._invoices[req.payment_hash]["created_at"] = (
            datetime.now(timezone.utc) - timedelta(seconds=10)
        )
        status = await gw.check_payment(req.id)
        assert status["paid"] is True
        assert req.preimage is not None
        # Verify it cryptographically matches
        expected_hash = hashlib.sha256(bytes.fromhex(req.preimage)).hexdigest()
        assert expected_hash == req.payment_hash


# ---------------------------------------------------------------------------
# NEW-06: Rate limiting on public endpoints — FIXED
# ---------------------------------------------------------------------------

class TestRateLimiting:
    """
    /payments/verify, /payments/qr, and /payments/paywall now have per-IP
    rate limiting. Excessive requests return 429 Too Many Requests.
    """

    def test_verify_endpoint_rate_limited(self, client):
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 10, "resource_url": "/"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        pid = resp.json()["payment_id"]

        # Rapid-fire requests — after the limit, 429 is returned
        statuses = []
        for _ in range(50):
            r = client.get(f"/payments/verify/{pid}")
            statuses.append(r.status_code)

        assert 429 in statuses

    def test_qr_endpoint_rate_limited(self, client):
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 10, "resource_url": "/"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        pid = resp.json()["payment_id"]

        statuses = []
        for _ in range(20):
            r = client.get(f"/payments/qr/{pid}")
            statuses.append(r.status_code)

        assert 429 in statuses


# ---------------------------------------------------------------------------
# NEW-07: python-jose removed — FIXED
# ---------------------------------------------------------------------------

class TestUnusedDependencyRemoved:
    """
    python-jose[cryptography] has been removed from requirements and
    pyproject.toml to reduce attack surface.
    """

    def test_python_jose_not_imported(self):
        import satgateway
        import satgateway.core
        import satgateway.middleware
        import main
        assert "jose" not in sys.modules

    def test_python_jose_not_in_requirements(self):
        req_path = os.path.expanduser("~/satgateway/requirements.txt")
        with open(req_path) as f:
            content = f.read()
        assert "python-jose" not in content

    def test_python_jose_not_in_pyproject(self):
        pyproject_path = os.path.expanduser("~/satgateway/pyproject.toml")
        with open(pyproject_path) as f:
            content = f.read()
        assert "python-jose" not in content


# ---------------------------------------------------------------------------
# NEW-08: CORS no longer falls back to wildcard — FIXED
# ---------------------------------------------------------------------------

class TestCorsRestricted:
    """
    main.py no longer falls back to allow_origins=["*"]. When ALLOWED_ORIGINS
    is unset, the default is an empty list, blocking all cross-origin requests.
    """

    def test_no_cors_wildcard_fallback(self):
        main_path = os.path.expanduser("~/satgateway/main.py")
        with open(main_path) as f:
            source = f.read()
        assert 'allow_origins = ["*"]' not in source
        assert "allow_origins=[\"*\"]" not in source


# ---------------------------------------------------------------------------
# NEW-09: Hardcoded weak credentials removed — FIXED
# ---------------------------------------------------------------------------

class TestHardcodedCredentialsRemoved:
    """
    Dockerfile no longer sets SATGATEWAY_KEY=changeme. docker-compose and
    lnd configs still have placeholder passwords but they are clearly labeled
    and the Dockerfile default has been removed.
    """

    def test_dockerfile_has_no_default_key(self):
        path = os.path.expanduser("~/satgateway/Dockerfile")
        with open(path) as f:
            content = f.read()
        assert "SATGATEWAY_KEY=changeme" not in content

    def test_docker_compose_uses_env_substitution(self):
        path = os.path.expanduser("~/satgateway/docker-compose.yml")
        with open(path) as f:
            content = f.read()
        assert "${SATGATEWAY_KEY}" in content


# ---------------------------------------------------------------------------
# NEW-10: Security headers added — FIXED
# ---------------------------------------------------------------------------

class TestSecurityHeadersPresent:
    """
    The application now sets X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy, and Content-Security-Policy on all responses.
    """

    def test_homepage_has_security_headers(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert "Content-Security-Policy" in resp.headers

    def test_paywall_has_security_headers(self, client):
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 10, "resource_url": "/"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        pid = resp.json()["payment_id"]
        resp = client.get(f"/payments/paywall/{pid}")
        assert resp.status_code == 200
        assert resp.headers.get("X-Frame-Options") == "DENY"


# ---------------------------------------------------------------------------
# NEW-11: API key comparison is constant-time — FIXED
# ---------------------------------------------------------------------------

class TestApiKeyConstantTime:
    """
    verify_api_key now uses hmac.compare_digest for constant-time comparison.
    """

    def test_api_key_uses_constant_time_comparison(self):
        import inspect
        source = inspect.getsource(verify_api_key)
        assert "hmac.compare_digest" in source


# ---------------------------------------------------------------------------
# NEW-12: LND error messages sanitized — FIXED
# ---------------------------------------------------------------------------

class TestLndErrorSanitized:
    """
    LndBackend.create_invoice now catches exceptions and raises a generic
    RuntimeError("Invoice service unavailable") instead of leaking raw LND
    response text to clients.
    """

    def test_create_invoice_error_is_generic(self):
        import inspect
        source = inspect.getsource(LndBackend.create_invoice)
        # Internal error text is still logged but the except block re-raises generically
        assert "Invoice service unavailable" in source

    def test_check_payment_error_is_generic(self):
        import inspect
        source = inspect.getsource(LndBackend.check_payment)
        assert "Payment verification service unavailable" in source


# ---------------------------------------------------------------------------
# NEW-13: aiohttp requests have timeouts — FIXED
# ---------------------------------------------------------------------------

class TestAiohttpTimeouts:
    """
    All aiohttp calls in LndBackend now include timeout=self._TIMEOUT.
    """

    def test_aiohttp_timeout_in_create_invoice(self):
        import inspect
        source = inspect.getsource(LndBackend.create_invoice)
        assert "timeout=self._TIMEOUT" in source

    def test_aiohttp_timeout_in_check_payment(self):
        import inspect
        source = inspect.getsource(LndBackend.check_payment)
        assert "timeout=self._TIMEOUT" in source

    def test_aiohttp_timeout_in_get_balance(self):
        import inspect
        source = inspect.getsource(LndBackend.get_balance)
        assert "timeout=self._TIMEOUT" in source


# ---------------------------------------------------------------------------
# NEW-14: Metadata size/depth bounded — FIXED
# ---------------------------------------------------------------------------

class TestMetadataBounded:
    """
    InvoiceRequest.metadata is now validated for size (16KB), depth (3),
    and top-level key count (50). Excessive metadata returns 422.
    """

    def test_deeply_nested_metadata_rejected(self, client):
        deep = {}
        current = deep
        for i in range(200):
            current["next"] = {}
            current = current["next"]

        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 10, "resource_url": "/", "metadata": deep},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        # Rejected by Pydantic validator
        assert resp.status_code == 422

    def test_large_metadata_rejected(self, client):
        large = {"key_" + str(i): "x" * 1000 for i in range(500)}
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 10, "resource_url": "/", "metadata": large},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        assert resp.status_code == 422

    def test_valid_metadata_accepted(self, client):
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 10, "resource_url": "/", "metadata": {"foo": "bar", "nested": {"a": 1}}},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# NEW-15: Payment IDs redacted from logs — FIXED
# ---------------------------------------------------------------------------

class TestPaymentIdsRedacted:
    """
    RedactAccessLog filter strips UUID-like payment IDs from uvicorn access
    logs without breaking request routing.
    """

    def test_redact_filter_exists(self):
        main_path = os.path.expanduser("~/satgateway/main.py")
        with open(main_path) as f:
            source = f.read()
        assert "RedactAccessLog" in source
        assert "[REDACTED]" in source
        # Must NOT be an ASGI middleware that mutates scope["path"]
        assert "scope[\"path\"]" not in source


# ---------------------------------------------------------------------------
# NEW-16: CORS explicitly allows X-Payment-ID (intentional design)
# ---------------------------------------------------------------------------

class TestCorsAllowsPaymentIdHeader:
    """
    CORS explicitly allows the X-Payment-ID header so that cross-origin
    paywall scripts can present payment proof. This is intentional and safe
    because origins are restricted via ALLOWED_ORIGINS, not wildcard.
    """

    def test_cors_allows_payment_id_header(self):
        main_path = os.path.expanduser("~/satgateway/main.py")
        with open(main_path) as f:
            source = f.read()
        assert "X-Payment-ID" in source
        assert "allow_headers" in source


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
