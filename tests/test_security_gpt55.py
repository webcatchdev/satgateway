"""
Security audit tests for SatGateway — GPT-5.5 findings.
These tests demonstrate vulnerabilities that previous audits missed or that
were reported but remain unfixed in the current codebase.

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

    return application


@pytest.fixture
def client(app):
    return TestClient(app)


# ---------------------------------------------------------------------------
# NEW-01: Unbounded in-memory payment storage (F-11 reported but NOT fixed)
# ---------------------------------------------------------------------------

class TestUnboundedMemoryStorage:
    """
    The _payments dict grows without bound because expired and paid
    payments are never evicted. An attacker with a valid API key can
    exhaust server memory by creating millions of invoices.
    """

    @pytest.mark.asyncio
    async def test_payments_never_cleaned_up(self):
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

        # All 500 expired payments are STILL in memory
        assert len(gw._payments) == 500

    @pytest.mark.asyncio
    async def test_locks_never_cleaned_up(self):
        """Each payment ID creates an asyncio.Lock that lives forever."""
        gw = SatGateway(
            backend=MockBackend(),
            config=GatewayConfig(api_key="***", fee_basis_points=50)
        )
        for i in range(500):
            req = await gw.create_request(amount_sats=1, description="x", resource_url="/")
            # Force lock creation via check_payment
            await gw.check_payment(req.id)

        assert len(gw._locks) == 500


# ---------------------------------------------------------------------------
# NEW-02: LND TLS verification disabled by default (F-19 reported but NOT fixed)
# ---------------------------------------------------------------------------

class TestLndTlsVerificationDisabled:
    """
    LndBackend sets self._ssl = False when no cert_path is provided,
    disabling TLS certificate verification and enabling MITM attacks.
    """

    def test_tls_disabled_when_no_cert(self):
        backend = LndBackend(
            host="https://lnd:8080",
            macaroon_hex="deadbeef"
        )
        assert backend._ssl is False

    def test_tls_disabled_for_missing_cert_path(self):
        backend = LndBackend(
            host="https://lnd:8080",
            macaroon_hex="deadbeef",
            cert_path="/nonexistent/tls.cert"
        )
        assert backend._ssl is False


# ---------------------------------------------------------------------------
# NEW-03: Paid payments never expire — permanent replay (NEW finding)
# ---------------------------------------------------------------------------

class TestPermanentPaymentReplay:
    """
    Once a payment is marked 'paid', check_payment returns paid=True
    forever with no expiration or revocation. A single payment grants
    lifetime access. The cookie expires in 1 hour but the payment ID
    itself can be reused indefinitely via the X-Payment-ID header.
    """

    @pytest.mark.asyncio
    async def test_paid_payment_valid_forever(self):
        gw = SatGateway(
            backend=MockBackend(),
            config=GatewayConfig(api_key="***", fee_basis_points=50)
        )
        req = await gw.create_request(amount_sats=100, description="test", resource_url="/api/expensive")
        # Manually mark as paid
        req.status = "paid"
        req.paid_at = datetime.now(timezone.utc) - timedelta(days=365)

        status = await gw.check_payment(req.id)
        assert status["paid"] is True
        # No expiration of the payment proof itself
        assert "expires_at" not in status or status.get("paid") is True

    def test_cookie_expires_but_header_does_not(self, client):
        """The sg_payment_id cookie has max_age=3600, but X-Payment-ID header has no expiry."""
        from satgateway.middleware import _default_gateway
        gw = _default_gateway()
        # Create payment directly with full URL to match require_payment check
        req = gw.create_request(
            amount_sats=100,
            description="test",
            resource_url="http://testserver/api/expensive"
        )
        # Run the async create_request
        import asyncio
        req = asyncio.get_event_loop().run_until_complete(req)
        req.status = "paid"

        # Even if cookie is gone, header still works
        resp = client.get("/api/expensive", headers={"X-Payment-ID": req.id})
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# NEW-04: Lightning preimage not cryptographically verified (NEW finding)
# ---------------------------------------------------------------------------

class TestPreimageNotVerified:
    """
    When check_payment receives a preimage from the backend, it stores it
    but NEVER verifies sha256(preimage) == payment_hash. A malicious backend
    or MITM can claim any payment is settled with an arbitrary fake preimage.
    """

    @pytest.mark.asyncio
    async def test_preimage_never_verified(self):
        gw = SatGateway(
            backend=MockBackend(),
            config=GatewayConfig(api_key="***", fee_basis_points=50)
        )
        req = await gw.create_request(amount_sats=100, description="test", resource_url="/")

        # Simulate a malicious backend returning paid=True with a fake preimage
        fake_preimage = "a" * 64
        with patch.object(gw.backend, "check_payment", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = {
                "paid": True,
                "preimage": fake_preimage,
                "amount_paid": 100
            }
            status = await gw.check_payment(req.id)

        assert status["paid"] is True
        assert req.preimage == fake_preimage
        # The preimage is accepted without cryptographic verification
        expected_hash = hashlib.sha256(bytes.fromhex(fake_preimage)).hexdigest()
        assert req.payment_hash != expected_hash  # Fake preimage does NOT match real payment_hash


# ---------------------------------------------------------------------------
# NEW-05: No rate limiting on public endpoints (F-20 reported but NOT fixed)
# ---------------------------------------------------------------------------

class TestNoRateLimiting:
    """
    /payments/verify, /payments/qr, and /payments/paywall have no rate
    limiting. An attacker can aggressively poll or request CPU-intensive
    QR generation to DoS the server.
    """

    def test_verify_endpoint_no_rate_limit(self, client):
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 10, "resource_url": "/"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        pid = resp.json()["payment_id"]

        # Rapid-fire 50 requests — all succeed with no throttling
        for _ in range(50):
            r = client.get(f"/payments/verify/{pid}")
            assert r.status_code == 200

    def test_qr_endpoint_no_rate_limit(self, client):
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 10, "resource_url": "/"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        pid = resp.json()["payment_id"]

        for _ in range(20):
            r = client.get(f"/payments/qr/{pid}")
            assert r.status_code == 200


# ---------------------------------------------------------------------------
# NEW-06: python-jose unused dependency with known CVEs (NEW finding)
# ---------------------------------------------------------------------------

class TestUnusedDependency:
    """
    python-jose[cryptography] is listed in requirements but never imported
    or used. It has known vulnerabilities (CVE-2024-33663, CVE-2024-33664).
    """

    def test_python_jose_not_imported(self):
        import satgateway
        import satgateway.core
        import satgateway.middleware
        import main
        # None of the source files import jose
        assert "jose" not in sys.modules

    def test_python_jose_in_requirements(self):
        req_path = os.path.expanduser("~/satgateway/requirements.txt")
        with open(req_path) as f:
            content = f.read()
        assert "python-jose" in content


# ---------------------------------------------------------------------------
# NEW-07: CORS defaults to wildcard when ALLOWED_ORIGINS unset (F-17 fix incomplete)
# ---------------------------------------------------------------------------

class TestCorsWildcardFallback:
    """
    main.py checks ALLOWED_ORIGINS env var; if unset, it falls back to ["*"].
    Production deployments that forget to set the env var remain wide open.
    """

    def test_cors_fallback_to_wildcard(self):
        import importlib
        # main.py reads os.getenv at import time; we can inspect the code
        main_path = os.path.expanduser("~/satgateway/main.py")
        with open(main_path) as f:
            source = f.read()
        assert 'allow_origins = ["*"]' in source or "allow_origins=[\"*\"]" in source


# ---------------------------------------------------------------------------
# NEW-08: Hardcoded weak credentials in Docker / LND configs (NEW finding)
# ---------------------------------------------------------------------------

class TestHardcodedWeakCredentials:
    """
    docker-compose.fullnode.yml and lnd-fullnode.conf contain the weak
    placeholder password CHANGE_ME_STRONG_PASSWORD. Dockerfile sets
    SATGATEWAY_KEY=changeme. If deployed unchanged, these are trivially
    guessable.
    """

    def test_dockerfile_default_key(self):
        path = os.path.expanduser("~/satgateway/Dockerfile")
        with open(path) as f:
            content = f.read()
        assert "SATGATEWAY_KEY=changeme" in content

    def test_docker_compose_weak_rpc_password(self):
        path = os.path.expanduser("~/satgateway/docker-compose.fullnode.yml")
        with open(path) as f:
            content = f.read()
        assert "CHANGE_ME_STRONG_PASSWORD" in content

    def test_lnd_config_weak_rpc_password(self):
        path = os.path.expanduser("~/satgateway/lnd-fullnode.conf")
        with open(path) as f:
            content = f.read()
        assert "CHANGE_ME_STRONG_PASSWORD" in content


# ---------------------------------------------------------------------------
# NEW-09: Missing security headers (NEW finding)
# ---------------------------------------------------------------------------

class TestMissingSecurityHeaders:
    """
    The application sets no HSTS, X-Frame-Options, X-Content-Type-Options,
    or CSP headers, making it vulnerable to clickjacking and MIME-sniffing.
    """

    def test_homepage_missing_security_headers(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "X-Frame-Options" not in resp.headers
        assert "X-Content-Type-Options" not in resp.headers
        assert "Strict-Transport-Security" not in resp.headers
        assert "Content-Security-Policy" not in resp.headers

    def test_paywall_missing_security_headers(self, client):
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 10, "resource_url": "/"},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        pid = resp.json()["payment_id"]
        resp = client.get(f"/payments/paywall/{pid}")
        assert resp.status_code == 200
        assert "X-Frame-Options" not in resp.headers


# ---------------------------------------------------------------------------
# NEW-10: API key comparison not constant-time (NEW finding)
# ---------------------------------------------------------------------------

class TestApiKeyTimingAttack:
    """
    verify_api_key uses != for string comparison, which short-circuits on
    the first mismatched character. An attacker can measure timing
    differences to guess the API key one byte at a time.
    """

    def test_api_key_uses_non_constant_time_comparison(self):
        import inspect
        source = inspect.getsource(verify_api_key)
        assert "!=" in source
        assert "hmac.compare_digest" not in source
        assert "secrets.compare_digest" not in source


# ---------------------------------------------------------------------------
# NEW-11: LND error messages leak internal information (NEW finding)
# ---------------------------------------------------------------------------

class TestLndErrorInfoLeak:
    """
    LndBackend.create_invoice and check_payment raise RuntimeError containing
    the full HTTP status and response text from LND. If these propagate to
    HTTP responses, they reveal LND version, paths, or internal state.
    """

    def test_create_invoice_error_includes_lnd_response(self):
        import inspect
        source = inspect.getsource(LndBackend.create_invoice)
        assert "await resp.text()" in source
        assert "raise RuntimeError" in source

    def test_check_payment_error_includes_lnd_response(self):
        import inspect
        source = inspect.getsource(LndBackend.check_payment)
        assert "await resp.json()" in source


# ---------------------------------------------------------------------------
# NEW-12: aiohttp requests lack timeout (NEW finding)
# ---------------------------------------------------------------------------

class TestAiohttpNoTimeout:
    """
    All aiohttp calls in LndBackend omit the timeout parameter. A hung LND
    connection can block gateway coroutines indefinitely, causing DoS.
    """

    def test_aiohttp_no_timeout_in_create_invoice(self):
        import inspect
        source = inspect.getsource(LndBackend.create_invoice)
        assert "timeout" not in source

    def test_aiohttp_no_timeout_in_check_payment(self):
        import inspect
        source = inspect.getsource(LndBackend.check_payment)
        assert "timeout" not in source

    def test_aiohttp_no_timeout_in_get_balance(self):
        import inspect
        source = inspect.getsource(LndBackend.get_balance)
        assert "timeout" not in source


# ---------------------------------------------------------------------------
# NEW-13: Metadata size/depth unbounded (NEW finding)
# ---------------------------------------------------------------------------

class TestUnboundedMetadata:
    """
    InvoiceRequest.metadata accepts arbitrary dicts with no size or depth
    limits. An attacker can send huge or deeply nested metadata to exhaust
    memory or cause recursion errors.
    """

    def test_metadata_accepts_deeply_nested_dict(self, client):
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
        # Pydantic accepts it without complaint
        assert resp.status_code == 200

    def test_metadata_accepts_large_dict(self, client):
        large = {"key_" + str(i): "x" * 1000 for i in range(500)}
        resp = client.post(
            "/payments/invoice",
            json={"amount_sats": 10, "resource_url": "/", "metadata": large},
            headers={"X-API-Key": "strong_test_key_12345"}
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# NEW-14: Payment IDs logged in server.log (F-21 reported but NOT fixed)
# ---------------------------------------------------------------------------

class TestPaymentIdsInLogs:
    """
    Uvicorn access logs include full URLs containing payment IDs. If logs
    are exposed, attackers can harvest payment IDs and replay them.
    """

    def test_server_log_contains_payment_ids(self):
        log_path = os.path.expanduser("~/satgateway/server.log")
        with open(log_path) as f:
            content = f.read()
        # The existing log file already contains payment IDs
        assert "/payments/verify/" in content
        import re
        uuids = re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", content)
        assert len(uuids) > 0


# ---------------------------------------------------------------------------
# NEW-15: CORS allows X-Payment-ID from any origin (NEW finding)
# ---------------------------------------------------------------------------

class TestCorsExposesPaymentIdHeader:
    """
    CORS explicitly allows the X-Payment-ID header. Combined with wildcard
    origins, any website can read payment status or replay payment IDs
    cross-origin.
    """

    def test_cors_allows_payment_id_header(self):
        main_path = os.path.expanduser("~/satgateway/main.py")
        with open(main_path) as f:
            source = f.read()
        assert "X-Payment-ID" in source
        assert "allow_headers" in source


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
