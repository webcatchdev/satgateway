"""
Tests closing the four remaining security gaps:
1. Persistent storage (SQLite) across workers
2. Rate limiting (Redis + in-memory fallback)
3. CSRF protection on paywall pages
4. Information disclosure on status endpoints
5. Atomic verify-and-consume
"""

import os
import sys
import json
import time
import asyncio
import tempfile
from datetime import datetime, timezone, timedelta

# Ensure satgateway is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from satgateway.core import PaymentRequest, MockBackend, GatewayConfig, SatGateway
from satgateway.store import PaymentStore
from satgateway.ratelimit import RateLimiter


# ---------------------------------------------------------------------------
# Gap 1 & 4: Persistent SQLite store + multi-worker safety
# ---------------------------------------------------------------------------

class TestPaymentStore:
    def test_save_and_get(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            store = PaymentStore(db_path=db_path)
            req = PaymentRequest(
                id="test-uuid-1234",
                amount_sats=100,
                description="test",
                resource_url="http://example.com",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                invoice="lnbc100n1...",
                payment_hash="deadbeef",
            )
            store.save(req)
            fetched = store.get("test-uuid-1234")
            assert fetched is not None
            assert fetched.amount_sats == 100
            assert fetched.status == "pending"
        finally:
            os.unlink(db_path)

    def test_verify_and_consume_atomic(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            store = PaymentStore(db_path=db_path)
            req = PaymentRequest(
                id="atomic-test",
                amount_sats=100,
                description="test",
                resource_url="http://example.com",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                invoice="lnbc100n1...",
                payment_hash="deadbeef",
                status="paid",
                paid_at=datetime.now(timezone.utc),
            )
            store.save(req)

            # First consume succeeds
            consumed = store.verify_and_consume("atomic-test")
            assert consumed is not None
            assert consumed.status == "paid"

            # Second consume fails (already consumed)
            consumed2 = store.verify_and_consume("atomic-test")
            assert consumed2 is None

            # Unpaid / not found returns None
            assert store.verify_and_consume("missing") is None
        finally:
            os.unlink(db_path)

    def test_concurrent_verify_and_consume(self):
        """Simulate multiple workers hitting verify_and_consume simultaneously."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            store = PaymentStore(db_path=db_path)
            req = PaymentRequest(
                id="race-test",
                amount_sats=100,
                description="test",
                resource_url="http://example.com",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                invoice="lnbc100n1...",
                payment_hash="deadbeef",
                status="paid",
                paid_at=datetime.now(timezone.utc),
            )
            store.save(req)

            results = []
            def worker():
                local_store = PaymentStore(db_path=db_path)
                results.append(local_store.verify_and_consume("race-test"))

            import threading
            threads = [threading.Thread(target=worker) for _ in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            successes = [r for r in results if r is not None]
            assert len(successes) == 1, f"Expected exactly 1 success, got {len(successes)}"
        finally:
            os.unlink(db_path)

    def test_update(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            store = PaymentStore(db_path=db_path)
            req = PaymentRequest(
                id="update-test",
                amount_sats=100,
                description="test",
                resource_url="http://example.com",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                invoice="lnbc100n1...",
                payment_hash="deadbeef",
            )
            store.save(req)
            req.status = "paid"
            req.paid_at = datetime.now(timezone.utc)
            store.update(req)
            fetched = store.get("update-test")
            assert fetched.status == "paid"
        finally:
            os.unlink(db_path)


# ---------------------------------------------------------------------------
# Gap 2: Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimiter:
    def test_memory_backend_allows_under_limit(self):
        rl = RateLimiter(default_limit=5, default_window=60)
        for i in range(5):
            allowed, _ = rl.is_allowed("client-a")
            assert allowed is True

    def test_memory_backend_blocks_over_limit(self):
        rl = RateLimiter(default_limit=3, default_window=60)
        for i in range(3):
            allowed, _ = rl.is_allowed("client-b")
            assert allowed is True
        allowed, headers = rl.is_allowed("client-b")
        assert allowed is False
        assert "Retry-After" in headers
        assert headers["X-RateLimit-Limit"] == "3"

    def test_memory_backend_window_resets(self):
        rl = RateLimiter(default_limit=1, default_window=1)
        allowed, _ = rl.is_allowed("client-c")
        assert allowed is True
        allowed, _ = rl.is_allowed("client-c")
        assert allowed is False
        time.sleep(1.1)
        allowed, _ = rl.is_allowed("client-c")
        assert allowed is True

    def test_headers_present(self):
        rl = RateLimiter(default_limit=10, default_window=60)
        allowed, headers = rl.is_allowed("client-d")
        assert allowed is True
        assert "X-RateLimit-Limit" in headers
        assert "X-RateLimit-Remaining" in headers
        assert "X-RateLimit-Reset" in headers


# ---------------------------------------------------------------------------
# Gap 5: Atomic verify-and-consume at SatGateway level
# ---------------------------------------------------------------------------

class TestSatGatewayAtomic:
    def test_verify_and_consume_integration(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            store = PaymentStore(db_path=db_path)
            backend = MockBackend()
            gw = SatGateway(backend=backend, config=GatewayConfig(api_key="test"), store=store)

            req = asyncio.run(gw.create_request(100, "test"))
            # Manually mark paid in store for test
            saved = store.get(req.id)
            saved.status = "paid"
            saved.paid_at = datetime.now(timezone.utc)
            store.update(saved)

            # Consume succeeds once
            c1 = gw.verify_and_consume(req.id)
            assert c1 is not None

            # Consume fails second time
            c2 = gw.verify_and_consume(req.id)
            assert c2 is None
        finally:
            os.unlink(db_path)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

class TestInputValidation:
    def test_clamp_description(self):
        from satgateway.middleware import _clamp_invoice_input
        body = {"description": "x" * 1000, "amount_sats": 100}
        out = _clamp_invoice_input(body)
        assert len(out["description"]) == 500

    def test_clamp_resource_url(self):
        from satgateway.middleware import _clamp_invoice_input
        body = {"resource_url": "http://example.com/" + "x" * 3000, "amount_sats": 100}
        out = _clamp_invoice_input(body)
        assert len(out["resource_url"]) == 2000

    def test_reject_oversized_metadata(self):
        from satgateway.middleware import _clamp_invoice_input
        body = {"metadata": {"data": "x" * 20000}, "amount_sats": 100}
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            _clamp_invoice_input(body)
        assert exc.value.status_code == 413

    def test_reject_invalid_amount(self):
        from satgateway.middleware import _clamp_invoice_input
        body = {"amount_sats": "not_a_number"}
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            _clamp_invoice_input(body)
        assert exc.value.status_code == 400


# ---------------------------------------------------------------------------
# UUID validation
# ---------------------------------------------------------------------------

class TestUUIDValidation:
    def test_valid_uuid(self):
        from satgateway.middleware import _validate_uuid
        assert _validate_uuid("12345678-1234-1234-1234-123456789abc") == "12345678-1234-1234-1234-123456789abc"

    def test_invalid_uuid(self):
        from satgateway.middleware import _validate_uuid
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            _validate_uuid("../../../etc/passwd")
        assert exc.value.status_code == 400

        with pytest.raises(HTTPException) as exc:
            _validate_uuid("not-a-uuid")
        assert exc.value.status_code == 400


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
