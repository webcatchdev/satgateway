"""Tests for SatGateway core engine."""

import pytest
from datetime import datetime, timezone, timedelta

from satgateway.core import (
    MockBackend, GatewayConfig, SatGateway,
    PaymentRequest,
)
from satgateway.store import PaymentStore


class TestMockBackend:
    @pytest.mark.asyncio
    async def test_create_invoice(self):
        backend = MockBackend()
        result = await backend.create_invoice(100, "test")
        assert "invoice" in result
        assert "payment_hash" in result
        assert result["invoice"].startswith("lnbc100")

    @pytest.mark.asyncio
    async def test_check_payment_unpaid(self):
        backend = MockBackend()
        result = await backend.create_invoice(100, "test")
        check = await backend.check_payment(result["payment_hash"])
        assert check["paid"] is False

    @pytest.mark.asyncio
    async def test_check_payment_auto_pay(self):
        backend = MockBackend()
        result = await backend.create_invoice(100, "test")
        # Mock auto-pays after 5 seconds — backdate created_at
        inv = backend._invoices[result["payment_hash"]]
        inv["created_at"] = datetime.now(timezone.utc) - timedelta(seconds=10)
        check = await backend.check_payment(result["payment_hash"])
        assert check["paid"] is True
        assert check["amount_paid"] == 100

    @pytest.mark.asyncio
    async def test_get_balance(self):
        backend = MockBackend()
        assert await backend.get_balance() == 1_000_000


class TestPaymentStore:
    def test_save_and_load(self, temp_db):
        store = PaymentStore(temp_db)
        req = PaymentRequest(
            id="test-123",
            amount_sats=100,
            description="test",
            resource_url="/api/secret",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        store.save(req)
        loaded = store.load("test-123")
        assert loaded is not None
        assert loaded.amount_sats == 100
        assert loaded.resource_url == "/api/secret"

    def test_load_all(self, temp_db):
        store = PaymentStore(temp_db)
        for i in range(3):
            req = PaymentRequest(
                id=f"test-{i}",
                amount_sats=100,
                description="test",
                resource_url="/api/secret",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
            )
            store.save(req)
        all_payments = store.load_all()
        assert len(all_payments) == 3

    def test_consume(self, temp_db):
        store = PaymentStore(temp_db)
        req = PaymentRequest(
            id="test-123",
            amount_sats=100,
            description="test",
            resource_url="/api/secret",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        store.save(req)
        assert store.consume("test-123") is True
        assert store.consume("test-123") is False  # already consumed

    def test_update_status(self, temp_db):
        store = PaymentStore(temp_db)
        req = PaymentRequest(
            id="test-123",
            amount_sats=100,
            description="test",
            resource_url="/api/secret",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        store.save(req)
        now = datetime.now(timezone.utc).isoformat()
        store.update_status("test-123", "paid", now, "preimage123")
        loaded = store.load("test-123")
        assert loaded.status == "paid"
        assert loaded.preimage == "preimage123"


class TestSatGateway:
    @pytest.mark.asyncio
    async def test_create_request_validation(self, gateway):
        with pytest.raises(ValueError):
            await gateway.create_request(amount_sats=0, description="test")
        with pytest.raises(ValueError):
            await gateway.create_request(amount_sats=100_000_000, description="test")

    @pytest.mark.asyncio
    async def test_create_request(self, gateway):
        req = await gateway.create_request(amount_sats=100, description="test", resource_url="/api/secret")
        assert req.amount_sats == 100
        assert req.resource_url == "/api/secret"
        assert req.status == "pending"
        assert req.invoice is not None

    @pytest.mark.asyncio
    async def test_check_payment_not_found(self, gateway):
        result = await gateway.check_payment("nonexistent")
        assert result["found"] is False

    @pytest.mark.asyncio
    async def test_verify_payment_scope(self, gateway):
        req = await gateway.create_request(amount_sats=100, description="test", resource_url="/api/secret")
        # Not paid yet
        assert gateway.verify_payment(req.id, 100, "/api/secret") is False

    @pytest.mark.asyncio
    async def test_verify_payment_wildcard_blocked(self, gateway):
        req = await gateway.create_request(amount_sats=100, description="test", resource_url="")
        # Simulate payment (mock auto-pays after backdating)
        inv = gateway.backend._invoices[req.payment_hash]
        inv["created_at"] = datetime.now(timezone.utc) - timedelta(seconds=10)
        await gateway.check_payment(req.id)
        # Blank resource_url should NOT unlock /api/secret
        assert gateway.verify_payment(req.id, 100, "/api/secret") is False
        # But SHOULD work for exact match (empty string)
        assert gateway.verify_payment(req.id, 100, "") is True

    @pytest.mark.asyncio
    async def test_verify_payment_amount_mismatch(self, gateway):
        req = await gateway.create_request(amount_sats=100, description="test", resource_url="/api/secret")
        inv = gateway.backend._invoices[req.payment_hash]
        inv["created_at"] = datetime.now(timezone.utc) - timedelta(seconds=10)
        await gateway.check_payment(req.id)
        assert gateway.verify_payment(req.id, 50, "/api/secret") is False

    @pytest.mark.asyncio
    async def test_consume_payment(self, gateway):
        req = await gateway.create_request(amount_sats=100, description="test", resource_url="/api/secret")
        inv = gateway.backend._invoices[req.payment_hash]
        inv["created_at"] = datetime.now(timezone.utc) - timedelta(seconds=10)
        await gateway.check_payment(req.id)
        assert gateway.verify_payment(req.id, 100, "/api/secret") is True
        assert gateway.consume_payment(req.id) is True
        assert gateway.verify_payment(req.id, 100, "/api/secret") is False  # consumed

    @pytest.mark.asyncio
    async def test_persistence(self, temp_db):
        gw1 = SatGateway(
            backend=MockBackend(),
            config=GatewayConfig(api_key="test"),
            db_path=temp_db
        )
        req = await gw1.create_request(amount_sats=100, description="test", resource_url="/api/secret")
        # Simulate new gateway instance (restart)
        gw2 = SatGateway(
            backend=MockBackend(),
            config=GatewayConfig(api_key="test"),
            db_path=temp_db
        )
        loaded = gw2.get_payment(req.id)
        assert loaded is not None
        assert loaded.amount_sats == 100

    @pytest.mark.asyncio
    async def test_underpayment_rejected(self, gateway):
        """Simulate backend returning less than expected amount."""
        req = await gateway.create_request(amount_sats=100, description="test", resource_url="/api/secret")
        # Manually mark backend as paid but with underpayment
        inv = gateway.backend._invoices[req.payment_hash]
        inv["paid"] = True
        inv["preimage"] = "abc123"
        inv["amount_sats"] = 50  # Underpaid!
        result = await gateway.check_payment(req.id)
        assert result["paid"] is False
        assert "Underpayment" in result.get("error", "")
