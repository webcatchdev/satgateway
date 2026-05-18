"""Tests for FastAPI middleware and decorators."""

from datetime import datetime, timezone, timedelta


class TestRequirePaymentDecorator:
    def test_unpaid_request_returns_402(self, client):
        """Hitting a protected endpoint without payment should return 402 with invoice."""
        response = client.get("/payments/api/secret")
        assert response.status_code == 402
        data = response.json()
        assert "invoice" in data
        assert "payment_id" in data
        assert data["amount_sats"] == 100
        assert "qr_url" in data
        assert "verify_url" in data
        # Should set cookie
        assert "sg_payment_id" in response.cookies

    def test_cheap_route_different_amount(self, client):
        """A 1-sat route should not be unlocked by a 100-sat invoice."""
        # First, get a 100-sat invoice by hitting the secret endpoint
        r1 = client.get("/payments/api/secret")
        assert r1.status_code == 402
        payment_id = r1.json()["payment_id"]

        # Try to use it on the cheap endpoint
        r2 = client.get("/payments/api/cheap", headers={"X-Payment-ID": payment_id})
        # Should return 402 because amount mismatch (100 != 1)
        assert r2.status_code == 402

    def test_amount_mismatch_blocked(self, client):
        """A 1-sat invoice should not unlock a 100-sat route."""
        r1 = client.get("/payments/api/cheap")
        assert r1.status_code == 402
        payment_id = r1.json()["payment_id"]

        r2 = client.get("/payments/api/secret", headers={"X-Payment-ID": payment_id})
        assert r2.status_code == 402

    def test_paid_request_succeeds(self, client, app):
        """After mock auto-pay, valid payment should unlock route."""
        from satgateway.middleware import _default_gateway

        r1 = client.get("/payments/api/secret")
        assert r1.status_code == 402
        payment_id = r1.json()["payment_id"]

        # Backdate the invoice to trigger auto-pay
        gw = _default_gateway()
        inv = gw.backend._invoices[gw.get_payment(payment_id).payment_hash]
        inv["created_at"] = datetime.now(timezone.utc) - timedelta(seconds=10)

        # Now access with payment ID
        r2 = client.get("/payments/api/secret", headers={"X-Payment-ID": payment_id})
        assert r2.status_code == 200
        assert r2.json()["message"] == "secret data"

    def test_consumed_payment_blocked(self, client, app):
        """A consumed (used) payment should not work twice."""
        from satgateway.middleware import _default_gateway

        r1 = client.get("/payments/api/secret")
        assert r1.status_code == 402
        payment_id = r1.json()["payment_id"]

        gw = _default_gateway()
        inv = gw.backend._invoices[gw.get_payment(payment_id).payment_hash]
        inv["created_at"] = datetime.now(timezone.utc) - timedelta(seconds=10)

        # First use — should succeed
        r2 = client.get("/payments/api/secret", headers={"X-Payment-ID": payment_id})
        assert r2.status_code == 200

        # Second use — should be consumed, return 402
        r3 = client.get("/payments/api/secret", headers={"X-Payment-ID": payment_id})
        assert r3.status_code == 402

    def test_handler_crash_does_not_consume(self, client, app):
        """If the handler crashes, the payment should NOT be consumed."""
        from satgateway.middleware import _default_gateway

        r1 = client.get("/payments/api/crash")
        assert r1.status_code == 402
        payment_id = r1.json()["payment_id"]

        gw = _default_gateway()
        inv = gw.backend._invoices[gw.get_payment(payment_id).payment_hash]
        inv["created_at"] = datetime.now(timezone.utc) - timedelta(seconds=10)

        # Hit the crashing endpoint — should return 500, not consume
        r2 = client.get("/payments/api/crash", headers={"X-Payment-ID": payment_id})
        assert r2.status_code == 500

        # Payment should still be valid
        assert gw.verify_payment(payment_id, 50, "http://testserver/payments/api/crash") is True

    def test_cookie_payment_works(self, client, app):
        """Payment ID in cookie should work the same as header.

        Note: secure=True cookies won't persist over http:// in TestClient,
        so we verify by explicitly passing the cookie value.
        """
        from satgateway.middleware import _default_gateway

        r1 = client.get("/payments/api/secret")
        assert r1.status_code == 402
        payment_id = r1.cookies["sg_payment_id"]

        gw = _default_gateway()
        inv = gw.backend._invoices[gw.get_payment(payment_id).payment_hash]
        inv["created_at"] = datetime.now(timezone.utc) - timedelta(seconds=10)

        # Pass cookie explicitly (secure cookies don't auto-persist on http)
        r2 = client.get("/payments/api/secret", cookies={"sg_payment_id": payment_id})
        assert r2.status_code == 200
        assert r2.json()["message"] == "secret data"


class TestPaymentGatewayRoutes:
    def test_create_invoice(self, client):
        """POST /payments/invoice should create an invoice."""
        response = client.post(
            "/payments/invoice",
            json={"amount_sats": 21, "description": "test", "resource_url": "/api/secret"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "payment_id" in data
        assert "invoice" in data
        assert data["amount_sats"] == 21

    def test_create_invoice_missing_amount(self, client):
        response = client.post("/payments/invoice", json={"description": "test"})
        assert response.status_code == 400

    def test_create_invoice_zero_amount(self, client):
        response = client.post("/payments/invoice", json={"amount_sats": 0})
        assert response.status_code == 400

    def test_create_invoice_invalid_amount(self, client):
        response = client.post("/payments/invoice", json={"amount_sats": "abc"})
        assert response.status_code == 400

    def test_verify_payment(self, client):
        r1 = client.post(
            "/payments/invoice",
            json={"amount_sats": 21, "description": "test"}
        )
        payment_id = r1.json()["payment_id"]

        r2 = client.get(f"/payments/verify/{payment_id}")
        assert r2.status_code == 200
        assert r2.json()["found"] is True
        assert r2.json()["paid"] is False

    def test_qr_not_found(self, client):
        response = client.get("/payments/qr/nonexistent")
        assert response.status_code == 404

    def test_paywall_page(self, client):
        r1 = client.post(
            "/payments/invoice",
            json={"amount_sats": 21, "description": "test"}
        )
        payment_id = r1.json()["payment_id"]

        r2 = client.get(f"/payments/paywall/{payment_id}")
        assert r2.status_code == 200
        assert "Lightning Paywall" in r2.text

    def test_paywall_not_found(self, client):
        response = client.get("/payments/paywall/nonexistent")
        assert response.status_code == 404

    def test_api_status(self, client):
        response = client.get("/payments/api/status")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "balance_sats" in data

    def test_analytics_track(self, client):
        response = client.post("/payments/analytics/track", json={"event": "test_event"})
        # Should succeed even without Redis (dev mode silent fail)
        assert response.status_code == 200

    def test_analytics_dashboard_with_key(self, client):
        """Dashboard should be accessible with correct API key."""
        response = client.get("/payments/analytics/dashboard", headers={"X-API-Key": "test-key"})
        assert response.status_code == 200
        assert "analytics" in response.json()

    def test_analytics_dashboard_without_key(self, client):
        """Dashboard should reject without API key when not in dev mode."""
        response = client.get("/payments/analytics/dashboard")
        assert response.status_code == 401

    def test_gateway_status(self, client):
        response = client.get("/payments/status")
        assert response.status_code == 200
        assert "balance_sats" in response.json()
