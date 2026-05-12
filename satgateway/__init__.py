"""
SatGateway — Bitcoin Lightning payments for websites & APIs.

The simplest way to add Lightning micropayments to any app.

Website (2 lines):
    <script src="https://satgateway.dev/v1/paywall.js" data-amount="100" data-api-key="pk_..."></script>

API (3 lines):
    from satgateway import require_payment
    
    @app.get("/premium")
    @require_payment(amount_sats=100)
    def premium_content(request: Request):
        return {"secret": "data"}
"""

from .middleware import require_payment, PaymentGateway
from .core import SatGateway

__version__ = "0.1.0"
__all__ = ["require_payment", "PaymentGateway", "SatGateway"]
