"""FastAPI middleware and decorators for SatGateway."""

import os
import base64
import json
from functools import wraps
from typing import Optional, Callable, Any

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse

from .core import SatGateway, PaymentRequest, GatewayConfig, MockBackend


# ---------------------------------------------------------------------------
# FastAPI decorator
# ---------------------------------------------------------------------------

def require_payment(
    amount_sats: int,
    description: Optional[str] = None,
    gateway: Optional[SatGateway] = None,
    on_paid: Optional[Callable] = None
):
    """
    Decorator that gates a FastAPI endpoint behind a Lightning payment.

    Usage:
        @app.get("/api/premium")
        @require_payment(amount_sats=100, description="Access premium API")
        async def premium(request: Request):
            return {"data": "secret"}
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            _gateway = gateway or _default_gateway()
            request: Request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if not request:
                for v in kwargs.values():
                    if isinstance(v, Request):
                        request = v
                        break

            if not request:
                raise HTTPException(status_code=500, detail="Could not find Request object")

            # 1. Check for existing payment proof in headers or cookies
            payment_id = request.headers.get("X-Payment-ID") or request.cookies.get("sg_payment_id")
            payment_preimage = request.headers.get("X-Payment-Preimage") or request.cookies.get("sg_preimage")

            if payment_id:
                status = await _gateway.check_payment(payment_id)
                if status.get("paid"):
                    # Valid payment — proceed
                    return await func(*args, **kwargs)

            # 2. No valid payment — create one and return 402
            resource_url = str(request.url)
            desc = description or f"Access to {request.url.path}"

            req = await _gateway.create_request(
                amount_sats=amount_sats,
                description=desc,
                resource_url=resource_url
            )

            # Return 402 Payment Required with invoice
            response = JSONResponse(
                status_code=402,
                content={
                    "error": "Payment Required",
                    "payment_id": req.id,
                    "amount_sats": req.amount_sats,
                    "description": req.description,
                    "invoice": req.invoice,
                    "expires_at": req.expires_at.isoformat(),
                    "qr_url": f"/payments/qr/{req.id}",
                    "verify_url": f"/payments/verify/{req.id}"
                },
                headers={
                    "PAYMENT-REQUIRED": base64.b64encode(json.dumps({
                        "scheme": "exact",
                        "network": "lightning",
                        "amount": req.amount_sats,
                        "currency": "BTC",
                        "invoice": req.invoice,
                        "expiresAt": req.expires_at.isoformat()
                    }).encode()).decode()
                }
            )
            response.set_cookie(key="sg_payment_id", value=req.id, max_age=3600, httponly=True)
            return response

        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# PaymentGateway class (injection-style)
# ---------------------------------------------------------------------------

class PaymentGateway:
    """
    Injectable gateway for FastAPI apps.

    Usage:
        gateway = PaymentGateway()
        app.include_router(gateway.router, prefix="/payments")
    """

    def __init__(self, sat_gateway: Optional[SatGateway] = None):
        self.gateway = sat_gateway or _default_gateway()
        from fastapi import APIRouter
        self.router = APIRouter()
        self._register_routes()

    def _register_routes(self):
        @self.router.post("/invoice")
        async def create_invoice(request: Request):
            body = await request.json()
            req = await self.gateway.create_request(
                amount_sats=body.get("amount_sats", 100),
                description=body.get("description", "Service access"),
                resource_url=body.get("resource_url", ""),
                metadata=body.get("metadata")
            )
            return {
                "payment_id": req.id,
                "invoice": req.invoice,
                "amount_sats": req.amount_sats,
                "qr_url": f"/payments/qr/{req.id}",
                "verify_url": f"/payments/verify/{req.id}"
            }

        @self.router.get("/verify/{payment_id}")
        async def verify_payment(payment_id: str):
            return await self.gateway.check_payment(payment_id)

        @self.router.get("/qr/{payment_id}")
        async def get_qr(payment_id: str):
            payment = self.gateway.get_payment(payment_id)
            if not payment:
                raise HTTPException(status_code=404, detail="Payment not found")

            import qrcode
            import io
            qr = qrcode.make(payment.invoice)
            buf = io.BytesIO()
            qr.save(buf, format="PNG")
            buf.seek(0)
            from fastapi.responses import StreamingResponse
            return StreamingResponse(buf, media_type="image/png")

        @self.router.get("/paywall/{payment_id}")
        async def paywall_page(payment_id: str):
            payment = self.gateway.get_payment(payment_id)
            if not payment:
                raise HTTPException(status_code=404, detail="Payment not found")

            html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Payment Required</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0d1117; color: #c9d1d9; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 16px; padding: 2rem; text-align: center; max-width: 400px; width: 90%; }}
        h1 {{ margin: 0 0 0.5rem; font-size: 1.5rem; color: #F7931A; }}
        .amount {{ font-size: 2.5rem; font-weight: 700; margin: 1rem 0; }}
        .sats {{ font-size: 1rem; color: #8b949e; }}
        .qr {{ margin: 1.5rem 0; }}
        .qr img {{ max-width: 250px; border-radius: 12px; }}
        .invoice {{ font-size: 0.75rem; color: #484f58; word-break: break-all; margin-top: 1rem; }}
        .copy-btn {{ background: #F7931A; color: #000; border: none; padding: 0.6rem 1.2rem; border-radius: 8px; font-weight: 600; cursor: pointer; margin-top: 1rem; }}
        .copy-btn:hover {{ opacity: 0.9; }}
        .status {{ margin-top: 1rem; padding: 0.5rem; border-radius: 8px; font-size: 0.875rem; }}
        .status.pending {{ background: rgba(247,147,26,0.1); color: #F7931A; }}
        .status.paid {{ background: rgba(35,197,94,0.1); color: #22c55e; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>⚡ Lightning Paywall</h1>
        <div class="amount">{payment.amount_sats:,} <span class="sats">sats</span></div>
        <div class="qr"><img src="/payments/qr/{payment.id}" alt="Payment QR Code"></div>
        <button class="copy-btn" onclick="copyInvoice()">Copy Invoice</button>
        <div class="invoice">{payment.invoice}</div>
        <div class="status pending" id="status">⏳ Waiting for payment...</div>
    </div>
    <script>
        function copyInvoice() {{
            navigator.clipboard.writeText("{payment.invoice}");
            event.target.textContent = "Copied!";
        }}
        async function check() {{
            const r = await fetch('/payments/verify/{payment.id}');
            const d = await r.json();
            const el = document.getElementById('status');
            if (d.paid) {{
                el.textContent = '✅ Payment received! Redirecting...';
                el.className = 'status paid';
                setTimeout(() => window.location.href = '{payment.resource_url or "/"}', 1500);
            }} else if (d.expired) {{
                el.textContent = '❌ Payment expired. Please refresh.';
            }}
        }}
        setInterval(check, 2000);
        check();
    </script>
</body>
</html>"""
            return HTMLResponse(content=html)

        @self.router.get("/api/status")
        async def api_status():
            from .core import MockBackend
            bal = await self.gateway.get_balance()
            return {
                "status": "ok",
                "gateway": "SatGateway",
                "version": "0.1.0",
                "balance_sats": bal,
                "fee_bps": self.gateway.config.fee_basis_points,
                "backend": "mock" if isinstance(self.gateway.backend, MockBackend) else "lnd"
            }



        @self.router.post("/analytics/track")
        async def track_event(request: Request):
            import os, redis
            body = await request.json()
            event = body.get("event", "unknown")
            r = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=6379, decode_responses=True)
            r.incr(f"analytics:{event}")
            r.incr("analytics:total_events")
            return {"ok": True}

        @self.router.get("/analytics/dashboard")
        async def analytics_dashboard():
            import os, redis
            r = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=6379, decode_responses=True)
            keys = r.keys("analytics:*")
            data = {}
            for k in keys:
                val = r.get(k)
                data[k.replace("analytics:", "")] = int(val) if val else 0
            return {"analytics": data, "node": "0301e382e103585adc5b3bd302e73be4e2f9ca44efe00a8f4c1aef075899ea160e"}
        @self.router.get("/status")
        async def gateway_status():
            bal = await self.gateway.get_balance()
            return {
                "balance_sats": bal,
                "fee_bps": self.gateway.config.fee_basis_points,
                "version": "0.1.0"
            }


# ---------------------------------------------------------------------------
# Default singleton
# ---------------------------------------------------------------------------

_default_gw: Optional[SatGateway] = None

def _default_gateway() -> SatGateway:
    global _default_gw
    if _default_gw is None:
        _default_gw = SatGateway(
            backend=MockBackend(),
            config=GatewayConfig(api_key=os.getenv("SATGATEWAY_KEY", "dev"))
        )
    return _default_gw


def init_gateway(backend=None, config=None):
    """Initialize the default gateway (call once at startup)."""
    global _default_gw
    _default_gw = SatGateway(
        backend=backend or MockBackend(),
        config=config or GatewayConfig(api_key=os.getenv("SATGATEWAY_KEY", "dev"))
    )
    return _default_gw
