"""FastAPI middleware and decorators for SatGateway."""

import os
import base64
import html
import json
import hmac
import time
from functools import wraps
from typing import Optional, Callable, Any
from urllib.parse import urlparse

from fastapi import Request, HTTPException, Depends, Header
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, constr, conint, field_validator

from .core import SatGateway, PaymentRequest, GatewayConfig, MockBackend


# ---------------------------------------------------------------------------
# Simple in-memory rate limiter (NEW-06)
# ---------------------------------------------------------------------------

class SimpleRateLimiter:
    """Token-bucket style rate limiter per client IP."""

    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets: dict[str, list[float]] = {}

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        window_start = now - self.window_seconds
        # Keep only requests within the current window
        self._buckets[key] = [t for t in self._buckets.get(key, []) if t > window_start]
        if len(self._buckets[key]) >= self.max_requests:
            return False
        self._buckets[key].append(now)
        return True

    def cleanup(self) -> int:
        """Remove stale entries. Returns count removed."""
        now = time.time()
        window_start = now - self.window_seconds
        stale = [k for k, times in self._buckets.items() if not any(t > window_start for t in times)]
        for k in stale:
            del self._buckets[k]
        return len(stale)


_rate_limiter = SimpleRateLimiter(max_requests=30, window_seconds=60)
_qr_rate_limiter = SimpleRateLimiter(max_requests=10, window_seconds=60)


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------

def _validate_metadata_size(value: Optional[dict]) -> Optional[dict]:
    """Validate metadata size and nesting depth (NEW-14)."""
    if value is None:
        return None
    # Limit total JSON size to 16KB
    json_str = json.dumps(value)
    if len(json_str) > 16384:
        raise ValueError("Metadata exceeds 16KB limit")
    # Limit nesting depth to 3
    def _depth(obj, current=0):
        if current > 3:
            raise ValueError("Metadata nesting exceeds 3 levels")
        if isinstance(obj, dict):
            for v in obj.values():
                _depth(v, current + 1)
        elif isinstance(obj, list):
            for item in obj:
                _depth(item, current + 1)
    _depth(value)
    # Limit number of top-level keys
    if isinstance(value, dict) and len(value) > 50:
        raise ValueError("Metadata exceeds 50 top-level keys")
    return value


class InvoiceRequest(BaseModel):
    amount_sats: conint(ge=1, le=1_000_000)
    description: constr(max_length=200) = "Service access"
    resource_url: constr(max_length=500) = ""
    metadata: Optional[dict] = None

    @field_validator("metadata", mode="before")
    @classmethod
    def check_metadata(cls, v):
        return _validate_metadata_size(v)


# ---------------------------------------------------------------------------
# API key dependency
# ---------------------------------------------------------------------------

async def verify_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    gateway: SatGateway = Depends(lambda: _default_gateway())
):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    # NEW-11: Use constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(x_api_key, gateway.config.api_key):
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


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
        _gateway = gateway or _default_gateway()

        @wraps(func)
        async def wrapper(*args, **kwargs):
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

            # Check for existing payment proof in headers or cookies
            payment_id = request.headers.get("X-Payment-ID") or request.cookies.get("sg_payment_id")

            if payment_id:
                status = await _gateway.check_payment(payment_id)
                if status.get("paid"):
                    payment = _gateway.get_payment(payment_id)
                    if payment:
                        # Validate resource binding (F-01) — normalize paths (NEW-05)
                        stored_path = urlparse(payment.resource_url).path or payment.resource_url
                        request_path = urlparse(str(request.url)).path or str(request.url)
                        if stored_path != request_path:
                            raise HTTPException(status_code=403, detail="Payment not valid for this resource")
                        # Validate amount (F-01)
                        if payment.amount_sats < amount_sats:
                            raise HTTPException(status_code=403, detail="Payment amount insufficient")
                    return await func(*args, **kwargs)

            # No valid payment — create one and return 402
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
                    "qr_url": f"/satgateway/qr/{req.id}",
                    "verify_url": f"/satgateway/verify/{req.id}"
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
            # Secure cookie flags (F-12)
            response.set_cookie(
                key="sg_payment_id",
                value=req.id,
                max_age=3600,
                httponly=True,
                secure=True,
                samesite="Lax"
            )
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
        async def create_invoice(
            invoice_req: InvoiceRequest,
            api_key: str = Depends(verify_api_key)
        ):
            # Validate resource_url is relative to prevent open redirect (F-08)
            if invoice_req.resource_url and not invoice_req.resource_url.startswith("/"):
                raise HTTPException(status_code=422, detail="resource_url must be a relative path starting with /")

            req = await self.gateway.create_request(
                amount_sats=invoice_req.amount_sats,
                description=invoice_req.description,
                resource_url=invoice_req.resource_url,
                metadata=invoice_req.metadata
            )
            return {
                "payment_id": req.id,
                "invoice": req.invoice,
                "amount_sats": req.amount_sats,
                "qr_url": f"/payments/qr/{req.id}",
                "verify_url": f"/payments/verify/{req.id}"
            }

        @self.router.get("/verify/{payment_id}")
        async def verify_payment(payment_id: str, request: Request):
            # NEW-06: Rate limit public verify endpoint
            client_ip = request.client.host if request.client else "unknown"
            if not _rate_limiter.is_allowed(f"verify:{client_ip}"):
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
            return await self.gateway.check_payment(payment_id)

        @self.router.get("/qr/{payment_id}")
        async def get_qr(payment_id: str, request: Request):
            # NEW-06: Stricter rate limit for QR generation (CPU-intensive)
            client_ip = request.client.host if request.client else "unknown"
            if not _qr_rate_limiter.is_allowed(f"qr:{client_ip}"):
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
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
        async def paywall_page(payment_id: str, request: Request):
            # NEW-06: Rate limit public paywall endpoint
            client_ip = request.client.host if request.client else "unknown"
            if not _rate_limiter.is_allowed(f"paywall:{client_ip}"):
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
            payment = self.gateway.get_payment(payment_id)
            if not payment:
                raise HTTPException(status_code=404, detail="Payment not found")

            # Escape values for safe HTML/JS insertion (F-02)
            safe_amount = html.escape(str(payment.amount_sats))
            safe_id = html.escape(payment.id)
            safe_invoice = html.escape(payment.invoice)
            safe_invoice_js = json.dumps(payment.invoice)
            safe_resource_js = json.dumps(payment.resource_url or "/")

            html_content = f"""<!DOCTYPE html>
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
        <div class="amount">{safe_amount} <span class="sats">sats</span></div>
        <div class="qr"><img src="/payments/qr/{safe_id}" alt="Payment QR Code"></div>
        <button class="copy-btn" onclick="copyInvoice()">Copy Invoice</button>
        <div class="invoice">{safe_invoice}</div>
        <div class="status pending" id="status">⏳ Waiting for payment...</div>
    </div>
    <script>
        function copyInvoice() {{
            navigator.clipboard.writeText({safe_invoice_js});
            event.target.textContent = "Copied!";
        }}
        async function check() {{
            const r = await fetch('/payments/verify/{safe_id}');
            const d = await r.json();
            const el = document.getElementById('status');
            if (d.paid) {{
                el.textContent = '✅ Payment received! Redirecting...';
                el.className = 'status paid';
                setTimeout(() => window.location.href = {safe_resource_js}, 1500);
            }} else if (d.expired) {{
                el.textContent = '❌ Payment expired. Please refresh.';
            }}
        }}
        setInterval(check, 2000);
        check();
    </script>
</body>
</html>"""
            return HTMLResponse(content=html_content)

        @self.router.get("/status")
        async def gateway_status(api_key: str = Depends(verify_api_key)):
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
        api_key = os.getenv("SATGATEWAY_KEY")
        if not api_key:
            raise RuntimeError("SATGATEWAY_KEY environment variable must be set")
        _default_gw = SatGateway(
            backend=MockBackend(),
            config=GatewayConfig(api_key=api_key)
        )
    return _default_gw


def init_gateway(backend=None, config=None):
    """Initialize the default gateway (call once at startup)."""
    global _default_gw
    if config is None:
        api_key = os.getenv("SATGATEWAY_KEY")
        if not api_key:
            raise RuntimeError("SATGATEWAY_KEY environment variable must be set")
        config = GatewayConfig(api_key=api_key)
    _default_gw = SatGateway(
        backend=backend or MockBackend(),
        config=config
    )
    return _default_gw
