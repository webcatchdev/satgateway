"""FastAPI middleware and decorators for SatGateway."""

import os
import re
import html
import hmac
import json
import base64
import secrets
from functools import wraps
from typing import Optional, Callable

from fastapi import Request, HTTPException, Header, Depends
from fastapi.responses import JSONResponse, HTMLResponse

from .core import SatGateway, GatewayConfig, MockBackend
from .ratelimit import RateLimiter

# ---------------------------------------------------------------------------
# Rate limiter singleton
# ---------------------------------------------------------------------------

_rate_limiter: Optional[RateLimiter] = None

def _get_rate_limiter() -> RateLimiter:
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _resolve_api_key() -> str:
    """Return the configured API key, or raise if not explicitly set."""
    key = os.getenv("SATGATEWAY_KEY")
    if not key:
        raise RuntimeError(
            "SATGATEWAY_KEY environment variable is required and must be non-empty. "
            "Set it to a secure random string before starting the gateway."
        )
    return key


async def _require_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    """Dependency that validates the SatGateway API key."""
    expected = _resolve_api_key()
    provided = x_api_key
    if not provided and authorization:
        if authorization.lower().startswith("bearer "):
            provided = authorization[7:]
        else:
            provided = authorization
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return provided


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

_MAX_DESCRIPTION = 500
_MAX_RESOURCE_URL = 2000
_MAX_METADATA_BYTES = 10_240  # 10 KB


def _validate_uuid(payment_id: str) -> str:
    if not _UUID_RE.match(payment_id):
        raise HTTPException(status_code=400, detail="Invalid payment ID format")
    return payment_id


def _validate_resource_url(url: str) -> str:
    """Allow only http, https, and relative URLs. Block javascript:, data:, etc."""
    if not url:
        return url
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid resource_url scheme: '{parsed.scheme}'. Only http, https, or relative URLs are allowed."
        )
    return url


def _clamp_invoice_input(body: dict) -> dict:
    """Clamp and sanitize invoice creation input."""
    desc = str(body.get("description", "Service access"))[:_MAX_DESCRIPTION]
    url = str(body.get("resource_url", ""))[:_MAX_RESOURCE_URL]
    url = _validate_resource_url(url)
    metadata = body.get("metadata")
    if metadata is not None:
        meta_str = json.dumps(metadata)
        if len(meta_str.encode("utf-8")) > _MAX_METADATA_BYTES:
            raise HTTPException(status_code=413, detail="Metadata payload too large (max 10KB)")
    amount = body.get("amount_sats", 100)
    try:
        amount = int(amount)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="amount_sats must be an integer")
    return {
        "amount_sats": amount,
        "description": desc,
        "resource_url": url,
        "metadata": metadata,
    }


# ---------------------------------------------------------------------------
# CSRF helpers
# ---------------------------------------------------------------------------

def _generate_csrf() -> str:
    return secrets.token_urlsafe(32)


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

    Uses atomic verify-and-consume to prevent double-spend race conditions.

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

            if payment_id:
                # Atomic verify-and-consume prevents double-spend across workers
                consumed = _gateway.verify_and_consume(payment_id)
                if consumed:
                    # Valid payment — proceed
                    return await func(*args, **kwargs)
                # Fall through to create new invoice if not paid / already consumed

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
                    "Cache-Control": "no-store, no-cache, must-revalidate, private",
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
            # secure=True requires HTTPS; allow HTTP override for local dev
            cookie_secure = os.getenv("SATGATEWAY_COOKIE_SECURE", "1") != "0"
            response.set_cookie(key="sg_payment_id", value=req.id, max_age=3600, httponly=True, samesite="Lax", secure=cookie_secure)
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
        # ------------------------------------------------------------------
        # POST /invoice  — rate limited, input validated
        # ------------------------------------------------------------------
        @self.router.post("/invoice")
        async def create_invoice(request: Request):
            rl = _get_rate_limiter()
            allowed, headers = rl.is_allowed_request(request)
            if not allowed:
                raise HTTPException(status_code=429, detail="Rate limit exceeded", headers=headers)

            body = await request.json()
            sanitized = _clamp_invoice_input(body)

            req = await self.gateway.create_request(
                amount_sats=sanitized["amount_sats"],
                description=sanitized["description"],
                resource_url=sanitized["resource_url"],
                metadata=sanitized["metadata"]
            )

            resp = JSONResponse({
                "payment_id": req.id,
                "invoice": req.invoice,
                "amount_sats": req.amount_sats,
                "qr_url": f"/payments/qr/{req.id}",
                "verify_url": f"/payments/verify/{req.id}"
            })
            resp.headers.update(headers)
            return resp

        # ------------------------------------------------------------------
        # GET /verify/{payment_id}
        # ------------------------------------------------------------------
        @self.router.get("/verify/{payment_id}")
        async def verify_payment(payment_id: str):
            _validate_uuid(payment_id)
            result = await self.gateway.check_payment(payment_id)
            return JSONResponse(
                content=result,
                headers={"Cache-Control": "no-store, no-cache, must-revalidate, private"}
            )

        # ------------------------------------------------------------------
        # GET /qr/{payment_id}
        # ------------------------------------------------------------------
        @self.router.get("/qr/{payment_id}")
        async def get_qr(payment_id: str):
            _validate_uuid(payment_id)
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
            return StreamingResponse(buf, media_type="image/png",
                                     headers={"Cache-Control": "no-store, no-cache, must-revalidate, private"})

        # ------------------------------------------------------------------
        # GET /paywall/{payment_id}  — CSRF token injected
        # ------------------------------------------------------------------
        @self.router.get("/paywall/{payment_id}")
        async def paywall_page(payment_id: str):
            _validate_uuid(payment_id)
            payment = self.gateway.get_payment(payment_id)
            if not payment:
                raise HTTPException(status_code=404, detail="Payment not found")

            csrf = _generate_csrf()
            # Store CSRF token in DB so we can validate later
            # Use update_csrf to avoid overwriting consumed flag (anti double-spend)
            self.gateway._store.update_csrf(payment.id, csrf)

            # Safely embed values — html.escape for HTML context,
            # json.dumps for JS string context
            safe_id = html.escape(payment.id)
            safe_invoice = html.escape(payment.invoice)
            safe_amount = payment.amount_sats
            js_invoice = json.dumps(payment.invoice)
            js_url = json.dumps(payment.resource_url or "/")
            js_csrf = json.dumps(csrf)

            html_page = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, private">
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
        <div class="amount">{safe_amount:,} <span class="sats">sats</span></div>
        <div class="qr"><img src="/payments/qr/{safe_id}" alt="Payment QR Code"></div>
        <button class="copy-btn" id="copyBtn">Copy Invoice</button>
        <div class="invoice">{safe_invoice}</div>
        <div class="status pending" id="status">⏳ Waiting for payment...</div>
    </div>
    <script>
        (function() {{
            const invoice = {js_invoice};
            const redirectUrl = {js_url};
            const csrfToken = {js_csrf};
            document.getElementById('copyBtn').addEventListener('click', function() {{
                navigator.clipboard.writeText(invoice);
                this.textContent = 'Copied!';
            }});
            async function check() {{
                const r = await fetch('/payments/verify/' + encodeURIComponent({json.dumps(payment.id)}), {{
                    headers: {{'X-CSRF-Token': csrfToken}}
                }});
                const d = await r.json();
                const el = document.getElementById('status');
                if (d.paid) {{
                    el.textContent = '✅ Payment received! Redirecting...';
                    el.className = 'status paid';
                    setTimeout(() => window.location.href = redirectUrl, 1500);
                }} else if (d.expired) {{
                    el.textContent = '❌ Payment expired. Please refresh.';
                }}
            }}
            setInterval(check, 2000);
            check();
        }})();
    </script>
</body>
</html>"""
            return HTMLResponse(content=html_page)

        # ------------------------------------------------------------------
        # GET /api/status      — public, minimal info (no backend type or balance)
        # GET /admin/status    — authenticated, full info
        # ------------------------------------------------------------------
        @self.router.get("/api/status")
        async def api_status_public():
            return {
                "status": "ok",
                "gateway": "SatGateway",
                "version": "0.1.0",
            }

        @self.router.get("/admin/status")
        async def api_status_admin(api_key: str = Depends(_require_api_key)):
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

        # ------------------------------------------------------------------
        # Analytics — protected by API key
        # ------------------------------------------------------------------
        @self.router.post("/analytics/track")
        async def track_event(request: Request, api_key: str = Depends(_require_api_key)):
            import redis
            body = await request.json()
            event = body.get("event", "unknown")
            try:
                r = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=6379, decode_responses=True)
                r.incr(f"analytics:{event}")
                r.incr("analytics:total_events")
            except Exception:
                # Degrade gracefully if Redis is unavailable
                pass
            return {"ok": True}

        @self.router.get("/analytics/dashboard")
        async def analytics_dashboard(api_key: str = Depends(_require_api_key)):
            import redis
            try:
                r = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=6379, decode_responses=True)
                keys = r.keys("analytics:*")
                data = {}
                for k in keys:
                    val = r.get(k)
                    data[k.replace("analytics:", "")] = int(val) if val else 0
            except Exception:
                data = {}
            return {"analytics": data}

        # ------------------------------------------------------------------
        # GET /status — public gateway health
        # ------------------------------------------------------------------
        @self.router.get("/status")
        async def gateway_status():
            return {
                "status": "ok",
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
            config=GatewayConfig(api_key=_resolve_api_key()),
        )
    return _default_gw


def init_gateway(backend=None, config=None, store=None):
    """Initialize the default gateway (call once at startup)."""
    global _default_gw
    _default_gw = SatGateway(
        backend=backend or MockBackend(),
        config=config or GatewayConfig(api_key=_resolve_api_key()),
        store=store,
    )
    return _default_gw
