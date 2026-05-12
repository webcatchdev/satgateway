"""
SatGateway Server — Standalone Lightning payment gateway.

Run:
    uvicorn main:app --host 0.0.0.0 --port 9026 --reload

Environment:
    SATGATEWAY_KEY        → API key for hosted mode
    SATGATEWAY_FEE_BPS    → Fee basis points (default: 50 = 0.5%)
    LND_HOST              → LND REST host (optional)
    LND_MACAROON          → LND macaroon hex (optional)
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from satgateway.middleware import PaymentGateway, init_gateway, require_payment, _default_gateway
from satgateway.core import GatewayConfig, MockBackend, LndBackend


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize gateway on startup
    fee_bps = int(os.getenv("SATGATEWAY_FEE_BPS", "50"))
    api_key = os.getenv("SATGATEWAY_KEY", "dev")

    if os.getenv("LND_HOST"):
        backend = LndBackend(
            host=os.getenv("LND_HOST"),
            macaroon_hex=os.getenv("LND_MACAROON") or None,
            macaroon_path=os.getenv("LND_MACAROON_PATH"),
            cert_path=os.getenv("LND_TLS_CERT_PATH")
        )
    else:
        backend = MockBackend()

    init_gateway(
        backend=backend,
        config=GatewayConfig(api_key=api_key, fee_basis_points=fee_bps)
    )
    gateway = PaymentGateway(sat_gateway=_default_gateway())
    app.include_router(gateway.router, prefix="/payments")
    yield


app = FastAPI(
    title="SatGateway",
    description="Bitcoin Lightning payments for websites and APIs",
    version="0.1.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

# ---------------------------------------------------------------------------
# Demo pages
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def home():
    return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SatGateway</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; }
        .hero { text-align: center; padding: 4rem 1rem; max-width: 800px; margin: 0 auto; }
        h1 { font-size: 3rem; margin: 0; color: #F7931A; letter-spacing: -0.02em; }
        .tagline { font-size: 1.25rem; color: #8b949e; margin: 1rem 0 2rem; }
        .cta { display: inline-block; background: #F7931A; color: #000; padding: 0.8rem 1.5rem; border-radius: 10px; text-decoration: none; font-weight: 600; margin: 0.5rem; }
        .cta:hover { opacity: 0.9; }
        .cta.secondary { background: transparent; border: 1px solid #30363d; color: #c9d1d9; }
        .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; max-width: 900px; margin: 2rem auto; padding: 0 1rem; }
        .feature { background: #161b22; border: 1px solid #30363d; padding: 1.5rem; border-radius: 12px; }
        .feature h3 { margin: 0 0 0.5rem; color: #F7931A; }
        .code { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; margin: 1rem 0; overflow-x: auto; font-family: monospace; font-size: 0.875rem; color: #e6edf3; }
        .code .comment { color: #8b949e; }
        .code .keyword { color: #ff7b72; }
        .code .string { color: #a5d6ff; }
        footer { text-align: center; padding: 2rem; color: #484f58; font-size: 0.875rem; }
    </style>
</head>
<body>
    <div class="hero">
        <h1>⚡ SatGateway</h1>
        <p class="tagline">Bitcoin Lightning payments for websites & APIs.<br>Two lines of code. Sub-penny fees. No accounts.</p>
        <a class="cta" href="/payments/">Try Demo</a>
        <a class="cta secondary" href="https://github.com/webcatchdev/satgateway">GitHub</a>
    </div>

    <div class="features">
        <div class="feature">
            <h3>🌐 Website Paywall</h3>
            <p>Add a Lightning paywall to any page:</p>
            <div class="code">&lt;<span class="keyword">script</span> <span class="string">src</span>=<span class="string">"/static/paywall.js"</span>
  <span class="string">data-amount</span>=<span class="string">"100"</span>&gt;&lt;/<span class="keyword">script</span>&gt;</div>
        </div>
        <div class="feature">
            <h3>🔌 API Middleware</h3>
            <p>Gate FastAPI endpoints:</p>
            <div class="code"><span class="keyword">@app.get</span>(<span class="string">"/api/premium"</span>)
<span class="keyword">@require_payment</span>(<span class="string">amount_sats=100</span>)
<span class="keyword">async def</span> premium(request: Request):
    <span class="keyword">return</span> {<span class="string">"secret"</span>: <span class="string">"data"</span>}</div>
        </div>
        <div class="feature">
            <h3>⚡ Lightning Native</h3>
            <p>Works with any Lightning node. Self-hosted or managed. No KYC, no accounts, instant settlement.</p>
        </div>
    </div>

    <div class="hero" id="demo">
        <h2>Live Demo</h2>
        <p class="tagline">Pay 100 sats to reveal a secret message</p>
        <div id="paywall-container"></div>
        <script src="/static/paywall.js" data-amount="100" data-resource="/api/secret" data-container="paywall-container"></script>
    </div>

    <footer>
        Built with ⚡ by <a href="https://github.com/webcatchdev" style="color:#F7931A;">@webcatchdev</a> · MIT License
    </footer>
</body>
</html>"""


@app.get("/payments/api/secret")
@require_payment(amount_sats=100, description="Access secret message")
async def secret_message(request: Request):
    return {
        "message": "🎉 Welcome to the lightning-enabled future!",
        "tip": "You just paid 100 sats via Lightning. This is the new internet.",
        "next_steps": [
            "Add @require_payment to your own endpoints",
            "Set your own price in sats",
            "Connect your LND node",
            "Start earning Bitcoin"
        ]
    }


@app.get("/payments/api/status")
async def status():
    from satgateway.middleware import _default_gateway
    gw = _default_gateway()
    bal = await gw.get_balance()
    return {
        "status": "ok",
        "gateway": "SatGateway",
        "version": "0.1.0",
        "balance_sats": bal,
        "fee_bps": gw.config.fee_basis_points,
        "backend": "mock" if isinstance(gw.backend, MockBackend) else "lnd"
    }


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9026)
