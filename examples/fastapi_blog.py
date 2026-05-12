"""
Example: Lightning-paywalled blog API.

Run:
    python examples/fastapi_blog.py

Then visit http://localhost:8000 to see the paywall demo.
"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from satgateway.middleware import require_payment, PaymentGateway, init_gateway
from satgateway.core import SatGateway, MockBackend, GatewayConfig

# Initialize gateway
init_gateway(
    backend=MockBackend(),
    config=GatewayConfig(api_key="demo", fee_basis_points=50)
)

app = FastAPI(title="Lightning Blog")

# Mount payment routes
gateway = PaymentGateway()
app.include_router(gateway.router, prefix="/payments")


@app.get("/", response_class=HTMLResponse)
def index():
    return """<!DOCTYPE html>
<html>
<head><title>Lightning Blog</title></head>
<body style="font-family:sans-serif; max-width:600px; margin:2rem auto; padding:0 1rem;">
    <h1>⚡ Lightning Blog</h1>
    <p>All articles are free — except the good ones.</p>
    <ul>
        <li><a href="/article/free">Free Article</a></li>
        <li><a href="/article/premium">Premium Article (100 sats)</a></li>
        <li><a href="/article/mega">Mega Article (500 sats)</a></li>
    </ul>
</body>
</html>"""


@app.get("/article/free")
def free_article():
    return {"title": "Why Lightning Rocks", "content": "It's fast, cheap, and permissionless."}


@app.get("/article/premium")
@require_payment(amount_sats=100, description="Read premium article")
async def premium_article(request: Request):
    return {
        "title": "The Future of Agent Payments",
        "content": "In 2026, every API will accept Lightning. Agents will pay each other in milliseconds. This article is worth every sat.",
        "author": "Satoshi's Ghost",
        "word_count": 420
    }


@app.get("/article/mega")
@require_payment(amount_sats=500, description="Read mega article")
async def mega_article(request: Request):
    return {
        "title": "How We Built SatGateway in a Weekend",
        "content": "It started with a simple idea: what if HTTP 402 wasn't a joke? What if every website could charge per view? ...",
        "author": "webcatchdev",
        "word_count": 1337,
        "bonus": "Secret API key: SG-MEGA-SECRET-12345"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
