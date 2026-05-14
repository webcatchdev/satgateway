# ⚡ SatGateway

> Bitcoin Lightning payments for websites and APIs. Two lines of code. Sub-penny fees. No accounts.

[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Why SatGateway?

Stripe charges 2.9% + $0.30 per transaction. That's fine for $50 purchases, but impossible for micropayments. What if you want to charge **1¢ per API call**? Or **100 sats to read an article**?

SatGateway makes it trivial:

- **Website paywall:** `<script src="paywall.js" data-amount="100"></script>`
- **API gate:** `@require_payment(amount_sats=100)`
- **Self-hosted:** Connect your own Lightning node (LND, CLN, or mock for dev)
- **Zero accounts:** Users pay with any Lightning wallet. No signup.
- **Instant settlement:** Sats hit your node in milliseconds.

---

## Quick Start

### 1. Install

```bash
pip install satgateway
```

### 2. Gate a FastAPI endpoint

```python
from fastapi import FastAPI
from satgateway import require_payment

app = FastAPI()

@app.get("/api/premium")
@require_payment(amount_sats=100, description="Access premium API")
def premium_data():
    return {"secret": "value"}
```

### 3. Add a website paywall

```html
<script src="https://your-server.com/static/paywall.js"
        data-amount="100"
        data-resource="/api/premium">
</script>
```

---

## Features

| Feature | Status |
|---------|--------|
| Lightning invoice generation | ✅ |
| QR code paywalls | ✅ |
| FastAPI middleware decorator | ✅ |
| JavaScript drop-in paywall | ✅ |
| LND node support | ✅ |
| Mock backend for dev | ✅ |
| HTTP 402 standard compliance | ✅ |
| x402 protocol compatible | ✅ |
| Self-hosted | ✅ |
| Fee collection (configurable) | ✅ |

---

## ⚠️ Security Warning

> **Before deploying to production, change all placeholder passwords.**
> `docker-compose.fullnode.yml` and `lnd-fullnode.conf` contain the placeholder password `CHANGE_ME_STRONG_PASSWORD` for Bitcoin RPC. You **must** replace this with a strong, unique password before starting your node. Failure to do so will leave your Bitcoin RPC exposed to anyone who reads the config file.

## Configuration

### Environment Variables

```bash
# Required
SATGATEWAY_KEY=your_api_key

# Optional
SATGATEWAY_FEE_BPS=50          # 0.5% fee
LND_HOST=https://localhost:8080 # LND REST endpoint
LND_MACAROON=your_macaroon_hex # LND macaroon
LND_CERT_PATH=/path/to/tls.cert # LND TLS cert
```

### Self-hosted with LND

```python
from satgateway.core import SatGateway, GatewayConfig, LndBackend
from satgateway.middleware import init_gateway

backend = LndBackend(
    host="https://localhost:8080",
    macaroon_hex="0201036c...",
    cert_path="~/.lnd/tls.cert"
)

init_gateway(
    backend=backend,
    config=GatewayConfig(api_key="prod", fee_basis_points=50)
)
```

---

## Architecture

```
┌─────────────┐     HTTP 402 + Invoice     ┌─────────────┐
│   User      │ ◄─────────────────────────► │  SatGateway │
│  (Browser   │     Lightning Payment       │   Server    │
│   or Agent) │ ◄─────────────────────────► │             │
└─────────────┘                             └──────┬──────┘
                                                   │
                                          ┌────────┴────────┐
                                          │                 │
                                          ▼                 ▼
                                    ┌─────────┐       ┌─────────┐
                                    │  LND    │       │   CLN   │
                                    │  Node   │       │  Node   │
                                    └─────────┘       └─────────┘
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/payments/invoice` | POST | Create a new payment request |
| `/payments/verify/{id}` | GET | Check payment status |
| `/payments/qr/{id}` | GET | Get QR code for invoice |
| `/payments/paywall/{id}` | GET | HTML paywall page |
| `/payments/status` | GET | Gateway status & balance |

---

## Business Model

SatGateway is MIT licensed. We make money by offering:

1. **Hosted facilitator** — We run the Lightning node, you just add the SDK. We take 0.5% per transaction.
2. **Enterprise** — Custom branding, SLA, analytics dashboard. Flat monthly fee.
3. **Open source** — Self-hosted, you keep 100%. We take nothing.

---

## Roadmap

- [ ] CLN (Core Lightning) backend
- [ ] Webhook notifications
- [ ] Analytics dashboard
- [ ] Subscription mode (recurring sats)
- [ ] Multi-currency (USD-denominated, settled in sats)
- [ ] Nostr zaps integration

---

## License

MIT — see [LICENSE](LICENSE)

Built for the lightning-native internet. ⚡
