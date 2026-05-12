# ⚡ SatGateway

> Self-hosted Bitcoin Lightning payment gateway for FastAPI — monetize any endpoint with a single decorator.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)

SatGateway is a **non-custodial, self-hosted** Lightning payment layer for Python apps. Drop `@require_payment(amount_sats=100)` on any FastAPI route and start accepting sats in seconds. No KYC. No middlemen. No monthly fees. Runs happily on a $5 VPS.

🔗 **Live Demo:** https://webcatch.dev/payments/

---

## 🚀 10-Second Demo

The fastest way to see it work — hit the public demo:

```bash
# Check the gateway status
curl https://webcatch.dev/api/status

# Create a 21-sat invoice for the secret endpoint
curl -X POST https://webcatch.dev/payments/invoice \
  -H "Content-Type: application/json" \
  -d '{"amount_sats": 21, "memo": "secret access", "redirect_url": "/api/secret"}'

# Get a QR code for that invoice (replace <invoice_id> with the id from above)
curl https://webcatch.dev/payments/qr/<invoice_id>

# Verify payment (poll this)
curl https://webcatch.dev/payments/verify/<invoice_id>

# Once paid, access the paywalled content
curl -H "X-Payment-Id: <invoice_id>" https://webcatch.dev/api/secret
```

Node Pubkey: `0301e382e103585adc5b3bd302e73be4e2f9ca44efe00a8f4c1aef075899ea160e`

---

## 🐳 Quick Start (Docker Compose)

Spin up a complete stack in under 60 seconds:

```bash
git clone https://github.com/webcatchdev/satgateway.git
cd satgateway

cp .env.example .env
# Edit .env and add your LND macaroon / cert paths (or leave as-is for MockBackend dev mode)

docker compose up -d
```

That's it. The gateway is live at `http://localhost:8000`.

---

## 🎯 The Decorator

SatGateway's entire API surface is one import and one decorator:

```python
from fastapi import FastAPI
from satgateway import require_payment

app = FastAPI()

@app.get("/api/public")
def public_route():
    return {"message": "free for everyone"}

@app.get("/api/premium")
@require_payment(amount_sats=100)
def premium_route():
    return {"message": "thanks for the sats!"}

@app.get("/api/tiered")
@require_payment(amount_sats=500, memo="Pro Tier")
def pro_route():
    return {"data": "exclusive dataset", "expires": "24h"}
```

What happens under the hood:
1. User hits `/api/premium` without paying → `402 Payment Required` with invoice payload
2. User pays the Lightning invoice
3. User re-requests with `X-Payment-Id: <invoice_id>` → gets the content

No boilerplate. No webhook juggling. Just sats.

---

## 🏠 Self-Hosting Guide

### Requirements

- Linux server (or any Docker host)
- 1 vCPU / 1 GB RAM minimum ($5 VPS is plenty)
- Python 3.11+ (if running bare-metal)
- Redis 7+ (for invoice state & caching)
- LND node (mainnet or testnet) — or use `MockBackend` for development

### Option A: Docker Compose (Recommended)

```yaml
# docker-compose.yml
services:
  redis:
    image: redis:7-alpine
    restart: unless-stopped

  satgateway:
    image: ghcr.io/webcatchdev/satgateway:latest
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      - REDIS_URL=redis://redis:6379
      - LND_GRPC_HOST=lnd:10009
      - LND_MACAROON_PATH=/secrets/admin.macaroon
      - LND_TLS_CERT_PATH=/secrets/tls.cert
    volumes:
      - ./lnd-secrets:/secrets:ro
    depends_on:
      - redis
```

### Option B: Bare Metal

```bash
# 1. Install dependencies
pip install satgateway[all]

# 2. Set environment variables
export REDIS_URL=redis://localhost:6379
export LND_GRPC_HOST=127.0.0.1:10009
export LND_MACAROON_PATH=/home/lnd/.lnd/data/chain/bitcoin/mainnet/admin.macaroon
export LND_TLS_CERT_PATH=/home/lnd/.lnd/tls.cert

# 3. Run
uvicorn satgateway.main:app --host 0.0.0.0 --port 8000
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_URL` | Redis connection string | `redis://localhost:6379` |
| `LND_GRPC_HOST` | LND gRPC endpoint | — |
| `LND_MACAROON_PATH` | Path to LND admin macaroon | — |
| `LND_TLS_CERT_PATH` | Path to LND TLS certificate | — |
| `BACKEND` | `lnd` or `mock` | `lnd` |
| `INVOICE_EXPIRY_SECONDS` | How long invoices live | `300` |

---

## 📡 API Reference

### Gateway Status
```
GET /api/status
```
Returns node connectivity, backend type, and current block height.

### Paywalled Content
```
GET /api/secret
Header: X-Payment-Id: <invoice_id>
```
Demo paywalled endpoint. Returns `402` with invoice details if unpaid.

### Invoice Creation
```
POST /payments/invoice
Content-Type: application/json

{
  "amount_sats": 100,
  "memo": "API access",
  "redirect_url": "/api/premium"
}
```
Response:
```json
{
  "id": "inv_abc123",
  "payment_request": "lnbc1u1p...",
  "amount_sats": 100,
  "expires_at": 1718000000
}
```

### QR Code
```
GET /payments/qr/{id}
```
Returns a PNG QR code for the invoice.

### Payment Verification
```
GET /payments/verify/{id}
```
Response:
```json
{
  "paid": true,
  "settled_at": 1717999999,
  "amount_sats": 100
}
```

---

## ⚔️ SatGateway vs. Alternatives

| | **SatGateway** | **LNPay** | **Voltage** | **Alby** |
|---|---|---|---|---|
| **Custody** | Non-custodial (your node) | Custodial | Non-custodial | Custodial |
| **Fees** | 0% routing only | Subscription + % | Subscription | % of volume |
| **Hosting** | Self-hosted | SaaS | Cloud node | SaaS |
| **FastAPI integration** | Native decorator | REST polling | REST polling | OAuth + REST |
| **Vendor lock-in** | None | High | Medium | Medium |
| **Privacy** | Full (no third party) | KYC required | Account required | Account required |
| **VPS cost** | ~$5/mo | $0 + fees | ~$20+/mo | Variable |

SatGateway is built for developers who want **full control**, **zero platform fees**, and **tight framework integration**. If you already run LND, it's the cheapest and most private option available.

---

## 🛠️ Development

```bash
# Clone and setup
git clone https://github.com/webcatchdev/satgateway.git
cd satgateway
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest -q

# Run with MockBackend (no LND required)
BACKEND=mock uvicorn satgateway.main:app --reload
```

### Project Layout

```
satgateway/
├── satgateway/
│   ├── __init__.py
│   ├── main.py           # FastAPI app
│   ├── decorators.py     # @require_payment
│   ├── backends/
│   │   ├── base.py
│   │   ├── lnd.py        # LND gRPC backend
│   │   └── mock.py       # Dev/test backend
│   └── models.py
├── tests/
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 🤝 Contributing

Contributions are welcome! Please open an issue first for major changes.

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/amazing-thing`
3. Commit your changes: `git commit -m 'feat: add amazing thing'`
4. Push and open a PR

Make sure tests pass and add coverage for new code.

---

## 📄 License

[MIT](LICENSE) © SatGateway Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

---

> **Lightning is the native money of the internet. SatGateway is its on-ramp for Python developers.**
