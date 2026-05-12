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
curl https://webcatch.dev/payments/api/status

# Create a 21-sat invoice for the secret endpoint
curl -X POST https://webcatch.dev/payments/invoice \
  -H "Content-Type: application/json" \
  -d '{"amount_sats": 21, "description": "secret access", "resource_url": "/api/secret"}'

# Get a QR code for that invoice (replace <payment_id> with the id from above)
curl https://webcatch.dev/payments/qr/<payment_id>

# Verify payment (poll this)
curl https://webcatch.dev/payments/verify/<payment_id>

# Once paid, access the paywalled content
curl -H "X-Payment-Id: <payment_id>" https://webcatch.dev/payments/api/secret
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

That's it. The gateway is live at `http://localhost:9026`.

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
@require_payment(amount_sats=500, description="Pro Tier")
def pro_route():
    return {"data": "exclusive dataset", "expires": "24h"}
```

What happens under the hood:
1. User hits `/api/premium` without paying → `402 Payment Required` with invoice payload
2. User pays the Lightning invoice
3. User re-requests with `X-Payment-Id: <payment_id>` → gets the content

No boilerplate. No webhook juggling. Just sats.

---

## 🏠 Self-Hosting Guide

### Requirements

- Linux server (or any Docker host)
- 1 vCPU / 1 GB RAM minimum ($5 VPS is plenty)
- Python 3.11+ (if running bare-metal)
- Redis 7+ (for analytics & caching)
- LND node (mainnet or testnet) — or use `MockBackend` for development

### Option A: Docker Compose (Recommended)

```yaml
# docker-compose.yml
version: "3.8"

services:
  redis:
    image: redis:7-alpine
    restart: unless-stopped

  satgateway:
    image: ghcr.io/webcatchdev/satgateway:latest
    restart: unless-stopped
    ports:
      - "9026:9026"
    environment:
      - SATGATEWAY_KEY=${SATGATEWAY_KEY:-dev}
      - SATGATEWAY_FEE_BPS=${SATGATEWAY_FEE_BPS:-50}
      - REDIS_HOST=redis
      # Optional: connect to your LND node
      # - LND_HOST=https://lnd:8080
      # - LND_MACAROON=${LND_MACAROON}
      # - LND_CERT_PATH=/app/lnd/tls.cert
    depends_on:
      - redis
```

### Option B: Bare Metal

```bash
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 9026
```

---

## 📁 Project Structure

```
satgateway/
├── satgateway/
│   ├── __init__.py
│   ├── middleware.py     # @require_payment + PaymentGateway router
│   ├── core.py           # SatGateway, backends, models
│   └── backends/
│       ├── base.py
│       ├── lnd.py        # LND REST backend
│       └── mock.py       # Dev/test backend
├── static/
│   └── landing/          # Demo landing page
├── main.py               # FastAPI entry point
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

---

## 📄 License

[MIT](LICENSE) © SatGateway Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

---

> **Lightning is the native money of the internet. SatGateway is its on-ramp for Python developers.**
