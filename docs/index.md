# ⚡ SatGateway

> Bitcoin Lightning payments for websites and APIs. Two lines of code. Sub-penny fees. No accounts.

## Why SatGateway?

Stripe charges 2.9% + $0.30 per transaction. That's fine for $50 purchases, but impossible for micropayments. What if you want to charge **1¢ per API call**? Or **100 sats to read an article**?

SatGateway makes it trivial.

## Features

- ⚡ **Lightning Native** — Works with any LND node. Self-hosted or managed.
- 🔌 **FastAPI Middleware** — Gate endpoints with `@require_payment(amount_sats=100)`
- 🌐 **Website Paywall** — Drop-in JavaScript paywall
- 🔒 **Security Audited** — 86 passing security tests, multiple independent audits
- 💰 **Sub-penny Fees** — 0.5% configurable, no per-transaction minimum

## Quick Links

- [GitHub Repository](https://github.com/bellum19/satgateway)
- [PyPI Package](https://pypi.org/project/satgateway/)
- [Docker Hub](https://hub.docker.com/r/bellum19/satgateway)
- [Report an Issue](https://github.com/bellum19/satgateway/issues)
