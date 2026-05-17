# Changelog

All notable changes to SatGateway will be documented in this file.

## [0.1.0] — 2026-05-17

### Added
- Initial release of SatGateway
- Lightning invoice generation via LND REST API
- Mock backend for development (`MOCK_BACKEND=1`)
- FastAPI `@require_payment` decorator for gating endpoints
- JavaScript drop-in paywall (`paywall.js`)
- HTML paywall pages with auto-refresh
- QR code generation for invoices
- Payment verification endpoint (`/payments/verify/{id}`)
- x402 protocol compatible HTTP 402 responses
- Configurable fee basis points (default 0.5%)
- In-memory storage with automatic cleanup and caps
- Background cleanup task for expired payments
- Payment validity window (default 1 hour after payment)
- Cryptographic preimage verification against payment hash
- Resource URL binding (payments locked to specific endpoints)
- Amount validation (prevents underpayment)

### Security
- **GLM-5.1 Audit** — 22 findings identified and fixed
- **Kimi K2.6 Audit** — follow-up verification
- **GPT-5.5 Audit** — 15 additional findings identified and fixed:
  - Unbounded memory growth + lock leaks
  - LND TLS certificate verification
  - Permanent payment replay
  - Lightning preimage cryptographic verification
  - URL path normalization for resource binding
  - Rate limiting on public endpoints
  - Removed unused dependency with known CVEs
  - CORS wildcard fallback eliminated
  - Security headers (X-Frame-Options, CSP, etc.)
  - Constant-time API key comparison
  - Sanitized LND error messages
  - aiohttp request timeouts
  - Metadata size/depth limits
  - Payment ID redaction from access logs
- **86 security tests pass** (`tests/test_security_*.py`)

### Infrastructure
- Docker support (`Dockerfile`, `docker-compose.fullnode.yml`)
- Bitcoin + LND full-node Docker Compose stack
- Uvicorn access log payment ID redaction
- Cache-Control headers on all payment responses

## Roadmap

- [ ] CLN (Core Lightning) backend
- [ ] Webhook notifications
- [ ] Analytics dashboard
- [ ] Subscription mode (recurring sats)
- [ ] Multi-currency (USD-denominated, settled in sats)
- [ ] Nostr zaps integration
