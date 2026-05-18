# Security

SatGateway has undergone multiple independent security audits before release.

## Audit History

| Audit | Date | Scope | Status |
|-------|------|-------|--------|
| GLM-5.1 (OpenRouter) | 2026-05-10 | Full codebase | ✅ 22 findings fixed |
| Kimi K2.6 | 2026-05-11 | Follow-up review | ✅ Verified |
| GPT-5.5 (OpenRouter) | 2026-05-13 | Deep re-audit + new attack vectors | ✅ 15 findings fixed |
| Launch Blockers | 2026-05-16 | Critical regression tests | ✅ 6 blockers resolved |

**All 86 security tests pass.** See `tests/test_security_*.py` for the full test matrix.

## Key Security Features

- 🔒 **TLS Verification** — LND connections require valid certificates in production
- 🔐 **Preimage Verification** — Every Lightning payment hash is cryptographically verified
- ⏱️ **Payment Expiry** — Payments expire after configurable time windows
- 🛡️ **Rate Limiting** — Public endpoints are rate-limited per IP
- 🔑 **Constant-Time Auth** — API keys compared with `hmac.compare_digest`
- 🧹 **Memory Cleanup** — Automatic eviction of expired payments with caps
- 📝 **Log Redaction** — Payment IDs redacted from access logs
- 🌐 **CORS Control** — No wildcard fallback; explicit origin allowlist

## Responsible Disclosure

Found a vulnerability? Please email security@satgateway.local with details.
