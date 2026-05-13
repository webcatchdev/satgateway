# SatGateway Security Audit Report — GPT-5.5 (OpenRouter)

**Date:** 2026-05-13  
**Auditor:** GPT-5.5 via OpenRouter  
**Scope:** Full codebase (~1,200 lines across source files, tests, Docker configs, and static assets)  
**Classification:** Follow-up audit focused on NEW vulnerabilities missed or left unfixed by GLM-5.1 and Kimi K2.6

---

## Executive Summary

This audit focused on identifying **new** security issues that previous audits (GLM-5.1 and Kimi K2.6) either missed entirely or reported but failed to actually fix. The codebase has 22 previously-reported findings that were supposedly patched; this review confirms that **several of those fixes are incomplete or were never applied**, and identifies **additional novel attack vectors** in cryptography, Lightning-specific logic, container security, and application configuration.

**Key findings:**

1. **Unbounded memory growth** (High) — `_payments` and `_locks` dicts grow forever; F-11 was reported but never fixed.
2. **LND TLS verification disabled** (High) — F-19 was reported but `self._ssl = False` remains in production code.
3. **Permanent payment replay** (High) — A single paid payment grants lifetime access with no expiration or revocation.
4. **Lightning preimage never cryptographically verified** (High) — A fundamental Lightning security property is ignored.
5. **F-01 fix introduced a regression** (Medium) — API-created invoices can never be validated by `require_payment` due to URL format mismatch.

---

## Findings

### NEW-01: Unbounded In-Memory Storage + Lock Memory Leak (High)

**Files:** `satgateway/core.py` lines 202, 204, 229  
**Severity:** High  
**CWE:** CWE-770 (Allocation of Resources Without Limits)

**Description:**  
`SatGateway._payments` is a plain `dict` that grows without bound. Expired, paid, and abandoned payments are never evicted. The same issue affects `self._locks` (line 204): every `check_payment` call creates a new `asyncio.Lock` per payment ID, and these locks live forever. F-11 was identified by GLM-5.1 but **no cleanup logic was ever implemented**.

In production, an attacker with a valid API key (or a compromised legitimate client) can create millions of invoices and exhaust server memory, causing a DoS.

**Proof of concept:**
```python
# tests/test_security_gpt55.py::TestUnboundedMemoryStorage
gw = SatGateway(backend=MockBackend(), config=GatewayConfig(api_key="test"))
for i in range(500):
    req = await gw.create_request(amount_sats=1, description=f"spam {i}", resource_url="/")
    req.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
assert len(gw._payments) == 500   # All expired, all still in memory
assert len(gw._locks) == 500      # Locks leaked too
```

**Remediation:**
- Implement a periodic cleanup task that removes expired payments and their locks:
```python
async def _cleanup_expired(self):
    now = datetime.now(timezone.utc)
    expired = [pid for pid, p in self._payments.items() if p.expires_at < now]
    for pid in expired:
        self._payments.pop(pid, None)
        self._locks.pop(pid, None)
```
- For production, migrate to Redis or a database with TTL support.

---

### NEW-02: LND TLS Certificate Verification Disabled by Default (High)

**File:** `satgateway/core.py` lines 122–126  
**Severity:** High  
**CWE:** CWE-295 (Improper Certificate Validation)

**Description:**  
`LndBackend.__init__` sets `self._ssl = False` whenever `cert_path` is not provided or the file does not exist. This disables TLS certificate verification for all LND REST API calls, allowing a network-positioned attacker to perform a MITM attack on the SatGateway ↔ LND connection. F-19 was identified in the GLM-5.1 audit but **the code was never changed**.

An attacker who can intercept traffic (e.g., on a compromised Docker network, via ARP spoofing, or DNS hijacking) can:
- Steal the LND macaroon
- Return fake payment confirmations
- Modify invoice amounts

**Proof of concept:**
```python
# tests/test_security_gpt55.py::TestLndTlsVerificationDisabled
backend = LndBackend(host="https://lnd:8080", macaroon_hex="deadbeef")
assert backend._ssl is False   # TLS verification completely disabled
```

**Remediation:**
- Default to strict TLS verification. Only disable it explicitly in development:
```python
if cert_path and os.path.exists(cert_path):
    self._ssl = ssl.create_default_context(cafile=cert_path)
else:
    raise ValueError("LND TLS certificate is required in production. Set LND_TLS_CERT_PATH.")
```

---

### NEW-03: Paid Payments Never Expire — Permanent Replay (High)

**Files:** `satgateway/core.py` lines 237–238, `satgateway/middleware.py` lines 84–95  
**Severity:** High  
**CWE:** CWE-284 (Improper Access Control)

**Description:**  
Once a payment is marked `"paid"`, `check_payment` returns `{"paid": True}` **forever** with no expiration, revocation, or session binding. The `sg_payment_id` cookie has `max_age=3600`, but the underlying payment ID can be reused indefinitely via the `X-Payment-ID` header. A user who pays once has a **lifetime pass** to the resource.

This is distinct from F-01 (cross-resource reuse). Even within the same resource, there is no time limit on the payment proof. If the resource price increases, the old cheap payment still works. If the user's access should be revoked (e.g., refund, abuse, subscription lapse), there is no mechanism to do so.

**Proof of concept:**
```python
# tests/test_security_gpt55.py::TestPermanentPaymentReplay
req = await gw.create_request(amount_sats=100, description="test", resource_url="/api/expensive")
req.status = "paid"
req.paid_at = datetime.now(timezone.utc) - timedelta(days=365)
status = await gw.check_payment(req.id)
assert status["paid"] is True   # One-year-old payment still valid
```

**Remediation:**
- Add a `payment_valid_for_seconds` field to `PaymentRequest`.
- After payment, validate `paid_at + validity_window > now()` before granting access.
- Consider using short-lived JWTs or signed cookies for session management instead of raw payment IDs.

---

### NEW-04: Lightning Preimage Never Cryptographically Verified (High)

**File:** `satgateway/core.py` lines 264–266  
**Severity:** High  
**CWE:** CWE-354 (Improper Validation of Integrity Check Value)

**Description:**  
When `check_payment` receives a preimage from the backend, it stores it in `req.preimage` but **never verifies that `SHA256(preimage) == payment_hash`**. Cryptographic preimage verification is a foundational property of the Lightning Network. Without it, a malicious LND backend (or a MITM attacker exploiting NEW-02) can claim any arbitrary payment is settled by returning `paid=True` with a random fake preimage.

SatGateway trusts the backend's `paid` boolean blindly. In a adversarial or compromised backend scenario, this allows complete payment bypass.

**Proof of concept:**
```python
# tests/test_security_gpt55.py::TestPreimageNotVerified
fake_preimage = "a" * 64
mock_check.return_value = {"paid": True, "preimage": fake_preimage, "amount_paid": 100}
status = await gw.check_payment(req.id)
assert status["paid"] is True
assert req.preimage == fake_preimage
# SHA256(fake_preimage) != req.payment_hash, yet gateway accepted it
```

**Remediation:**
- Always verify the preimage before marking a payment as paid:
```python
if result["paid"]:
    preimage = result.get("preimage")
    if preimage:
        expected = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
        if expected != req.payment_hash:
            raise ValueError("Preimage does not match payment hash — possible fraud")
    req.preimage = preimage
    req.status = "paid"
```

---

### NEW-05: F-01 Fix Introduced a Functional Regression (Medium)

**File:** `satgateway/middleware.py` lines 90–91, 172–173  
**Severity:** Medium  
**CWE:** CWE-840 (Business Logic Errors)

**Description:**  
The fix for F-01 added a check: `if payment.resource_url != str(request.url): raise HTTPException(403)`. However, `/payments/invoice` enforces that `resource_url` must be a **relative path** starting with `/`, while `str(request.url)` in FastAPI is always an **absolute URL** like `http://testserver/api/expensive`. Therefore, **any invoice created via the public API can never be validated by `require_payment`**, even when accessing the correct resource.

This breaks legitimate use cases where a client creates an invoice via API and then presents the payment ID to a `@require_payment` endpoint. It also forces all payment flows through the decorator's auto-generated invoices, reducing flexibility.

**Proof of concept:**
```python
# Create invoice via API with relative URL
resp = client.post("/payments/invoice",
    json={"amount_sats": 100, "resource_url": "/api/expensive"},
    headers={"X-API-Key": "..."})
pid = resp.json()["payment_id"]
# Try to access /api/expensive with this payment ID
gw._payments[pid].status = "paid"
resp = client.get("/api/expensive", headers={"X-Payment-ID": pid})
# Returns 403 because "/api/expensive" != "http://testserver/api/expensive"
```

**Remediation:**
- Normalize URL comparison. Either store and compare only the path component, or allow the decorator to match both relative and absolute forms:
```python
from urllib.parse import urlparse
stored_path = urlparse(payment.resource_url).path or payment.resource_url
request_path = urlparse(str(request.url)).path
if stored_path != request_path:
    raise HTTPException(status_code=403, detail="Payment not valid for this resource")
```

---

### NEW-06: No Rate Limiting on Public Endpoints (Medium)

**Files:** `satgateway/middleware.py` lines 189–206  
**Severity:** Medium  
**CWE:** CWE-770 / CWE-799

**Description:**  
F-20 (No rate limiting) was reported by GLM-5.1 but **no rate limiting was ever implemented**. The public endpoints `/payments/verify/{payment_id}`, `/payments/qr/{payment_id}`, and `/payments/paywall/{payment_id}` can be hit without authentication and without any throttling. An attacker can:
- Aggressively poll `/payments/verify/` to probe for valid payment IDs
- Repeatedly request `/payments/qr/` to trigger expensive PIL-based QR generation (CPU/memory DoS)
- Scrape `/payments/paywall/` pages

**Proof of concept:**
```python
# tests/test_security_gpt55.py::TestNoRateLimiting
for _ in range(50):
    r = client.get(f"/payments/verify/{pid}")
    assert r.status_code == 200   # No throttling, all succeed instantly
```

**Remediation:**
- Add rate limiting using `slowapi` or `fastapi-limiter` with Redis:
```python
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
```
- Apply stricter limits to `/payments/qr/` due to CPU cost.

---

### NEW-07: Unused Dependency with Known CVEs (Medium)

**Files:** `requirements.txt` line 7, `pyproject.toml` line 34  
**Severity:** Medium  
**CWE:** CWE-1104 (Use of Unmaintained Third-Party Components)

**Description:**  
`python-jose[cryptography]` is listed as a dependency but **is never imported or used** anywhere in the codebase. It has known vulnerabilities:
- CVE-2024-33663 (algorithm confusion)
- CVE-2024-33664 (key confusion)

Unused dependencies expand the attack surface and may be pulled in by attackers who discover novel vulnerabilities in the library.

**Proof of concept:**
```python
# tests/test_security_gpt55.py::TestUnusedDependency
assert "jose" not in sys.modules   # Never imported
assert "python-jose" in open("requirements.txt").read()
```

**Remediation:**
- Remove `python-jose[cryptography]` from `requirements.txt` and `pyproject.toml`.

---

### NEW-08: CORS Still Defaults to Wildcard (Medium)

**File:** `main.py` lines 59–63  
**Severity:** Medium  
**CWE:** CWE-942 (Overly Permissive CORS Policy)

**Description:**  
F-17 was supposedly fixed by reading `ALLOWED_ORIGINS` from an environment variable. However, the code still falls back to `allow_origins = ["*"]` when the variable is unset. In production, operators who forget to set `ALLOWED_ORIGINS` will run with a completely open CORS policy. Any website can make cross-origin requests, including reading payment statuses and replaying payment IDs.

**Proof of concept:**
```python
# tests/test_security_gpt55.py::TestCorsWildcardFallback
assert 'allow_origins = ["*"]' in open("main.py").read()
```

**Remediation:**
- Refuse to start if `ALLOWED_ORIGINS` is not set, or default to an empty list:
```python
allow_origins = [o.strip() for o in origins.split(",")] if origins else []
if not allow_origins:
    raise RuntimeError("ALLOWED_ORIGINS must be set for CORS policy")
```

---

### NEW-09: Hardcoded Weak Credentials in Docker / LND Configs (Medium)

**Files:** `Dockerfile` line 18, `docker-compose.fullnode.yml` line 17, `lnd-fullnode.conf` line 15  
**Severity:** Medium  
**CWE:** CWE-798 (Use of Hard-coded Credentials)

**Description:**  
- `Dockerfile` sets `ENV SATGATEWAY_KEY=changeme` — containers built without an explicit override will use a trivially guessable default.
- `docker-compose.fullnode.yml` sets `-rpcpassword=CHANGE_ME_STRONG_PASSWORD`
- `lnd-fullnode.conf` sets `bitcoind.rpcpass=CHANGE_ME_STRONG_PASSWORD`

If operators deploy without changing these placeholders, attackers on the Docker network can access Bitcoin RPC with a known password.

**Proof of concept:**
```python
# tests/test_security_gpt55.py::TestHardcodedWeakCredentials
assert "SATGATEWAY_KEY=changeme" in open("Dockerfile").read()
assert "CHANGE_ME_STRONG_PASSWORD" in open("docker-compose.fullnode.yml").read()
assert "CHANGE_ME_STRONG_PASSWORD" in open("lnd-fullnode.conf").read()
```

**Remediation:**
- Remove `ENV SATGATEWAY_KEY=changeme` from the Dockerfile entirely.
- Replace placeholder passwords with explicit `${VAR}` substitutions that fail at runtime if unset.

---

### NEW-10: Missing Security Headers (Medium)

**File:** `main.py` (global)  
**Severity:** Medium  
**CWE:** CWE-693 (Protection Mechanism Failure)

**Description:**  
The application does not set any security headers:
- `X-Frame-Options` — missing, allowing clickjacking of paywall pages
- `X-Content-Type-Options: nosniff` — missing
- `Strict-Transport-Security` — missing
- `Content-Security-Policy` — missing

An attacker can embed the paywall or paid content in an invisible iframe and trick users into paying for the attacker's content (clickjacking).

**Proof of concept:**
```python
# tests/test_security_gpt55.py::TestMissingSecurityHeaders
resp = client.get("/")
assert "X-Frame-Options" not in resp.headers
assert "Content-Security-Policy" not in resp.headers
```

**Remediation:**
- Add a FastAPI middleware to inject security headers on all responses:
```python
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response
```

---

### NEW-11: API Key Comparison Not Constant-Time (Low)

**File:** `satgateway/middleware.py` lines 36–39  
**Severity:** Low  
**CWE:** CWE-208 (Observable Timing Discrepancy)

**Description:**  
`verify_api_key` compares the submitted key using `!=`, which short-circuits on the first mismatched byte. A sophisticated attacker could measure response-time differences to recover the API key one character at a time.

**Proof of concept:**
```python
# tests/test_security_gpt55.py::TestApiKeyTimingAttack
assert "!=" in inspect.getsource(verify_api_key)
assert "hmac.compare_digest" not in inspect.getsource(verify_api_key)
```

**Remediation:**
- Use `hmac.compare_digest` or `secrets.compare_digest`:
```python
import hmac
if not x_api_key or not hmac.compare_digest(x_api_key, gateway.config.api_key):
    raise HTTPException(status_code=401, detail="Invalid API key")
```

---

### NEW-12: LND Error Messages Leak Internal Information (Low)

**File:** `satgateway/core.py` lines 140–141  
**Severity:** Low  
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)

**Description:**  
When LND returns an error, `LndBackend.create_invoice` raises `RuntimeError(f"LND create_invoice failed: {resp.status} {text}")`. If this exception propagates to the HTTP client (e.g., in development mode or if not caught by middleware), it leaks:
- LND internal error messages
- Potentially LND version or path information
- Macaroon-related errors that reveal privilege levels

**Proof of concept:**
```python
# tests/test_security_gpt55.py::TestLndErrorInfoLeak
assert "await resp.text()" in inspect.getsource(LndBackend.create_invoice)
assert "raise RuntimeError" in inspect.getsource(LndBackend.create_invoice)
```

**Remediation:**
- Log the full error server-side, but return a generic message to clients:
```python
try:
    ...
except RuntimeError:
    logger.error("LND create_invoice failed", exc_info=True)
    raise HTTPException(status_code=502, detail="Invoice service unavailable")
```

---

### NEW-13: aiohttp Requests Lack Timeout (Low)

**File:** `satgateway/core.py` lines 137–138, 158–159, 178–179  
**Severity:** Low  
**CWE:** CWE-1088 (Synchronous Access of Remote Resource without Timeout)

**Description:**  
All `aiohttp` calls in `LndBackend` omit the `timeout` parameter. If LND becomes unresponsive, the gateway coroutine will hang indefinitely, exhausting the async worker pool and causing a DoS.

**Proof of concept:**
```python
# tests/test_security_gpt55.py::TestAiohttpNoTimeout
assert "timeout" not in inspect.getsource(LndBackend.create_invoice)
assert "timeout" not in inspect.getsource(LndBackend.check_payment)
assert "timeout" not in inspect.getsource(LndBackend.get_balance)
```

**Remediation:**
- Add explicit timeouts:
```python
import aiohttp
TIMEOUT = aiohttp.ClientTimeout(total=10)
async with session.post(url, json=payload, headers=self._headers, ssl=self._ssl, timeout=TIMEOUT) as resp:
    ...
```

---

### NEW-14: Metadata Size/Depth Unbounded (Low)

**File:** `satgateway/middleware.py` line 25  
**Severity:** Low  
**CWE:** CWE-20 (Improper Input Validation)

**Description:**  
`InvoiceRequest.metadata` accepts any `dict` with no size limit, depth limit, or key/value validation. An attacker can send a 500MB metadata blob or a deeply nested structure to exhaust server memory or cause stack-overflow during JSON serialization.

**Proof of concept:**
```python
# tests/test_security_gpt55.py::TestUnboundedMetadata
deep = {}
current = deep
for i in range(200):
    current["next"] = {}
    current = current["next"]
resp = client.post("/payments/invoice",
    json={"amount_sats": 10, "resource_url": "/", "metadata": deep},
    headers={"X-API-Key": "..."})
assert resp.status_code == 200   # Accepted without complaint
```

**Remediation:**
- Add size limits in Pydantic:
```python
from pydantic import BaseModel, Field
class InvoiceRequest(BaseModel):
    metadata: Optional[dict] = Field(default=None, max_length=10)
    # Or use a custom validator to limit total JSON size and nesting depth
```

---

### NEW-15: Payment IDs Logged in Access Logs (Low)

**File:** `server.log`  
**Severity:** Low  
**CWE:** CWE-532 (Insertion of Sensitive Information into Log File)

**Description:**  
Uvicorn access logs include full request paths such as `/payments/verify/7ae2922c-8821-405b-8d77-4511542f029a`. If logs are stored insecurely or forwarded to third-party log aggregation services, payment IDs are exposed. An attacker who gains log access can replay these IDs as `X-Payment-ID` headers.

F-21 was reported by GLM-5.1 but **no log redaction was implemented**.

**Proof of concept:**
```python
# tests/test_security_gpt55.py::TestPaymentIdsInLogs
content = open("server.log").read()
assert "/payments/verify/" in content
uuids = re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", content)
assert len(uuids) > 0
```

**Remediation:**
- Configure Uvicorn/ASGI middleware to redact payment IDs from logs:
```python
class RedactPaymentIdsLoggingMiddleware:
    def __call__(self, scope):
        # Replace UUID patterns in paths before logging
        pass
```
- Ensure log files have strict permissions (`chmod 600`) and are not included in backups or error reports.

---

## Summary Table

| ID | Severity | Finding | File | Status |
|----|----------|---------|------|--------|
| NEW-01 | High | Unbounded memory + lock leak | `core.py:202,204,229` | Previously reported (F-11), **still unfixed** |
| NEW-02 | High | LND TLS verification disabled | `core.py:122-126` | Previously reported (F-19), **still unfixed** |
| NEW-03 | High | Permanent payment replay | `core.py:237-238`, `middleware.py:84-95` | **New finding** |
| NEW-04 | High | Preimage not cryptographically verified | `core.py:264-266` | **New finding** |
| NEW-05 | Medium | F-01 fix regression (URL mismatch) | `middleware.py:90-91,172-173` | **New finding** |
| NEW-06 | Medium | No rate limiting | `middleware.py:189-206` | Previously reported (F-20), **still unfixed** |
| NEW-07 | Medium | Unused dependency with CVEs | `requirements.txt:7` | **New finding** |
| NEW-08 | Medium | CORS wildcard fallback | `main.py:59-63` | Fix incomplete |
| NEW-09 | Medium | Hardcoded weak credentials | `Dockerfile:18`, `docker-compose.fullnode.yml:17` | **New finding** |
| NEW-10 | Medium | Missing security headers | `main.py` (global) | **New finding** |
| NEW-11 | Low | API key timing attack | `middleware.py:36-39` | **New finding** |
| NEW-12 | Low | LND error info leakage | `core.py:140-141` | **New finding** |
| NEW-13 | Low | aiohttp no timeout | `core.py:137-138,158-159,178-179` | **New finding** |
| NEW-14 | Low | Unbounded metadata | `middleware.py:25` | **New finding** |
| NEW-15 | Low | Payment IDs in logs | `server.log` | Previously reported (F-21), **still unfixed** |

---

## Recommended Priority Actions

1. **Fix NEW-03 and NEW-04 immediately** — Payment replay and missing preimage verification are fundamental flaws in the payment security model.
2. **Fix NEW-01 and NEW-02** — These were reported before but remain unfixed. Unbounded memory growth will crash production servers; disabled TLS verification exposes LND macaroons.
3. **Fix NEW-05** — The F-01 fix broke legitimate API usage. Normalize URL comparison before the next release.
4. **Remove python-jose (NEW-07)** and **add rate limiting (NEW-06)** before public deployment.
5. **Harden Docker configs (NEW-09)** — Never ship containers with default passwords.
6. **Add security headers (NEW-10)** and **timeouts (NEW-13)** to improve resilience.
