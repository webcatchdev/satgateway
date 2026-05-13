# SatGateway Security Audit Report — GLM-5.1

**Date:** 2026-05-12  
**Auditor:** GLM-5.1 (independent audit)  
**Scope:** Full codebase (~900 lines across 5 source files + infrastructure configs)  
**Classification:** Independent fresh review — no reference to prior audits

---

## Executive Summary

SatGateway is a Bitcoin Lightning payment gateway for websites and APIs. The audit identified **22 distinct security findings** ranging from Critical to Low severity. The most severe issues are:

1. **Cross-resource payment reuse** (Critical) — any paid payment grants access to ALL paywalled endpoints regardless of amount or resource
2. **Stored XSS via user-controlled `resource_url`** in server-rendered HTML (Critical) — full JavaScript execution in victim browsers
3. **Invoice amount bypass** (High) — pay 1 sat for a 1000-sat resource via the public API

The fundamental architectural flaw is that the payment verification check only confirms `paid=True` without binding the payment to a specific resource or validating the amount paid matches the required amount. This defeats the entire purpose of the paywall.

---

## findings

### F-01: Cross-Resource Payment Reuse (Critical)

**Files:** `satgateway/middleware.py` lines 53-61  
**Severity:** Critical  
**CWE:** CWE-284 (Improper Access Control)

**Description:**  
The `require_payment` decorator checks only whether a payment ID is "paid" — it does NOT verify what resource the payment was created for, nor the amount. A user who pays for *any* endpoint receives a payment ID cookie that grants access to *every* `@require_payment` endpoint, regardless of the required amount.

**Attack scenario:**  
1. Attacker pays 1 sat for a cheap endpoint (or uses the free `/payments/invoice` API to create a 1-sat invoice)
2. After payment, attacker receives `sg_payment_id` cookie  
3. Attacker sends that same cookie to a 10,000-sat endpoint → access granted

**Proof of concept:**
```python
# Pay 1 sat for /api/cheap
req = await gateway.create_request(amount_sats=1, resource_url="/api/cheap")
# Mark as paid (or wait for mock auto-pay)
# ...
# Re-use same payment_id for /api/expensive endpoint
# require_payment only checks: status.get("paid") → True → ACCESS GRANTED
```

**Fix:**  
When checking a payment, validate that the payment's `resource_url` matches the current request path AND that `payment.amount_sats >= required_amount_sats`:

```python
# In require_payment decorator, replace lines 57-61 with:
if payment_id:
    status = await _gateway.check_payment(payment_id)
    if status.get("paid"):
        payment = _gateway.get_payment(payment_id)
        # Validate resource binding
        if payment.resource_url != str(request.url):
            raise HTTPException(status_code=403, detail="Payment not valid for this resource")
        # Validate amount
        if payment.amount_sats < amount_sats:
            raise HTTPException(status_code=403, detail="Payment amount insufficient")
        return await func(*args, **kwargs)
```

---

### F-02: Stored XSS via resource_url in Paywall Page (Critical)

**File:** `satgateway/middleware.py` lines 166-219, specifically lines 199 and 209  
**Severity:** Critical  
**CWE:** CWE-79 (Cross-Site Scripting)

**Description:**  
The `/payments/paywall/{payment_id}` endpoint constructs HTML using an f-string that directly interpolates `payment.resource_url` into a JavaScript string without escaping. Since `resource_url` is user-controlled (submitted via the `/payments/invoice` POST endpoint), an attacker can inject arbitrary JavaScript.

**Vulnerable code:**
```python
# Line 209:
window.location.href = '{payment.resource_url or "/"}'
```

**Attack:**  
```
POST /payments/invoice
{"amount_sats": 1, "resource_url": "'}; alert(document.cookie); window.location.href='"}
```

This creates a payment where `resource_url` contains `'}; alert(document.cookie); window.location.href='`, which breaks out of the JavaScript string and executes arbitrary code in the victim's browser.

**Fix:**  
Use `html.escape()` and JSON-encode values interpolated into HTML/JS contexts:

```python
import html, json

# In the f-string:
window.location.href = {json.dumps(payment.resource_url or "/")}
```

Or better, use a template engine like Jinja2 with auto-escaping.

---

### F-03: XSS in paywall.js renderContent (High)

**File:** `static/paywall.js` lines 76-83  
**Severity:** High  
**CWE:** CWE-79 (Cross-Site Scripting)

**Description:**  
The `renderContent` function interpolates `JSON.stringify(data)` into `innerHTML`. While `JSON.stringify` adds quotes around strings, it does NOT escape HTML entities. The `</pre>` tag within the JSON string can close the `<pre>` tag, and embedded HTML like `<img onerror=...>` then executes.

**Vulnerable code:**
```javascript
container.innerHTML = `
    <pre ...>${JSON.stringify(data, null, 2)}</pre>
`;
```

If a paid endpoint returns `{"secret": "</pre><img src=x onerror=alert(1)>"}` the XSS fires.

**Fix:**  
Escape HTML in rendered data:
```javascript
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
// Then:
container.innerHTML = `<pre ...>${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
```

---

### F-04: XSS in paywall.js renderPaywall (Medium)

**File:** `static/paywall.js` lines 61-73, especially line 70  
**Severity:** Medium  
**CWE:** CWE-79 (Cross-Site Scripting)

**Description:**  
Same pattern as F-03: `payment.invoice` is interpolated directly into `innerHTML`. While Lightning invoices follow the `lnbc...` format and are hard to exploit in practice (they're controlled by the backend), this is still a defense-in-depth violation. If a malicious backend or MITM injects tags into the invoice string, it would execute.

**Fix:** Same as F-03 — escape HTML before inserting into innerHTML.

---

### F-05: Invoice Amount Bypass via Public API (High)

**File:** `satgateway/middleware.py` lines 124-139  
**Severity:** High  
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)

**Description:**  
The `/payments/invoice` endpoint accepts `amount_sats` directly from the request body with no validation or rate limiting. Combined with F-01 (cross-resource reuse), an attacker can:
1. POST `/payments/invoice` with `amount_sats: 1`
2. Pay the 1-sat invoice
3. Use that payment cookie to access 10,000-sat endpoints

Even without F-01, this endpoint allows creating arbitrarily small invoices. It also allows creating invoices for arbitrarily large amounts up to 10M sats (0.1 BTC), which could be abused for money laundering or to exhaust backend resources.

**Fix:**  
- Add authentication to the `/payments/invoice` endpoint  
- Validate amount bounds on the server side  
- Rate-limit invoice creation  
- Bind invoices to specific resources so they cannot be used across endpoints

---

### F-06: LND Admin Macaroon Used Instead of Invoice-Only (High)

**File:** `docker-compose.neutrino.yml` line 27, `docker-compose.fullnode.yml` line 50  
**Severity:** High  
**CWE:** CWE-250 (Execution with Unnecessary Privileges)

**Description:**  
The docker-compose configurations mount `admin.macaroon` for LND access. The admin macaroon grants full control over the LND node — including draining funds, closing channels, and modifying node configuration. SatGateway only needs to create invoices and check payment status.

If the SatGateway application is compromised (e.g., via F-02 XSS leading to server-side code execution, or any SSRF), the attacker gains full LND admin control and can steal all funds.

**Fix:**  
Create a custom macaroon with only `invoices:create` and `invoices:read` permissions:
```bash
lncli bakemacaroon invoices:create invoices:read --save_to=invoice.macaroon
```
Then mount `invoice.macaroon` instead of `admin.macaroon`.

---

### F-07: Default/Weak API Key (High)

**File:** `main.py` line 30, `satgateway/middleware.py` lines 242, 252  
**Severity:** High  
**CWE:** CWE-798 (Use of Hard-coded Credentials)

**Description:**  
The API key defaults to `"dev"` when the `SATGATEWAY_KEY` environment variable is not set. This is a trivially guessable credential. The Dockerfile also sets `SATGATEWAY_KEY=changeme` as the default. No authentication is enforced against this key for any endpoint.

**Fix:**  
- Refuse to start if `SATGATEWAY_KEY` is not set to a strong value  
- Remove default keys  
- Actually authenticate requests using the API key (currently no endpoint checks it)

---

### F-08: Open Redirect via resource_url (High)

**File:** `satgateway/middleware.py` line 209  
**Severity:** High  
**CWE:** CWE-601 (Open Redirect)

**Description:**  
The paywall page redirects users to `payment.resource_url` after payment. Since `resource_url` is user-controlled and not validated, an attacker can create a payment with `resource_url` pointing to a phishing site:

```
POST /payments/invoice
{"amount_sats": 100, "resource_url": "https://evil-phishing-site.com"}
```

Victims who follow the payment link will be redirected to the attacker's site after paying.

**Fix:**  
Validate `resource_url` to be a relative path (starting with `/`) or match against an allowlist. Never redirect to absolute URLs.

---

### F-09: Bitcoin Core RPC Exposed to All Networks (High)

**File:** `docker-compose.fullnode.yml` lines 17-19  
**Severity:** High  
**CWE:** CWE-1327 (Authorization Misconfiguration)

**Description:**  
The Bitcoind configuration uses:
- `rpcbind=0.0.0.0` — binds RPC to all interfaces
- `rpcallowip=0.0.0.0/0` — allows RPC from any IP
- `rpcpassword=CHANGE...WORD` — placeholder weak password

While the container is on an internal Docker network, these settings are dangerously permissive. If Docker networking is misconfigured or the container is exposed, anyone can control the Bitcoin node.

**Fix:**  
- Use `rpcbind=0.0.0.0` with `rpcallowip=172.16.0.0/12` (Docker networks only)  
- Set a strong, unique RPC password  
- Consider using Bitcoind's `-rpcwhitelist` feature

---

### F-10: Unauthenticated Invoice Creation — Resource Exhaustion (High)

**File:** `satgateway/middleware.py` lines 124-139  
**Severity:** High  
**CWE:** CWE-770 (Allocation of Resources Without Limits)

**Description:**  
The `/payments/invoice` endpoint requires no authentication and has no rate limiting. Each invoice creates a `PaymentRequest` object stored in the `_payments` dict, which is never cleaned up. An attacker can:
1. Create millions of invoices to exhaust server memory
2. Create invoices with large `amount_sats` to create large Lightning network invoices
3. Flood the LND backend with invoice creation requests

**Fix:**  
- Add rate limiting (per-IP and global)  
- Add authentication  
- Set a maximum on `_payments` dict size  
- Implement payment expiration and cleanup

---

### F-11: In-Memory Storage With No Eviction (Medium)

**File:** `satgateway/core.py` line 202  
**Severity:** Medium  
**CWE:** CWE-770 (Allocation of Resources Without Limits)

**Description:**  
`SatGateway._payments` is a plain dict that grows without bound. Expired and completed payments are never removed. In production, this leads to:
- Unbounded memory growth
- All payment state lost on server restart (users lose access to paid content)
- No persistence across deployments

**Fix:**  
Add a cleanup task that removes expired payments. Consider persistent storage (Redis/database) for production.

```python
async def _cleanup_expired(self):
    now = datetime.now(timezone.utc)
    expired = [pid for pid, p in self._payments.items() if p.expires_at < now]
    for pid in expired:
        del self._payments[pid]
```

---

### F-12: Cookie Missing SameSite and Secure Flags (Medium)

**File:** `satgateway/middleware.py` line 97  
**Severity:** Medium  
**CWE:** CWE-1275 (Sensitive Cookie Without SameSite Attribute)

**Description:**  
The `sg_payment_id` cookie is set with `httponly=True` but without:
- `secure=True` — cookie sent over plain HTTP
- `samesite="Lax"` or `"Strict"` — cookie sent with cross-site navigations

Without `SameSite`, the cookie is sent with cross-origin POST requests, enabling CSRF-style attacks where an attacker's site can trigger invoice creation using the victim's browser.

**Fix:**
```python
response.set_cookie(
    key="sg_payment_id", value=req.id, max_age=3600,
    httponly=True, secure=True, samesite="Lax"
)
```

---

### F-13: sg_preimage Checked But Never Set (Medium)

**File:** `satgateway/middleware.py` line 55  
**Severity:** Medium  
**CWE:** CWE-754 (Improper Check for Unusual Conditions)

**Description:**  
The decorator checks for `X-Payment-Preimage` header and `sg_preimage` cookie, but neither is ever set. Line 97 only sets `sg_payment_id`. The preimage-based verification path is dead code, meaning the system has a claimed but unimplemented security feature. If someone intended the preimage to provide cryptographic proof of payment, it's not working.

**Fix:**  
Either:
1. Remove the dead preimage check, or
2. Implement proper preimage storage and verification: store the preimage when payment is confirmed, set it as a cookie `sg_preimage`, and verify it matches the expected value on subsequent requests.

---

### F-14: Information Disclosure via Status Endpoints (Medium)

**Files:** `main.py` lines 155-167, `satgateway/middleware.py` lines 221-228  
**Severity:** Medium  
**CWE:** CWE-200 (Information Exposure)

**Description:**  
Both `/api/status` and `/payments/status` expose sensitive information without authentication:
- Node balance in sats (`balance_sats`)
- Fee configuration (`fee_bps`)
- Backend type (mock vs LND)
- Software version

An attacker can use the balance info to target high-value nodes, and the version info to find known exploits.

**Fix:**  
Require authentication (API key) for these endpoints, or remove them in production.

---

### F-15: Race Condition in Payment Callback (Medium)

**File:** `satgateway/core.py` lines 231-256  
**Severity:** Medium  
**CWE:** CWE-362 (Race Condition)

**Description:**  
When two concurrent requests check the same payment ID:
1. Request A: `req.status != "paid"` → calls `backend.check_payment`
2. Request B: `req.status != "paid"` → also calls `backend.check_payment`  
3. Both get `paid=True`  
4. Both set `req.status = "paid"` and call `_trigger_callback`

The callback could fire twice for a single payment. If the callback performs financial operations (e.g., crediting a user account), this is a double-spend bug.

**Fix:**  
Use `asyncio.Lock` per payment ID:
```python
self._locks: Dict[str, asyncio.Lock] = {}

async def check_payment(self, payment_id: str):
    lock = self._locks.setdefault(payment_id, asyncio.Lock())
    async with lock:
        # ... existing logic
```

---

### F-16: Missing Input Validation on Invoice Endpoint (Medium)

**File:** `satgateway/middleware.py` lines 124-139  
**Severity:** Medium  
**CWE:** CWE-20 (Improper Input Validation)

**Description:**  
The `/payments/invoice` endpoint:
- Doesn't validate JSON content type
- Doesn't validate `amount_sats` is an integer or within bounds
- Doesn't validate `description` length or content
- Doesn't validate `resource_url` format or length
- Will crash with a 500 error if the body is not valid JSON

**Fix:**  
Use Pydantic models for request validation:
```python
from pydantic import BaseModel, constr, conint

class InvoiceRequest(BaseModel):
    amount_sats: conint(ge=1, le=1_000_000)
    description: constr(max_length=200) = "Service access"
    resource_url: constr(max_length=500) = ""
    metadata: Optional[Dict[str, Any]] = None

@self.router.post("/invoice")
async def create_invoice(request: InvoiceRequest):
    ...
```

---

### F-17: CORS Wildcard Allows All Origins (Medium)

**File:** `main.py` lines 56-61  
**Severity:** Medium  
**CWE:** CWE-942 (Overly Permissive CORS Policy)

**Description:**  
`allow_origins=["*"]` with `allow_methods=["*"]` and `allow_headers=["*"]` means any website can make cross-origin requests to the gateway. This enables:
- CSRF attacks from any website
- Any site can create invoices on behalf of visitors
- Credential theft if cookies are forwarded

**Fix:**  
Restrict to specific trusted origins:
```python
allow_origins=["https://yourdomain.com"],
allow_methods=["GET", "POST"],
allow_headers=["Content-Type"]
```

---

### F-18: No Authentication on Any Gateway Endpoint (Medium)

**File:** `satgateway/middleware.py` lines 123-228  
**Severity:** Medium  
**CWE:** CWE-306 (Missing Authentication)

**Description:**  
Aside from the `require_payment` decorator (which is opt-in per endpoint), no gateway endpoint requires authentication:
- `POST /payments/invoice` — create invoices
- `GET /payments/verify/{id}` — check payment status
- `GET /payments/qr/{id}` — get QR codes
- `GET /payments/paywall/{id}` — get paywall pages
- `GET /payments/status` — gateway status

The `GatewayConfig.api_key` field exists but is never checked on any endpoint.

**Fix:**  
Add API key middleware or dependency:
```python
from fastapi import Header, HTTPException

async def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != gateway.config.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
```

---

### F-19: LND TLS Verification Disabled (Medium)

**File:** `satgateway/core.py` line 126  
**Severity:** Medium  
**CWE:** CWE-295 (Improper Certificate Validation)

**Description:**  
When `cert_path` is not provided, `self._ssl = False` disables TLS certificate verification for LND connections. This allows MITM attacks on the connection between SatGateway and LND, enabling:
- Invoice interception/modification
- Fake payment confirmations  
- Macaroon theft

Docker Compose does provide `LND_TLS_CERT_PATH`, but the code default is insecure.

**Fix:**  
Require TLS verification in production:
```python
if cert_path and os.path.exists(cert_path):
    self._ssl = ssl.create_default_context(cafile=cert_path)
else:
    import warnings
    warnings.warn("LND TLS verification DISABLED — not safe for production")
    self._ssl = False  # Only for development
```

---

### F-20: No Rate Limiting (Low)

**Files:** `main.py`, `satgateway/middleware.py`  
**Severity:** Low  
**CWE:** CWE-799 (Improper Control of Interaction Frequency)

**Description:**  
No rate limiting exists on any endpoint. This allows:
- Invoice flooding (memory exhaustion)
- Payment verification polling (backend probing)
- QR code generation DoS

**Fix:**  
Use `slowapi` or `fastapi-limiter`:
```python
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
```

---

### F-21: Server Log Contains Payment IDs (Low)

**File:** `server.log`  
**Severity:** Low  
**CWE:** CWE-532 (Insertion of Sensitive Information into Log File)

**Description:**  
The server log contains full payment IDs (UUIDs) in URLs. If logs are accessible to attackers, they can use these to verify payment status and potentially access paid content without paying (by using the payment ID as `X-Payment-ID` header).

**Fix:**  
- Exclude payment IDs from logs  
- Use log redaction for sensitive identifiers  
- Ensure logs are not publicly accessible

---

### F-22: Payment Verification Doesn't Check Amount Paid (Low)

**File:** `satgateway/core.py` lines 231-256  
**Severity:** Low (elevated to High when combined with F-01)  
**CWE:** CWE-838 (Inappropriate Encoding for Output Context)

**Description:**  
The `SatGateway.check_payment()` method returns `amount_sats` from the PaymentRequest, but never validates that `amount_paid` (returned by the backend) matches or exceeds `amount_sats`. The LND backend reports `amt_paid_sat` which could differ from the invoice amount (e.g., in overpayment or edge cases). The stored `req.amount_sats` is blindly trusted.

**Fix:**
```python
if result["paid"]:
    paid_amount = result.get("amount_paid", 0)
    if paid_amount < req.amount_sats:
        req.status = "underpaid"
        return {"found": True, "paid": False, "underpaid": True, 
                "expected": req.amount_sats, "paid_amount": paid_amount}
```

---

## Summary Table

| ID | Severity | Finding | File |
|----|----------|---------|------|
| F-01 | Critical | Cross-resource payment reuse | middleware.py:53-61 |
| F-02 | Critical | Stored XSS via resource_url | middleware.py:199,209 |
| F-03 | High | XSS via JSON.stringify in paywall.js | paywall.js:76-83 |
| F-04 | Medium | XSS via invoice in paywall.js | paywall.js:61-73 |
| F-05 | High | Invoice amount bypass via API | middleware.py:124-139 |
| F-06 | High | LND admin macaroon overprivilege | docker-compose*.yml |
| F-07 | High | Default API key 'dev' | main.py:30, middleware.py:242 |
| F-08 | High | Open redirect via resource_url | middleware.py:209 |
| F-09 | High | Bitcoin RPC open to all IPs | docker-compose.fullnode.yml:17-19 |
| F-10 | High | Unauthenticated invoice creation | middleware.py:124-139 |
| F-11 | Medium | In-memory storage, no eviction | core.py:202 |
| F-12 | Medium | Cookie missing SameSite/Secure | middleware.py:97 |
| F-13 | Medium | sg_preimage dead code path | middleware.py:55 |
| F-14 | Medium | Info disclosure on status endpoints | main.py:155, middleware.py:221 |
| F-15 | Medium | Race condition in payment callback | core.py:231-256 |
| F-16 | Medium | Missing input validation | middleware.py:124-139 |
| F-17 | Medium | CORS wildcard | main.py:56-61 |
| F-18 | Medium | No authentication on gateway endpoints | middleware.py:123-228 |
| F-19 | Medium | LND TLS skip-verify | core.py:126 |
| F-20 | Low | No rate limiting | global |
| F-21 | Low | Payment IDs in server log | server.log |
| F-22 | Low | Payment amount not cross-verified | core.py:231-256 |

---

## Recommended Priority Actions

1. **Immediately fix F-01 and F-05** — The payment bypass makes the entire paywall useless. Bind payments to specific resources and validate amounts.
2. **Fix F-02** — Stored XSS enables full account takeover in any browser that visits a crafted payment link.
3. **Fix F-06** — Switch from admin macaroon to invoice-only macaroon before handling real funds.
4. **Add authentication (F-18)** and rate limiting (F-20) before public deployment.
5. **Fix cookie security (F-12)** and CORS (F-17) for production.
6. **Implement persistent storage (F-11)** — in-memory dict is not production-ready.