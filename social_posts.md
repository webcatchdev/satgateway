# SatGateway — Social Media Posts

---

## 1. Hacker News "Show HN" Post

**Title:** Show HN: SatGateway — Self-hosted Lightning payment gateway with one decorator

**Body:**

APIs need monetization, but Stripe is expensive, complex, and terrible for micro-payments. You need a company, a bank account, and a compliance team just to charge a few sats per request.

SatGateway is a self-hosted, non-custodial Bitcoin Lightning payment gateway. You add one decorator to your API endpoints:

```python
@require_payment(amount_sats=100)
def my_endpoint():
    return "Premium content unlocked"
```

That's it. No KYC, no middlemen, no custody. You run it on a $5 VPS, connect your own Lightning node, and start accepting sats directly.

- Lightning-native
- Self-hosted & non-custodial
- One-decorator integration
- Runs anywhere (even a cheap VPS)

Demo: https://webcatch.dev/payments/

Node pubkey: 0301e382e103585adc5b3bd302e73be4e2f9ca44efe00a8f4c1aef075899ea160e

GitHub repo coming soon. Would love feedback from anyone building paid APIs or micro-SaaS tools.

---

## 2. Nostr Post

SatGateway: one Python decorator to monetize any API with Lightning. Self-hosted, non-custodial, no Stripe required. Run it on a $5 VPS and stack sats directly.

Demo: https://webcatch.dev/payments/

#Bitcoin #Lightning #nostr #buildinpublic

---

## 3. X/Twitter Thread

**Tweet 1 (Hook):**
What if you could monetize any API with a single line of code?

No Stripe. No KYC. No middlemen.

Just sats, straight to your node.

🧵👇

[VIDEO/GIF PLACEHOLDER]

---

**Tweet 2:**
SatGateway adds one decorator to your endpoints:

```python
@require_payment(amount_sats=100)
def my_api():
    return "Paid content"
```

That's the entire integration.

Lightning invoice → payment verified → request proceeds.

All programmatic. All instant.

---

**Tweet 3:**
It's self-hosted and non-custodial.

You run it on a $5 VPS, plug in your own Lightning node, and keep every sat.

No platform risk. No account bans. No waiting 7 days for payouts.

Demo: https://webcatch.dev/payments/

---

**Tweet 4 (CTA):**
If you're building paid APIs, paywalled content, or premium features — DM or reply.

GitHub repo dropping soon.

Node: 0301e382e103585adc5b3bd302e73be4e2f9ca44efe00a8f4c1aef075899ea160e

Let's make the internet payable by the request ⚡

---

## 4. r/lightningnetwork Reddit Post

**Title:** SatGateway — Self-hosted Lightning payment gateway for APIs (one decorator, $5 VPS)

**Body:**

Hey r/lightningnetwork — wanted to share a project I've been building for anyone who wants to monetize APIs or web content directly over Lightning.

**What it is**
SatGateway is a self-hosted, non-custodial payment gateway. You add a single decorator to any API endpoint, and it requires a Lightning payment before serving the request.

**How it works**
```python
@require_payment(amount_sats=100)
def my_endpoint():
    return "Premium content unlocked"
```
The gateway generates an invoice, verifies payment on your node, and lets the request through. That's the whole integration.

**Use cases**
- Paywalled APIs (per-request pricing for micro-SaaS)
- Premium content or features in web apps
- Metered access to compute, data, or tools
- Anything where Stripe is overkill and you want instant, global, permissionless payments

**Why not just use Stripe / PayPal?**
- They require a business entity, bank account, and KYC
- High fees make micro-payments impossible
- Payout delays, chargebacks, and account bans
- Custodial — they hold your funds

SatGateway is the opposite: self-hosted, non-custodial, Lightning-native. You run it on a $5 VPS, connect your own node, and stack sats directly.

**Demo & node**
- Demo: https://webcatch.dev/payments/
- Node pubkey: 0301e382e103585adc5b3bd302e73be4e2f9ca44efe00a8f4c1aef075899ea160e

GitHub repo is coming soon — happy to answer questions or take feedback. Anyone here building Lightning-native tools for devs?

---
