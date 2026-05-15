"""Core payment engine for SatGateway."""

import os
import json
import uuid
import hashlib
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional, Callable, Dict, Any
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PaymentRequest:
    id: str
    amount_sats: int
    description: str
    resource_url: str
    expires_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    paid_at: Optional[datetime] = None
    preimage: Optional[str] = None
    invoice: Optional[str] = None
    payment_hash: Optional[str] = None


@dataclass
class GatewayConfig:
    api_key: str
    api_secret: Optional[str] = None
    fee_basis_points: int = 50  # 0.5% default
    min_amount_sats: int = 1
    max_amount_sats: int = 10_000_000  # 0.1 BTC
    webhook_url: Optional[str] = None
    payment_valid_for_seconds: int = 3600  # paid payment valid for 1 hour
    max_stored_payments: int = 10_000  # cap in-memory storage
    cleanup_interval_seconds: int = 300  # run cleanup every 5 minutes
    branding: Dict[str, str] = field(default_factory=lambda: {
        "name": "SatGateway",
        "logo_url": "",
        "primary_color": "#F7931A"
    })


# ---------------------------------------------------------------------------
# Lightning backend abstraction
# ---------------------------------------------------------------------------

class LightningBackend:
    """Abstract base for Lightning node interfaces."""

    async def create_invoice(self, amount_sats: int, description: str, expiry_seconds: int = 3600) -> Dict[str, str]:
        """Return {'invoice': <bolt11>, 'payment_hash': <hash>, 'expires_at': <iso>}"""
        raise NotImplementedError

    async def check_payment(self, payment_hash: str) -> Dict[str, Any]:
        """Return {'paid': bool, 'preimage': str|None, 'amount_paid': int}"""
        raise NotImplementedError

    async def get_balance(self) -> int:
        """Return balance in sats."""
        raise NotImplementedError


class MockBackend(LightningBackend):
    """In-memory mock for development. Auto-pays after 5 seconds for demos."""

    def __init__(self):
        self._invoices: Dict[str, Dict] = {}
        self._balance = 1_000_000  # 1M sats

    async def create_invoice(self, amount_sats: int, description: str, expiry_seconds: int = 3600):
        # Generate a cryptographically valid preimage→hash pair
        preimage_bytes = os.urandom(32)
        preimage = preimage_bytes.hex()
        payment_hash = hashlib.sha256(preimage_bytes).hexdigest()
        invoice = f"lnbc{amount_sats}n1p{payment_hash[:20]}...MOCK"
        expires = datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds)
        self._invoices[payment_hash] = {
            "amount_sats": amount_sats,
            "description": description,
            "expires_at": expires,
            "paid": False,
            "preimage": preimage,
            "created_at": datetime.now(timezone.utc)
        }
        return {"invoice": invoice, "payment_hash": payment_hash, "expires_at": expires.isoformat()}

    async def check_payment(self, payment_hash: str):
        inv = self._invoices.get(payment_hash, {})
        # DEMO: auto-pay after 5 seconds
        if not inv.get("paid") and inv.get("created_at", datetime.now(timezone.utc)) < datetime.now(timezone.utc) - timedelta(seconds=5):
            inv["paid"] = True
        return {
            "paid": inv.get("paid", False),
            "preimage": inv.get("preimage"),
            "amount_paid": inv.get("amount_sats", 0) if inv.get("paid") else 0
        }

    async def get_balance(self):
        return self._balance


class LndBackend(LightningBackend):
    """Connect to an LND node via REST API. Works with Voltage, Umbrel, dockerized LND, etc."""

    _TIMEOUT = None  # set in __init__

    def __init__(self, host: str, macaroon_hex: Optional[str] = None,
                 macaroon_path: Optional[str] = None, cert_path: Optional[str] = None,
                 verify_tls: bool = True):
        self.host = host.rstrip("/")
        self.cert_path = cert_path

        if macaroon_path:
            with open(macaroon_path, "rb") as f:
                self.macaroon = f.read().hex()
        elif macaroon_hex:
            self.macaroon = macaroon_hex
        else:
            raise ValueError("Provide macaroon_hex or macaroon_path")

        self._headers = {"Grpc-Metadata-macaroon": self.macaroon}

        # Handle TLS — require cert in production; allow override via verify_tls=False for dev
        import ssl
        import aiohttp
        self._TIMEOUT = aiohttp.ClientTimeout(total=10)
        if verify_tls:
            if cert_path and os.path.exists(cert_path):
                self._ssl = ssl.create_default_context(cafile=cert_path)
            else:
                raise ValueError(
                    "LND TLS certificate is required when verify_tls=True. "
                    "Set LND_TLS_CERT_PATH or LND_VERIFY_TLS=false for development only."
                )
        else:
            self._ssl = False  # aiohttp interprets False as no verification

    async def create_invoice(self, amount_sats: int, description: str, expiry_seconds: int = 3600):
        import aiohttp
        import base64
        url = f"{self.host}/v1/invoices"
        payload = {
            "value": amount_sats,
            "memo": description,
            "expiry": expiry_seconds
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, headers=self._headers, ssl=self._ssl, timeout=self._TIMEOUT) as resp:
                    if resp.status != 200:
                        text = await resp.text()
                        raise RuntimeError(f"LND create_invoice failed: {resp.status}")
                    data = await resp.json()
                    # r_hash is base64 from LND REST
                    r_hash_b64 = data["r_hash"]
                    r_hash_hex = base64.b64decode(r_hash_b64).hex()
                    return {
                        "invoice": data["payment_request"],
                        "payment_hash": r_hash_hex,
                        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds)).isoformat()
                    }
        except RuntimeError:
            raise
        except Exception as e:
            raise RuntimeError("Invoice service unavailable") from e

    async def check_payment(self, payment_hash: str):
        import aiohttp
        import base64
        # LND REST expects base64-encoded payment hash in URL
        # HIGH FIX: Use URL-safe base64 to avoid / and + corrupting the URL path
        ph_b64 = base64.urlsafe_b64encode(bytes.fromhex(payment_hash)).decode()
        url = f"{self.host}/v1/invoice/{ph_b64}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=self._headers, ssl=self._ssl, timeout=self._TIMEOUT) as resp:
                    if resp.status == 404:
                        return {"paid": False, "preimage": None, "amount_paid": 0}
                    data = await resp.json()
                    preimage = data.get("r_preimage")
                    if isinstance(preimage, str) and not preimage.startswith("0x"):
                        try:
                            preimage = base64.b64decode(preimage).hex()
                        except Exception:
                            pass
                    # HIGH FIX: LND may return amt_paid_sat as a JSON string
                    amount_paid = data.get("amt_paid_sat", 0)
                    try:
                        amount_paid = int(amount_paid)
                    except (ValueError, TypeError):
                        amount_paid = 0
                    return {
                        "paid": data.get("settled", False),
                        "preimage": preimage,
                        "amount_paid": amount_paid
                    }
        except Exception as e:
            raise RuntimeError("Payment verification service unavailable") from e

    async def get_balance(self):
        import aiohttp
        url = f"{self.host}/v1/balance/channels"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=self._headers, ssl=self._ssl, timeout=self._TIMEOUT) as resp:
                    data = await resp.json()
                    return data.get("balance", 0)
        except Exception as e:
            raise RuntimeError("Balance service unavailable") from e


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class SatGateway:
    """
    SatGateway payment engine.

    Usage:
        gateway = SatGateway(backend=MockBackend())
        req = await gateway.create_request(amount_sats=100, description="Article access")
        print(req.invoice)  # Show QR code
        status = await gateway.check_payment(req.id)
    """

    def __init__(self, backend: LightningBackend, config: Optional[GatewayConfig] = None):
        self.backend = backend
        self.config = config or GatewayConfig(api_key="***")
        self._payments: Dict[str, PaymentRequest] = {}
        self._callbacks: Dict[str, Callable] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._cleanup_task: Optional[asyncio.Task] = None

    async def create_request(
        self,
        amount_sats: int,
        description: str,
        resource_url: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        expiry_seconds: int = 3600
    ) -> PaymentRequest:
        if not (self.config.min_amount_sats <= amount_sats <= self.config.max_amount_sats):
            raise ValueError(f"Amount must be between {self.config.min_amount_sats} and {self.config.max_amount_sats} sats")

        inv_data = await self.backend.create_invoice(amount_sats, description, expiry_seconds)

        req = PaymentRequest(
            id=str(uuid.uuid4()),
            amount_sats=amount_sats,
            description=description,
            resource_url=resource_url,
            expires_at=datetime.fromisoformat(inv_data["expires_at"].replace("Z", "+00:00")),
            metadata=metadata or {},
            invoice=inv_data["invoice"],
            payment_hash=inv_data.get("payment_hash")
        )
        self._payments[req.id] = req
        # Enforce max stored payments cap — evict oldest expired/unpaid first, then oldest overall
        self._enforce_storage_cap()
        return req

    async def check_payment(self, payment_id: str) -> Dict[str, Any]:
        req = self._payments.get(payment_id)
        if not req:
            return {"found": False, "paid": False}

        if req.status == "paid":
            # NEW-03: Check if paid payment has expired its validity window
            now = datetime.now(timezone.utc)
            valid_until = req.paid_at + timedelta(seconds=self.config.payment_valid_for_seconds) if req.paid_at else now
            if now > valid_until:
                return {"found": True, "paid": False, "expired": True, "detail": "Payment validity period expired"}
            return {"found": True, "paid": True, "amount_sats": req.amount_sats, "paid_at": req.paid_at.isoformat() if req.paid_at else None}

        lock = self._locks.setdefault(payment_id, asyncio.Lock())
        async with lock:
            # Re-check inside lock in case another coroutine already updated status
            if req.status == "paid":
                now = datetime.now(timezone.utc)
                valid_until = req.paid_at + timedelta(seconds=self.config.payment_valid_for_seconds) if req.paid_at else now
                if now > valid_until:
                    return {"found": True, "paid": False, "expired": True, "detail": "Payment validity period expired"}
                return {"found": True, "paid": True, "amount_sats": req.amount_sats, "paid_at": req.paid_at.isoformat() if req.paid_at else None}

            if req.expires_at < datetime.now(timezone.utc):
                req.status = "expired"
                return {"found": True, "paid": False, "expired": True}

            result = await self.backend.check_payment(req.payment_hash or "")

            if result["paid"]:
                # Validate amount paid meets or exceeds requested amount
                # HIGH FIX: Backend may return amount_paid as a string
                amount_paid = result.get("amount_paid", 0)
                try:
                    amount_paid = int(amount_paid)
                except (ValueError, TypeError):
                    amount_paid = 0
                if amount_paid < req.amount_sats:
                    return {
                        "found": True,
                        "paid": False,
                        "underpaid": True,
                        "expected": req.amount_sats,
                        "paid_amount": amount_paid,
                        "expires_at": req.expires_at.isoformat()
                    }

                # NEW-04: Cryptographically verify preimage against payment hash
                preimage = result.get("preimage")
                if preimage and req.payment_hash:
                    try:
                        expected_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
                        if expected_hash != req.payment_hash:
                            return {
                                "found": True,
                                "paid": False,
                                "detail": "Preimage verification failed — possible fraud"
                            }
                    except ValueError:
                        return {
                            "found": True,
                            "paid": False,
                            "detail": "Invalid preimage format"
                        }

                req.status = "paid"
                req.paid_at = datetime.now(timezone.utc)
                req.preimage = preimage
                self._trigger_callback(req)

            return {
                "found": True,
                "paid": result["paid"] and req.status == "paid",
                "amount_sats": req.amount_sats,
                "expires_at": req.expires_at.isoformat()
            }

    def cleanup_expired(self) -> int:
        """Remove expired payments (unpaid) and paid payments whose validity window expired. Returns count removed."""
        now = datetime.now(timezone.utc)
        expired_ids = []
        for pid, p in self._payments.items():
            if p.status != "paid" and p.expires_at < now:
                expired_ids.append(pid)
            elif p.status == "paid" and p.paid_at:
                valid_until = p.paid_at + timedelta(seconds=self.config.payment_valid_for_seconds)
                if now > valid_until:
                    expired_ids.append(pid)
        for pid in expired_ids:
            self._payments.pop(pid, None)
            self._locks.pop(pid, None)
        return len(expired_ids)

    def _enforce_storage_cap(self) -> int:
        """If payment store exceeds cap, evict oldest items. Returns count removed."""
        cap = self.config.max_stored_payments
        if len(self._payments) <= cap:
            return 0
        # Sort by creation/expiry time; evict oldest first
        sorted_items = sorted(
            self._payments.items(),
            key=lambda item: item[1].expires_at
        )
        to_evict = len(sorted_items) - cap
        removed = 0
        for pid, _ in sorted_items[:to_evict]:
            self._payments.pop(pid, None)
            self._locks.pop(pid, None)
            removed += 1
        return removed

    async def _cleanup_loop(self):
        """Background task that periodically cleans up expired payments."""
        while True:
            try:
                await asyncio.sleep(self.config.cleanup_interval_seconds)
                self.cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    def start_cleanup_task(self):
        """Start the background cleanup task (call once at startup)."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    def stop_cleanup_task(self):
        """Stop the background cleanup task (call on shutdown)."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()

    def on_payment(self, payment_id: str, callback: Callable):
        """Register a callback for when a payment is confirmed."""
        self._callbacks[payment_id] = callback

    def _trigger_callback(self, req: PaymentRequest):
        cb = self._callbacks.pop(req.id, None)
        if cb:
            try:
                cb(req)
            except Exception:
                pass

    def get_payment(self, payment_id: str) -> Optional[PaymentRequest]:
        return self._payments.get(payment_id)

    async def get_balance(self) -> int:
        return await self.backend.get_balance()
