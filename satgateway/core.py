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
        payment_hash = hashlib.sha256(os.urandom(32)).hexdigest()
        invoice = f"lnbc{amount_sats}n1p{payment_hash[:20]}...MOCK"
        expires = datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds)
        self._invoices[payment_hash] = {
            "amount_sats": amount_sats,
            "description": description,
            "expires_at": expires,
            "paid": False,
            "preimage": None,
            "created_at": datetime.now(timezone.utc)
        }
        return {"invoice": invoice, "payment_hash": payment_hash, "expires_at": expires.isoformat()}

    async def check_payment(self, payment_hash: str):
        inv = self._invoices.get(payment_hash, {})
        # DEMO: auto-pay after 5 seconds
        if not inv.get("paid") and inv.get("created_at", datetime.now(timezone.utc)) < datetime.now(timezone.utc) - timedelta(seconds=5):
            inv["paid"] = True
            inv["preimage"] = hashlib.sha256(os.urandom(32)).hexdigest()
        return {
            "paid": inv.get("paid", False),
            "preimage": inv.get("preimage"),
            "amount_paid": inv.get("amount_sats", 0) if inv.get("paid") else 0
        }

    async def get_balance(self):
        return self._balance


class LndBackend(LightningBackend):
    """Connect to an LND node via REST API. Works with Voltage, Umbrel, dockerized LND, etc."""

    def __init__(self, host: str, macaroon_hex: Optional[str] = None,
                 macaroon_path: Optional[str] = None, cert_path: Optional[str] = None):
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

        # Handle TLS — require explicit opt-out for verification skip
        import ssl
        if cert_path and os.path.exists(cert_path):
            self._ssl = ssl.create_default_context(cafile=cert_path)
        elif os.getenv("LND_TLS_SKIP_VERIFY") == "1":
            self._ssl = False  # aiohttp interprets False as no verification
        else:
            raise ValueError(
                "LND TLS certificate is required. Set LND_TLS_CERT_PATH to the "
                "TLS certificate file, or set LND_TLS_SKIP_VERIFY=1 to disable "
                "verification (NOT recommended for production)."
            )

    async def create_invoice(self, amount_sats: int, description: str, expiry_seconds: int = 3600):
        import aiohttp
        import base64
        url = f"{self.host}/v1/invoices"
        payload = {
            "value": amount_sats,
            "memo": description,
            "expiry": expiry_seconds
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=self._headers, ssl=self._ssl) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(f"LND create_invoice failed: {resp.status} {text}")
                data = await resp.json()
                # r_hash is base64 from LND REST
                r_hash_b64 = data["r_hash"]
                r_hash_hex = base64.b64decode(r_hash_b64).hex()
                return {
                    "invoice": data["payment_request"],
                    "payment_hash": r_hash_hex,
                    "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds)).isoformat()
                }

    async def check_payment(self, payment_hash: str):
        import aiohttp
        import base64
        # LND REST expects base64-encoded payment hash in URL
        ph_b64 = base64.urlsafe_b64encode(bytes.fromhex(payment_hash)).decode()
        url = f"{self.host}/v1/invoice/{ph_b64}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self._headers, ssl=self._ssl) as resp:
                if resp.status == 404:
                    return {"paid": False, "preimage": None, "amount_paid": 0}
                data = await resp.json()
                preimage = data.get("r_preimage")
                if isinstance(preimage, str) and not preimage.startswith("0x"):
                    try:
                        preimage = base64.b64decode(preimage).hex()
                    except Exception:
                        pass
                return {
                    "paid": data.get("settled", False),
                    "preimage": preimage,
                    "amount_paid": data.get("amt_paid_sat", 0)
                }

    async def get_balance(self):
        import aiohttp
        url = f"{self.host}/v1/balance/channels"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self._headers, ssl=self._ssl) as resp:
                data = await resp.json()
                return data.get("balance", 0)


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

    def __init__(self, backend: LightningBackend, config: Optional[GatewayConfig] = None, store=None):
        self.backend = backend
        self.config = config or GatewayConfig(api_key="***")
        from .store import PaymentStore
        self._store: PaymentStore = store or PaymentStore()
        self._callbacks: Dict[str, Callable] = {}

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
        self._store.save(req)
        return req

    async def check_payment(self, payment_id: str) -> Dict[str, Any]:
        req = self._store.get(payment_id)
        if not req:
            return {"found": False, "paid": False}

        if req.status == "paid":
            return {"found": True, "paid": True, "amount_sats": req.amount_sats, "paid_at": req.paid_at.isoformat() if req.paid_at else None}

        if req.expires_at < datetime.now(timezone.utc):
            req.status = "expired"
            self._store.update(req)
            return {"found": True, "paid": False, "expired": True}

        result = await self.backend.check_payment(req.payment_hash or "")

        if result["paid"]:
            req.status = "paid"
            req.paid_at = datetime.now(timezone.utc)
            req.preimage = result.get("preimage")
            self._store.update(req)
            self._trigger_callback(req)

        return {
            "found": True,
            "paid": result["paid"],
            "amount_sats": req.amount_sats,
            "expires_at": req.expires_at.isoformat()
        }

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
        return self._store.get(payment_id)

    def verify_and_consume(self, payment_id: str) -> Optional[PaymentRequest]:
        """Atomically verify a paid payment and mark it consumed.

        Returns the PaymentRequest if it was pending-paid (and now consumed),
        or None if already consumed / not found / not paid.
        """
        return self._store.verify_and_consume(payment_id)

    async def get_balance(self) -> int:
        return await self.backend.get_balance()
