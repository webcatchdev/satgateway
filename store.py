"""Persistent SQLite-backed payment store.

Eliminates multi-worker race conditions and data-loss on restart.
"""

import os
import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from .core import PaymentRequest


class PaymentStore:
    """Thread-safe SQLite store for payment requests.

    Works across multiple Uvicorn workers because all workers
    read/write the same SQLite file.  WAL mode gives good
    concurrency for this read-heavy workload.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.getenv("SATGATEWAY_DB_PATH", "satgateway.db")
        self._local = threading.local()
        self._init_db()

    # ------------------------------------------------------------------
    # Connection handling (one per thread)
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=10.0,
                isolation_level=None,  # autocommit for manual BEGIN/COMMIT
            )
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def _init_db(self):
        with self._conn():
            self._conn().execute("""
                CREATE TABLE IF NOT EXISTS payments (
                    id              TEXT PRIMARY KEY,
                    amount_sats     INTEGER NOT NULL,
                    description     TEXT NOT NULL,
                    resource_url    TEXT NOT NULL,
                    expires_at      TEXT NOT NULL,
                    metadata        TEXT,
                    status          TEXT NOT NULL DEFAULT 'pending',
                    paid_at         TEXT,
                    preimage        TEXT,
                    invoice         TEXT,
                    payment_hash    TEXT,
                    consumed        INTEGER NOT NULL DEFAULT 0,
                    csrf_token      TEXT,
                    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)
            self._conn().execute("""
                CREATE INDEX IF NOT EXISTS idx_payments_hash
                ON payments(payment_hash)
            """)
            self._conn().execute("""
                CREATE INDEX IF NOT EXISTS idx_payments_status
                ON payments(status)
            """)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def save(self, req: PaymentRequest, csrf_token: Optional[str] = None):
        """Insert or replace a payment record."""
        self._conn().execute(
            """
            INSERT OR REPLACE INTO payments
            (id, amount_sats, description, resource_url, expires_at,
             metadata, status, paid_at, preimage, invoice, payment_hash,
             consumed, csrf_token)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                req.id,
                req.amount_sats,
                req.description,
                req.resource_url,
                req.expires_at.isoformat(),
                json.dumps(req.metadata) if req.metadata else "{}",
                req.status,
                req.paid_at.isoformat() if req.paid_at else None,
                req.preimage,
                req.invoice,
                req.payment_hash,
                0,  # consumed is managed separately by verify_and_consume
                csrf_token,
            ),
        )

    def get(self, payment_id: str) -> Optional[PaymentRequest]:
        row = self._conn().execute(
            "SELECT * FROM payments WHERE id = ?", (payment_id,)
        ).fetchone()
        if not row:
            return None
        return self._row_to_req(row)

    def get_by_hash(self, payment_hash: str) -> Optional[PaymentRequest]:
        row = self._conn().execute(
            "SELECT * FROM payments WHERE payment_hash = ?", (payment_hash,)
        ).fetchone()
        if not row:
            return None
        return self._row_to_req(row)

    def update(self, req: PaymentRequest):
        """Update mutable fields (status, paid_at, preimage).

        Does NOT touch `consumed` — that is managed exclusively
        by verify_and_consume() to prevent accidental overwrites.
        """
        self._conn().execute(
            """
            UPDATE payments
            SET status = ?, paid_at = ?, preimage = ?
            WHERE id = ?
            """,
            (
                req.status,
                req.paid_at.isoformat() if req.paid_at else None,
                req.preimage,
                req.id,
            ),
        )

    def verify_and_consume(self, payment_id: str) -> Optional[PaymentRequest]:
        """Atomically verify a pending payment and mark consumed.

        Returns the PaymentRequest if it was pending (and now consumed),
        or None if already consumed / not found / not paid.
        """
        conn = self._conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM payments WHERE id = ? AND consumed = 0 AND status = 'paid'",
                (payment_id,),
            ).fetchone()
            if not row:
                conn.execute("ROLLBACK")
                return None
            conn.execute(
                "UPDATE payments SET consumed = 1 WHERE id = ?",
                (payment_id,),
            )
            conn.execute("COMMIT")
            return self._row_to_req(row)
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def list_pending(self) -> list:
        rows = self._conn().execute(
            "SELECT * FROM payments WHERE status = 'pending'"
        ).fetchall()
        return [self._row_to_req(r) for r in rows]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_req(row: sqlite3.Row) -> PaymentRequest:
        metadata = json.loads(row["metadata"]) if row["metadata"] else {}
        return PaymentRequest(
            id=row["id"],
            amount_sats=row["amount_sats"],
            description=row["description"],
            resource_url=row["resource_url"],
            expires_at=datetime.fromisoformat(row["expires_at"]),
            metadata=metadata,
            status=row["status"],
            paid_at=datetime.fromisoformat(row["paid_at"]) if row["paid_at"] else None,
            preimage=row["preimage"],
            invoice=row["invoice"],
            payment_hash=row["payment_hash"],
        )
