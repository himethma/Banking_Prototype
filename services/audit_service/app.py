from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


DB_PATH = Path("/data/audit.db")
KEY_SERVICE_URL = os.environ["KEY_SERVICE_URL"]
CERT = (os.environ["CLIENT_CERT_FILE"], os.environ["CLIENT_KEY_FILE"])
VERIFY = os.environ["CA_FILE"]
LOCK = threading.Lock()
app = FastAPI(title="Immutable Audit Service", docs_url=None, redoc_url=None)


def connection() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.executescript(
        """
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS audit_entries (
          sequence INTEGER PRIMARY KEY AUTOINCREMENT,
          id TEXT NOT NULL UNIQUE,
          occurred_at TEXT NOT NULL,
          actor TEXT NOT NULL,
          action TEXT NOT NULL,
          outcome TEXT NOT NULL,
          details TEXT NOT NULL,
          previous_hash TEXT NOT NULL,
          entry_hash TEXT NOT NULL UNIQUE,
          signature TEXT NOT NULL,
          key_version TEXT NOT NULL
        );
        CREATE TRIGGER IF NOT EXISTS audit_no_update
        BEFORE UPDATE ON audit_entries BEGIN SELECT RAISE(ABORT, 'append-only audit log'); END;
        CREATE TRIGGER IF NOT EXISTS audit_no_delete
        BEFORE DELETE ON audit_entries BEGIN SELECT RAISE(ABORT, 'append-only audit log'); END;
        """
    )
    return con


class AuditEvent(BaseModel):
    actor: str
    action: str
    outcome: str
    details: dict = {}


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def kms_post(path: str, payload: dict) -> dict:
    with httpx.Client(cert=CERT, verify=VERIFY, timeout=5) as client:
        response = client.post(KEY_SERVICE_URL + path, json=payload)
        response.raise_for_status()
        return response.json()


@app.on_event("startup")
def startup() -> None:
    with connection() as con:
        con.execute("SELECT 1")


@app.get("/healthz")
def health() -> dict:
    return {"status": "ok", "storage": "append-only"}


@app.post("/v1/events")
def append_event(event: AuditEvent) -> dict:
    with LOCK, connection() as con:
        previous = con.execute(
            "SELECT entry_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["entry_hash"] if previous else "0" * 64
        body = {
            "id": str(uuid.uuid4()),
            "occurred_at": datetime.now(UTC).isoformat(),
            "actor": event.actor,
            "action": event.action,
            "outcome": event.outcome,
            "details": event.details,
            "previous_hash": previous_hash,
        }
        body_bytes = canonical(body)
        entry_hash = hashlib.sha256(body_bytes).hexdigest()
        signed = kms_post(
            "/v1/sign", {"data": base64.urlsafe_b64encode(body_bytes).decode()}
        )
        cursor = con.execute(
            """
            INSERT INTO audit_entries
              (id, occurred_at, actor, action, outcome, details, previous_hash,
               entry_hash, signature, key_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                body["id"],
                body["occurred_at"],
                body["actor"],
                body["action"],
                body["outcome"],
                json.dumps(body["details"], sort_keys=True),
                previous_hash,
                entry_hash,
                signed["signature"],
                signed["key_version"],
            ),
        )
        return {"sequence": cursor.lastrowid, "entry_hash": entry_hash, **signed}


@app.get("/v1/events")
def list_events(limit: int = 100) -> list[dict]:
    limit = max(1, min(limit, 500))
    with connection() as con:
        rows = con.execute(
            "SELECT * FROM audit_entries ORDER BY sequence DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/v1/verify")
def verify_chain() -> dict:
    with connection() as con:
        rows = con.execute("SELECT * FROM audit_entries ORDER BY sequence").fetchall()
    previous_hash = "0" * 64
    for row in rows:
        body = {
            "id": row["id"],
            "occurred_at": row["occurred_at"],
            "actor": row["actor"],
            "action": row["action"],
            "outcome": row["outcome"],
            "details": json.loads(row["details"]),
            "previous_hash": row["previous_hash"],
        }
        body_bytes = canonical(body)
        digest = hashlib.sha256(body_bytes).hexdigest()
        signature_valid = kms_post(
            "/v1/verify",
            {
                "data": base64.urlsafe_b64encode(body_bytes).decode(),
                "signature": row["signature"],
                "key_version": row["key_version"],
            },
        )["valid"]
        if row["previous_hash"] != previous_hash or digest != row["entry_hash"] or not signature_valid:
            return {
                "valid": False,
                "entries": len(rows),
                "failed_sequence": row["sequence"],
            }
        previous_hash = row["entry_hash"]
    return {"valid": True, "entries": len(rows), "head": previous_hash}
