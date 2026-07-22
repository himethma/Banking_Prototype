from __future__ import annotations

import json
import os
import smtplib
import ssl
import sqlite3
import threading
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from email.message import EmailMessage


DB_PATH = Path("/data/monitor.db")
LOCK = threading.Lock()
app = FastAPI(title="Secure Bank IDS and SIEM", docs_url=None, redoc_url=None)


def notify_critical(title: str, rule: str, actor: str) -> None:
    message = EmailMessage()
    message["From"] = "siem@secure-bank.test"
    message["To"] = "security-admin@secure-bank.test"
    message["Subject"] = f"[CRITICAL] {title}"
    message.set_content(f"Rule: {rule}\nActor: {actor}\nReview the security dashboard. No sensitive data is included.")
    context = ssl.create_default_context(cafile=os.getenv("SMTP_CA_FILE", "/certs/ca.crt"))
    with smtplib.SMTP(os.getenv("SMTP_HOST", "mailpit"), int(os.getenv("SMTP_PORT", "1025")), timeout=5) as smtp:
        smtp.starttls(context=context)
        smtp.send_message(message)

RULES = {
    "auth.failure": ("medium", 5, 300, "Repeated authentication failures"),
    "waf.block": ("high", 3, 60, "Repeated WAF attack signatures"),
    "token.invalid": ("high", 3, 300, "Repeated invalid or tampered tokens"),
    "access.forbidden": ("medium", 3, 300, "Repeated forbidden resource access"),
    "transfer.completed": ("medium", 5, 60, "Unusual transfer velocity"),
    "audit.invalid": ("critical", 1, 3600, "Audit chain verification failed"),
    "backup.invalid": ("critical", 1, 3600, "Backup integrity verification failed"),
}


def connection() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY, occurred_at TEXT NOT NULL, event_type TEXT NOT NULL,
          actor TEXT NOT NULL, source_ip TEXT NOT NULL, details TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS alerts (
          id TEXT PRIMARY KEY, created_at TEXT NOT NULL, severity TEXT NOT NULL,
          rule TEXT NOT NULL, title TEXT NOT NULL, actor TEXT NOT NULL,
          evidence TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    return con


class SecurityEvent(BaseModel):
    event_type: str
    actor: str = "anonymous"
    source_ip: str = "unknown"
    details: dict = {}


@app.on_event("startup")
def startup() -> None:
    with connection() as con:
        con.execute("SELECT 1")


@app.get("/healthz")
def health() -> dict:
    return {"status": "ok", "rules": len(RULES)}


@app.post("/v1/events")
def ingest(event: SecurityEvent) -> dict:
    now = datetime.now(UTC)
    event_id = str(uuid.uuid4())
    alert_id = None
    with LOCK, connection() as con:
        con.execute(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?)",
            (
                event_id,
                now.isoformat(),
                event.event_type,
                event.actor,
                event.source_ip,
                json.dumps(event.details, sort_keys=True),
            ),
        )
        rule = RULES.get(event.event_type)
        if rule:
            severity, threshold, window, title = rule
            since = (now - timedelta(seconds=window)).isoformat()
            count = con.execute(
                """
                SELECT COUNT(*) FROM events
                WHERE event_type=? AND actor=? AND occurred_at>=?
                """,
                (event.event_type, event.actor, since),
            ).fetchone()[0]
            if count >= threshold:
                existing = con.execute(
                    """
                    SELECT id FROM alerts WHERE rule=? AND actor=? AND created_at>=?
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (event.event_type, event.actor, since),
                ).fetchone()
                if not existing:
                    alert_id = str(uuid.uuid4())
                    con.execute(
                        "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
                        (
                            alert_id,
                            now.isoformat(),
                            severity,
                            event.event_type,
                            title,
                            event.actor,
                            json.dumps({"count": count, "window_seconds": window}),
                        ),
                    )
                    if severity == "critical":
                        try:
                            notify_critical(title, event.event_type, event.actor)
                        except Exception:
                            pass
    return {"accepted": True, "event_id": event_id, "alert_id": alert_id}


@app.get("/v1/alerts")
def alerts(limit: int = 100) -> list[dict]:
    limit = max(1, min(limit, 500))
    with connection() as con:
        rows = con.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/v1/events")
def list_events(event_type: str | None = None, limit: int = 100) -> list[dict]:
    limit = max(1, min(limit, 500))
    with connection() as con:
        if event_type:
            rows = con.execute(
                "SELECT * FROM events WHERE event_type=? ORDER BY occurred_at DESC LIMIT ?",
                (event_type, limit),
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM events ORDER BY occurred_at DESC LIMIT ?", (limit,)
            ).fetchall()
    return [dict(row) for row in rows]


@app.post("/v1/alerts/{alert_id}/acknowledge")
def acknowledge(alert_id: str) -> dict:
    with connection() as con:
        updated = con.execute(
            "UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,)
        ).rowcount
    if not updated:
        raise HTTPException(404, "Alert not found")
    return {"acknowledged": True}


@app.get("/v1/summary")
def summary() -> dict:
    with connection() as con:
        rows = con.execute("SELECT severity, acknowledged FROM alerts").fetchall()
        events = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    by_severity = Counter(row["severity"] for row in rows)
    return {
        "events": events,
        "alerts": len(rows),
        "unacknowledged": sum(1 for row in rows if not row["acknowledged"]),
        "by_severity": dict(by_severity),
    }
