"""Deliberately vulnerable, synthetic-only comparison application.

This service is never connected to banking networks, volumes, identities, or secrets.
Its insecure patterns exist solely so the attack runner can compare outcomes.
"""
from __future__ import annotations

import sqlite3
import time

import jwt
from fastapi import FastAPI, Header, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel


app = FastAPI(title="Intentionally Vulnerable Banking Lab")
db = sqlite3.connect(":memory:", check_same_thread=False)
db.executescript(
    """
    CREATE TABLE accounts (id INTEGER PRIMARY KEY, owner TEXT, account_number TEXT, balance INTEGER);
    INSERT INTO accounts VALUES (1, 'alice', '100000000001', 50000000);
    INSERT INTO accounts VALUES (2, 'bob', '100000000002', 35000000);
    CREATE TABLE comments (body TEXT);
    CREATE TABLE transfers (id TEXT PRIMARY KEY, amount INTEGER);
    """
)


class Comment(BaseModel):
    body: str


class Transfer(BaseModel):
    transfer_id: str
    amount: int


@app.get("/healthz")
def health():
    return {"status": "intentionally-vulnerable", "synthetic_data": True}


@app.get("/lab/sqli")
def sqli(search: str):
    query = f"SELECT id, owner, account_number, balance FROM accounts WHERE owner = '{search}'"
    rows = db.execute(query).fetchall()
    return {"query": query, "accounts": rows}


@app.post("/lab/xss")
def store_xss(comment: Comment):
    db.execute("INSERT INTO comments VALUES (?)", (comment.body,))
    db.commit()
    return {"stored_without_encoding": True}


@app.get("/lab/xss", response_class=HTMLResponse)
def show_xss():
    comments = "".join(f"<li>{row[0]}</li>" for row in db.execute("SELECT body FROM comments"))
    return f"<html><body><ul>{comments}</ul></body></html>"


@app.get("/lab/idor/{account_id}")
def idor(account_id: int, x_user: str = Header(default="alice")):
    row = db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
    return {"requested_by": x_user, "account": row, "ownership_checked": False}


@app.post("/lab/transfer")
def replayable_transfer(transfer: Transfer, request: Request):
    db.execute("INSERT OR REPLACE INTO transfers VALUES (?, ?)", (transfer.transfer_id, transfer.amount))
    db.commit()
    return {
        "completed": True,
        "csrf_checked": False,
        "idempotency_enforced": False,
        "origin": request.headers.get("origin"),
    }


@app.get("/lab/weak-token")
def weak_token():
    token = jwt.encode({"sub": "alice", "role": "admin", "iat": int(time.time())}, "password", algorithm="HS256")
    return {"token": token, "weak_shared_secret": True, "expiry_required": False}


@app.post("/lab/login")
def login():
    return {"accepted": True, "rate_limited": False, "locked": False}

