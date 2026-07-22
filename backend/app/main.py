from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.exceptions import HTTPException as StarletteHTTPException

from .clients import (
    audit,
    canonical_json,
    decrypt_text,
    encrypt_text,
    internal_get,
    internal_post,
    security_event,
    send_notification,
    sign_bytes,
    verify_bytes,
)
from .config import get_settings
from .database import SessionLocal, engine, session_dependency
from .models import (
    Account,
    Base,
    IdempotencyRecord,
    Transaction,
    TransferPreparation,
    UserProfile,
)
from .schemas import TransferCommitRequest, TransferPrepareRequest
from .security import Customer, Principal, SecurityAdmin, current_principal


settings = get_settings()
app = FastAPI(
    title="Secure Bank API",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.public_origin],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Idempotency-Key"],
)


def problem(status: int, title: str, detail: str, request: Request, errors=None) -> JSONResponse:
    body = {
        "type": "about:blank",
        "title": title,
        "status": status,
        "detail": detail,
        "instance": request.url.path,
    }
    if errors:
        body["errors"] = errors
    return JSONResponse(body, status_code=status, media_type="application/problem+json")


@app.exception_handler(StarletteHTTPException)
async def http_exception(request: Request, exc: StarletteHTTPException):
    title = {
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        409: "Conflict",
        422: "Unprocessable Content",
        429: "Too Many Requests",
    }.get(exc.status_code, "Request Failed")
    return problem(exc.status_code, title, str(exc.detail), request)


@app.exception_handler(RequestValidationError)
async def validation_exception(request: Request, exc: RequestValidationError):
    errors = [
        {"field": ".".join(str(item) for item in error["loc"][1:]), "message": error["msg"]}
        for error in exc.errors()
    ]
    return problem(422, "Validation Failed", "The request contains invalid fields.", request, errors)


@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception):
    await security_event("application.error", details={"path": request.url.path})
    return problem(500, "Internal Server Error", "The request could not be completed.", request)


async def seed_data() -> None:
    seed = json.loads(open("/bootstrap/seed.json", encoding="utf-8").read())
    async with SessionLocal() as session:
        await session.execute(text("SELECT pg_advisory_lock(8127391)"))
        try:
            existing = await session.scalar(select(func.count()).select_from(UserProfile))
            if existing:
                return
            customers = [user for user in seed["users"] if user["username"] in {"alice", "bob"}]
            for user in seed["users"]:
                encrypted = await encrypt_text(
                    json.dumps({"full_name": user["full_name"]}),
                    f"user:{user['subject']}",
                )
                session.add(
                    UserProfile(
                        subject=user["subject"],
                        username=user["username"],
                        encrypted_pii=encrypted,
                    )
                )
            await session.flush()
            session.add_all(
                [
                    Account(
                        owner_subject=customers[0]["subject"],
                        account_number="100000000001",
                        balance_minor=50_000_000,
                    ),
                    Account(
                        owner_subject=customers[1]["subject"],
                        account_number="100000000002",
                        balance_minor=35_000_000,
                    ),
                ]
            )
            await session.commit()
        finally:
            await session.execute(text("SELECT pg_advisory_unlock(8127391)"))


@app.on_event("startup")
async def startup() -> None:
    async with engine.begin() as connection:
        await connection.execute(text("SELECT pg_advisory_lock(8127390)"))
        try:
            await connection.run_sync(Base.metadata.create_all)
        finally:
            await connection.execute(text("SELECT pg_advisory_unlock(8127390)"))
    await seed_data()


@app.get("/healthz")
async def health() -> dict:
    return {"status": "ok", "instance": settings.instance_name}


def mask_account(number: str) -> str:
    return "*" * max(0, len(number) - 4) + number[-4:]


@app.get("/api/v1/me")
async def me(
    principal: Annotated[Principal, Depends(current_principal)],
    session: Annotated[AsyncSession, Depends(session_dependency)],
) -> dict:
    profile = await session.get(UserProfile, principal.subject)
    if not profile:
        raise HTTPException(404, "User profile not found")
    pii = json.loads(await decrypt_text(profile.encrypted_pii, f"user:{profile.subject}"))
    return {
        "subject": principal.subject,
        "username": principal.username,
        "email": principal.email,
        "full_name": pii["full_name"],
        "roles": sorted(principal.roles & {"customer", "security-admin"}),
    }


@app.get("/api/v1/accounts")
async def accounts(
    customer: Customer,
    session: Annotated[AsyncSession, Depends(session_dependency)],
) -> list[dict]:
    rows = (
        await session.scalars(
            select(Account).where(Account.owner_subject == customer.subject).order_by(Account.created_at)
        )
    ).all()
    return [
        {
            "id": str(row.id),
            "account_number": row.account_number,
            "masked_account_number": mask_account(row.account_number),
            "currency": row.currency,
            "balance_minor": row.balance_minor,
            "active": row.active,
        }
        for row in rows
    ]


@app.get("/api/v1/accounts/{account_id}/transactions")
async def transactions(
    account_id: uuid.UUID,
    customer: Customer,
    session: Annotated[AsyncSession, Depends(session_dependency)],
) -> list[dict]:
    account = await session.get(Account, account_id)
    if not account or account.owner_subject != customer.subject:
        await security_event("access.forbidden", actor=customer.subject, details={"resource": "account"})
        raise HTTPException(404, "Account not found")
    rows = (
        await session.scalars(
            select(Transaction)
            .where(
                or_(
                    Transaction.source_account_id == account.id,
                    Transaction.destination_account_id == account.id,
                )
            )
            .order_by(Transaction.created_at.desc())
            .limit(100)
        )
    ).all()
    result = []
    for row in rows:
        incoming = row.destination_account_id == account.id
        result.append(
            {
                "id": str(row.id),
                "direction": "credit" if incoming else "debit",
                "amount_minor": row.amount_minor,
                "currency": row.currency,
                "created_at": row.created_at,
                "description": await decrypt_text(
                    row.encrypted_description, f"transaction:{row.id}"
                ),
            }
        )
    return result


def transfer_payload(request: TransferPrepareRequest) -> dict:
    return {
        "source_account_id": str(request.source_account_id),
        "destination_account_number": request.destination_account_number,
        "amount_minor": request.amount_minor,
        "currency": request.currency,
        "description": request.description,
    }


@app.post("/api/v1/transfers/prepare", status_code=201)
async def prepare_transfer(
    request: TransferPrepareRequest,
    customer: Customer,
    session: Annotated[AsyncSession, Depends(session_dependency)],
) -> dict:
    source = await session.get(Account, request.source_account_id)
    if not source or source.owner_subject != customer.subject or not source.active:
        await security_event("access.forbidden", actor=customer.subject, details={"resource": "source-account"})
        raise HTTPException(404, "Source account not found")
    destination = await session.scalar(
        select(Account).where(Account.account_number == request.destination_account_number)
    )
    if not destination or not destination.active:
        raise HTTPException(404, "Destination account not found")
    if destination.id == source.id:
        raise HTTPException(400, "Source and destination accounts must differ")
    if request.amount_minor > settings.transfer_limit_minor:
        raise HTTPException(422, "Per-transfer limit exceeded")
    if source.balance_minor < request.amount_minor:
        raise HTTPException(422, "Insufficient funds")
    start = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    sent_today = await session.scalar(
        select(func.coalesce(func.sum(Transaction.amount_minor), 0)).where(
            Transaction.source_account_id == source.id,
            Transaction.created_at >= start,
        )
    )
    if sent_today + request.amount_minor > settings.daily_limit_minor:
        raise HTTPException(422, "Daily transfer limit exceeded")
    payload = transfer_payload(request)
    digest = hashlib.sha256(canonical_json(payload)).hexdigest()
    preparation = TransferPreparation(
        owner_subject=customer.subject,
        payload=payload,
        request_hash=digest,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    session.add(preparation)
    await session.commit()
    await audit(
        customer.subject,
        "transfer.prepare",
        "success",
        {"preparation_id": str(preparation.id), "request_hash": digest},
    )
    return {
        "preparation_id": str(preparation.id),
        "request_hash": digest,
        "expires_at": preparation.expires_at,
        "requires_recent_mfa": True,
    }


@app.post("/api/v1/transfers/commit", status_code=201)
async def commit_transfer(
    request: TransferCommitRequest,
    customer: Customer,
    session: Annotated[AsyncSession, Depends(session_dependency)],
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=16, max_length=128)],
) -> dict:
    if int(time.time()) - customer.auth_time > 120:
        raise HTTPException(401, "Recent MFA authentication is required")
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
        {"lock_key": customer.subject + ":" + idempotency_key},
    )
    preparation = await session.scalar(
        select(TransferPreparation)
        .where(TransferPreparation.id == request.preparation_id)
        .with_for_update()
    )
    if not preparation or preparation.owner_subject != customer.subject:
        raise HTTPException(404, "Transfer preparation not found")
    existing = await session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.owner_subject == customer.subject,
            IdempotencyRecord.key == idempotency_key,
        )
    )
    if existing:
        if existing.request_hash != preparation.request_hash:
            raise HTTPException(409, "Idempotency key was used for a different request")
        if existing.response:
            return existing.response
    if preparation.used:
        raise HTTPException(409, "Transfer preparation has already been used")
    if preparation.expires_at < datetime.now(UTC):
        raise HTTPException(409, "Transfer preparation has expired")

    payload = preparation.payload
    source_id = uuid.UUID(payload["source_account_id"])
    destination = await session.scalar(
        select(Account).where(Account.account_number == payload["destination_account_number"])
    )
    if not destination:
        raise HTTPException(404, "Destination account not found")
    locked = (
        await session.scalars(
            select(Account)
            .where(Account.id.in_([source_id, destination.id]))
            .order_by(Account.id)
            .with_for_update()
        )
    ).all()
    by_id = {account.id: account for account in locked}
    source = by_id.get(source_id)
    destination = by_id.get(destination.id)
    if not source or source.owner_subject != customer.subject or not destination:
        raise HTTPException(409, "Account state changed")
    amount = int(payload["amount_minor"])
    if source.balance_minor < amount:
        raise HTTPException(422, "Insufficient funds")

    transaction_id = uuid.uuid4()
    encrypted_description = await encrypt_text(
        payload["description"], f"transaction:{transaction_id}"
    )
    receipt_body = {
        "transaction_id": str(transaction_id),
        "source_account": mask_account(source.account_number),
        "destination_account": mask_account(destination.account_number),
        "amount_minor": amount,
        "currency": payload["currency"],
        "completed_at": datetime.now(UTC).isoformat(),
        "request_hash": preparation.request_hash,
    }
    signature = await sign_bytes(canonical_json(receipt_body))
    receipt = {**receipt_body, **signature}
    transaction = Transaction(
        id=transaction_id,
        source_account_id=source.id,
        destination_account_id=destination.id,
        amount_minor=amount,
        currency=payload["currency"],
        encrypted_description=encrypted_description,
        request_hash=preparation.request_hash,
        receipt=receipt,
    )
    source.balance_minor -= amount
    destination.balance_minor += amount
    preparation.used = True
    response = {"status": "completed", "receipt": receipt}
    session.add(transaction)
    session.add(
        IdempotencyRecord(
            owner_subject=customer.subject,
            key=idempotency_key,
            request_hash=preparation.request_hash,
            response=response,
        )
    )
    await session.commit()
    audit_result = await audit(
        customer.subject,
        "transfer.commit",
        "success",
        {
            "transaction_id": str(transaction_id),
            "amount_minor": amount,
            "request_hash": preparation.request_hash,
        },
    )
    response["audit_hash"] = audit_result["entry_hash"]
    await security_event(
        "transfer.completed",
        actor=customer.subject,
        details={"transaction_id": str(transaction_id), "amount_minor": amount},
    )
    try:
        await send_notification(
            customer.email,
            "Secure Bank transfer completed",
            f"Your transfer reference {transaction_id} was completed. No sensitive details are included in this email.",
        )
    except Exception:
        await security_event("mail.failure", actor=customer.subject)
    return response


@app.get("/api/v1/transfers/{transaction_id}/receipt")
async def get_receipt(
    transaction_id: uuid.UUID,
    customer: Customer,
    session: Annotated[AsyncSession, Depends(session_dependency)],
) -> dict:
    transaction = await session.get(Transaction, transaction_id)
    if not transaction:
        raise HTTPException(404, "Transaction not found")
    source = await session.get(Account, transaction.source_account_id)
    destination = await session.get(Account, transaction.destination_account_id)
    if customer.subject not in {source.owner_subject, destination.owner_subject}:
        raise HTTPException(404, "Transaction not found")
    return transaction.receipt


@app.post("/api/v1/receipts/verify")
async def verify_receipt(receipt: dict, principal: Annotated[Principal, Depends(current_principal)]) -> dict:
    signature = receipt.get("signature")
    body = {
        key: value
        for key, value in receipt.items()
        if key not in {"signature", "algorithm", "key_version", "digest"}
    }
    if not signature:
        return {"valid": False, "reason": "Missing signature"}
    return {
        "valid": await verify_bytes(
            canonical_json(body), signature, receipt.get("key_version")
        )
    }


@app.post("/api/v1/statements/export")
async def export_statement(
    account_id: uuid.UUID,
    customer: Customer,
    session: Annotated[AsyncSession, Depends(session_dependency)],
) -> dict:
    account = await session.get(Account, account_id)
    if not account or account.owner_subject != customer.subject:
        raise HTTPException(404, "Account not found")
    rows = (
        await session.scalars(
            select(Transaction)
            .where(
                or_(
                    Transaction.source_account_id == account.id,
                    Transaction.destination_account_id == account.id,
                )
            )
            .order_by(Transaction.created_at)
        )
    ).all()
    csv_lines = ["transaction_id,date,direction,amount_minor,currency"]
    for row in rows:
        direction = "credit" if row.destination_account_id == account.id else "debit"
        csv_lines.append(
            f"{row.id},{row.created_at.isoformat()},{direction},{row.amount_minor},{row.currency}"
        )
    envelope = await encrypt_text("\n".join(csv_lines), f"statement:{account.id}")
    await audit(customer.subject, "statement.export", "success", {"account_id": str(account.id)})
    return {
        "filename": f"statement-{mask_account(account.account_number)}.csv.aesgcm.json",
        "transport": "HTTPS download; backup copy uses SFTP",
        "envelope": envelope,
    }


@app.get("/api/v1/admin/alerts")
async def admin_alerts(admin: SecurityAdmin) -> list:
    return await internal_get(settings.monitor_service_url, "/v1/alerts")


@app.post("/api/v1/admin/alerts/{alert_id}/acknowledge")
async def admin_acknowledge(alert_id: str, admin: SecurityAdmin) -> dict:
    result = await internal_post(
        settings.monitor_service_url, f"/v1/alerts/{alert_id}/acknowledge", {}
    )
    await audit(admin.subject, "alert.acknowledge", "success", {"alert_id": alert_id})
    return result


@app.get("/api/v1/admin/security-summary")
async def security_summary(admin: SecurityAdmin) -> dict:
    monitor = await internal_get(settings.monitor_service_url, "/v1/summary")
    audit_status = await internal_get(settings.audit_service_url, "/v1/verify")
    return {"monitor": monitor, "audit": audit_status}


@app.get("/api/v1/admin/backups")
async def admin_backups(admin: SecurityAdmin) -> list:
    return await internal_get(
        settings.monitor_service_url, "/v1/events?event_type=backup.created&limit=100"
    )


@app.get("/api/v1/admin/audit")
async def admin_audit(admin: SecurityAdmin) -> list:
    return await internal_get(settings.audit_service_url, "/v1/events?limit=100")


@app.get("/api/v1/admin/audit/verify")
async def admin_verify_audit(admin: SecurityAdmin) -> dict:
    result = await internal_get(settings.audit_service_url, "/v1/verify")
    if not result.get("valid"):
        await security_event("audit.invalid", actor=admin.subject, details=result)
    return result


@app.get("/api/v1/admin/controls")
async def controls(admin: SecurityAdmin) -> dict:
    return {
        "algorithm": [
            "AES-256-GCM field and backup encryption",
            "Argon2id passwords",
            "ECDSA P-384 token, audit, receipt and manifest signatures",
            "SHA-256 audit hash chain",
        ],
        "protocol": [
            "TLS 1.3 public endpoint",
            "mTLS service communication",
            "PostgreSQL TLS",
            "SMTP STARTTLS",
            "SFTP with Ed25519 keys",
        ],
        "system": [
            "OWASP CRS WAF",
            "segmented Docker networks",
            "IDS/SIEM correlation",
            "append-only audit store",
            "encrypted primary and DR backups",
        ],
        "limitations": [
            "Software key service is not a hardware HSM",
            "Docker networks are not a physical NGFW",
            "IDS is event/log based rather than packet mirroring",
            "DR storage is locally separated, not geographic",
        ],
    }


@app.post("/api/v1/admin/keys/rotate")
async def rotate_keys(admin: SecurityAdmin) -> dict:
    result = await internal_post(settings.key_service_url, "/v1/rotate", {})
    await audit(
        admin.subject,
        "keys.rotate",
        "success",
        {"active_version": result["active_version"]},
    )
    return result
