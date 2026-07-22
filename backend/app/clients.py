from __future__ import annotations

import base64
import json
import ssl
from email.message import EmailMessage

import aiosmtplib
import httpx

from .config import get_settings


settings = get_settings()


def tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=settings.internal_ca_file)
    context.load_cert_chain(settings.client_cert_file, settings.client_key_file)
    return context


async def internal_post(base_url: str, path: str, payload: dict) -> dict:
    async with httpx.AsyncClient(verify=tls_context(), timeout=8) as client:
        response = await client.post(base_url + path, json=payload)
        response.raise_for_status()
        return response.json()


async def internal_get(base_url: str, path: str) -> dict | list:
    async with httpx.AsyncClient(verify=tls_context(), timeout=8) as client:
        response = await client.get(base_url + path)
        response.raise_for_status()
        return response.json()


async def encrypt_text(plaintext: str, associated_data: str) -> dict:
    return await internal_post(
        settings.key_service_url,
        "/v1/encrypt",
        {"plaintext": plaintext, "associated_data": associated_data},
    )


async def decrypt_text(envelope: dict, associated_data: str) -> str:
    result = await internal_post(
        settings.key_service_url,
        "/v1/decrypt",
        {**envelope, "associated_data": associated_data},
    )
    return result["plaintext"]


async def sign_bytes(data: bytes) -> dict:
    return await internal_post(
        settings.key_service_url,
        "/v1/sign",
        {"data": base64.urlsafe_b64encode(data).decode()},
    )


async def verify_bytes(data: bytes, signature: str, key_version: str | None = None) -> bool:
    result = await internal_post(
        settings.key_service_url,
        "/v1/verify",
        {
            "data": base64.urlsafe_b64encode(data).decode(),
            "signature": signature,
            "key_version": key_version,
        },
    )
    return bool(result["valid"])


async def audit(actor: str, action: str, outcome: str, details: dict) -> dict:
    return await internal_post(
        settings.audit_service_url,
        "/v1/events",
        {"actor": actor, "action": action, "outcome": outcome, "details": details},
    )


async def security_event(
    event_type: str,
    actor: str = "anonymous",
    source_ip: str = "unknown",
    details: dict | None = None,
) -> dict:
    try:
        return await internal_post(
            settings.monitor_service_url,
            "/v1/events",
            {
                "event_type": event_type,
                "actor": actor,
                "source_ip": source_ip,
                "details": details or {},
            },
        )
    except Exception:
        return {"accepted": False}


async def send_notification(recipient: str, subject: str, text: str) -> None:
    message = EmailMessage()
    message["From"] = "notifications@secure-bank.test"
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(text)
    context = ssl.create_default_context(cafile=settings.smtp_ca_file)
    await aiosmtplib.send(
        message,
        hostname=settings.smtp_host,
        port=settings.smtp_port,
        start_tls=True,
        tls_context=context,
        timeout=5,
    )


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
