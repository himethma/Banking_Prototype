from __future__ import annotations

import base64
import hashlib
import os
import threading
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import (
    aes_key_unwrap_with_padding,
    aes_key_wrap_with_padding,
)
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def b64d(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value.encode("ascii"))
    except Exception as exc:
        raise HTTPException(400, "Invalid base64 input") from exc


INITIAL_AES_KEY = base64.urlsafe_b64decode(Path("/run/secrets/kms_aes_key").read_bytes())
INITIAL_SIGNING_KEY = serialization.load_pem_private_key(
    Path("/run/secrets/kms_signing_key.pem").read_bytes(), password=None
)
if len(INITIAL_AES_KEY) != 32 or not isinstance(INITIAL_SIGNING_KEY, ec.EllipticCurvePrivateKey):
    raise RuntimeError("Invalid key material")

ACTIVE_VERSION = os.getenv("KEY_VERSION", "v1")
AES_KEYS = {ACTIVE_VERSION: INITIAL_AES_KEY}
SIGNING_KEYS = {ACTIVE_VERSION: INITIAL_SIGNING_KEY}
KEY_LOCK = threading.Lock()
app = FastAPI(title="Secure Bank Key Management Service", docs_url=None, redoc_url=None)


class EncryptRequest(BaseModel):
    plaintext: str
    associated_data: str = ""


class DecryptRequest(BaseModel):
    nonce: str
    ciphertext: str
    associated_data: str = ""
    key_version: str = Field(pattern=r"^v[0-9]+$")


class DataRequest(BaseModel):
    data: str


class VerifyRequest(DataRequest):
    signature: str
    key_version: str | None = None


class WrappedKeyRequest(BaseModel):
    key: str
    key_version: str | None = None


@app.get("/healthz")
def health() -> dict:
    return {"status": "ok", "key_version": ACTIVE_VERSION, "available_versions": sorted(AES_KEYS)}


@app.get("/v1/public-key")
def public_key() -> dict:
    public = SIGNING_KEYS[ACTIVE_VERSION].public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {
        "algorithm": "ECDSA-P384-SHA384",
        "key_version": ACTIVE_VERSION,
        "public_key": public.decode("ascii"),
    }


@app.post("/v1/encrypt")
def encrypt(request: EncryptRequest) -> dict:
    nonce = os.urandom(12)
    cipher = AESGCM(AES_KEYS[ACTIVE_VERSION])
    ciphertext = cipher.encrypt(
        nonce, request.plaintext.encode(), request.associated_data.encode()
    )
    return {
        "algorithm": "AES-256-GCM",
        "key_version": ACTIVE_VERSION,
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
    }


@app.post("/v1/decrypt")
def decrypt(request: DecryptRequest) -> dict:
    key = AES_KEYS.get(request.key_version)
    if not key:
        raise HTTPException(400, "Unknown key version")
    try:
        plaintext = AESGCM(key).decrypt(
            b64d(request.nonce),
            b64d(request.ciphertext),
            request.associated_data.encode(),
        )
    except Exception as exc:
        raise HTTPException(400, "Ciphertext authentication failed") from exc
    return {"plaintext": plaintext.decode()}


@app.post("/v1/sign")
def sign(request: DataRequest) -> dict:
    data = b64d(request.data)
    signature = SIGNING_KEYS[ACTIVE_VERSION].sign(data, ec.ECDSA(hashes.SHA384()))
    return {
        "algorithm": "ECDSA-P384-SHA384",
        "key_version": ACTIVE_VERSION,
        "digest": hashlib.sha256(data).hexdigest(),
        "signature": b64e(signature),
    }


@app.post("/v1/verify")
def verify(request: VerifyRequest) -> dict:
    version = request.key_version or ACTIVE_VERSION
    signing_key = SIGNING_KEYS.get(version)
    if not signing_key:
        return {"valid": False, "key_version": version}
    try:
        signing_key.public_key().verify(
            b64d(request.signature), b64d(request.data), ec.ECDSA(hashes.SHA384())
        )
        return {"valid": True, "key_version": version}
    except InvalidSignature:
        return {"valid": False, "key_version": version}


@app.post("/v1/wrap-key")
def wrap_key(request: WrappedKeyRequest) -> dict:
    raw = b64d(request.key)
    if len(raw) != 32:
        raise HTTPException(400, "Only 256-bit data keys are accepted")
    return {
        "algorithm": "AES-256-KWP",
        "key_version": ACTIVE_VERSION,
        "wrapped_key": b64e(aes_key_wrap_with_padding(AES_KEYS[ACTIVE_VERSION], raw)),
    }


@app.post("/v1/unwrap-key")
def unwrap_key(request: WrappedKeyRequest) -> dict:
    version = request.key_version or ACTIVE_VERSION
    wrapping_key = AES_KEYS.get(version)
    if not wrapping_key:
        raise HTTPException(400, "Unknown key version")
    try:
        raw = aes_key_unwrap_with_padding(wrapping_key, b64d(request.key))
    except Exception as exc:
        raise HTTPException(400, "Wrapped key authentication failed") from exc
    return {"key": b64e(raw), "key_version": version}


@app.post("/v1/rotate")
def rotate_keys() -> dict:
    global ACTIVE_VERSION
    with KEY_LOCK:
        next_number = max(int(version.removeprefix("v")) for version in AES_KEYS) + 1
        ACTIVE_VERSION = f"v{next_number}"
        AES_KEYS[ACTIVE_VERSION] = AESGCM.generate_key(bit_length=256)
        SIGNING_KEYS[ACTIVE_VERSION] = ec.generate_private_key(ec.SECP384R1())
    return {
        "rotated": True,
        "active_version": ACTIVE_VERSION,
        "retained_versions": sorted(AES_KEYS),
        "persistence": "in-memory prototype rotation; production uses HSM-managed durable versions",
    }
