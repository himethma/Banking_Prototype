from __future__ import annotations

import ssl
import time
from dataclasses import dataclass
from typing import Annotated

import httpx
import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .clients import security_event
from .config import get_settings


settings = get_settings()
bearer = HTTPBearer(auto_error=False)
_jwks: dict = {}
_jwks_loaded_at = 0.0


@dataclass(frozen=True)
class Principal:
    subject: str
    username: str
    email: str
    roles: frozenset[str]
    auth_time: int
    claims: dict


async def get_jwks() -> dict:
    global _jwks, _jwks_loaded_at
    if _jwks and time.monotonic() - _jwks_loaded_at < 300:
        return _jwks
    context = ssl.create_default_context(cafile=settings.keycloak_ca_file)
    async with httpx.AsyncClient(verify=context, timeout=5) as client:
        response = await client.get(settings.keycloak_jwks_url)
        response.raise_for_status()
    _jwks = response.json()
    _jwks_loaded_at = time.monotonic()
    return _jwks


async def decode_token(token: str) -> dict:
    header = jwt.get_unverified_header(token)
    if header.get("alg") != "ES384" or not header.get("kid"):
        raise jwt.InvalidAlgorithmError("ES384 token required")
    jwks = await get_jwks()
    matching = next((key for key in jwks.get("keys", []) if key.get("kid") == header["kid"]), None)
    if not matching:
        global _jwks_loaded_at
        _jwks_loaded_at = 0
        jwks = await get_jwks()
        matching = next((key for key in jwks.get("keys", []) if key.get("kid") == header["kid"]), None)
    if not matching:
        raise jwt.InvalidKeyError("Unknown signing key")
    public_key = jwt.algorithms.ECAlgorithm.from_jwk(matching)
    return jwt.decode(
        token,
        public_key,
        algorithms=["ES384"],
        issuer=settings.keycloak_issuer,
        audience="bank-spa",
        options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        leeway=10,
    )


async def current_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Principal:
    if not credentials or credentials.scheme.lower() != "bearer":
        await security_event("auth.failure", source_ip=request.client.host if request.client else "unknown")
        raise HTTPException(401, "Bearer token required", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = await decode_token(credentials.credentials)
    except Exception:
        await security_event("token.invalid", source_ip=request.client.host if request.client else "unknown")
        raise HTTPException(401, "Invalid or expired access token", headers={"WWW-Authenticate": "Bearer"})
    roles = frozenset(claims.get("realm_access", {}).get("roles", []))
    return Principal(
        subject=claims["sub"],
        username=claims.get("preferred_username", "unknown"),
        email=claims.get("email", "unknown@secure-bank.test"),
        roles=roles,
        auth_time=int(claims.get("auth_time", 0)),
        claims=claims,
    )


def require_role(role: str):
    async def dependency(principal: Annotated[Principal, Depends(current_principal)]) -> Principal:
        if role not in principal.roles:
            await security_event("access.forbidden", actor=principal.subject, details={"required_role": role})
            raise HTTPException(403, "Insufficient role")
        return principal

    return dependency


Customer = Annotated[Principal, Depends(require_role("customer"))]
SecurityAdmin = Annotated[Principal, Depends(require_role("security-admin"))]

