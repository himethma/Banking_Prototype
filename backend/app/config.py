from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def read_file_env(name: str, fallback: str = "") -> str:
    file_name = os.getenv(name + "_FILE")
    if file_name and Path(file_name).exists():
        return Path(file_name).read_text().strip()
    return os.getenv(name, fallback)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    database_url: str = ""
    keycloak_issuer: str = "https://localhost:8443/auth/realms/secure-bank"
    keycloak_jwks_url: str = "https://keycloak:8443/auth/realms/secure-bank/protocol/openid-connect/certs"
    keycloak_ca_file: str = "/certs/ca.crt"
    key_service_url: str = "https://key-service:8443"
    audit_service_url: str = "https://audit-service:8443"
    monitor_service_url: str = "https://monitor:8443"
    client_cert_file: str = "/certs/api.crt"
    client_key_file: str = "/certs/api.key"
    internal_ca_file: str = "/certs/ca.crt"
    smtp_host: str = "mailpit"
    smtp_port: int = 1025
    smtp_ca_file: str = "/certs/ca.crt"
    public_origin: str = "https://localhost:8443"
    transfer_limit_minor: int = 10_000_000
    daily_limit_minor: int = 25_000_000
    instance_name: str = "api"


@lru_cache
def get_settings() -> Settings:
    values: dict[str, object] = {}
    database_url = read_file_env("DATABASE_URL")
    if database_url:
        values["database_url"] = database_url
    return Settings(**values)

