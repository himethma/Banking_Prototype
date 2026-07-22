from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import paramiko
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .clients import canonical_json, internal_post, security_event, sign_bytes, verify_bytes
from .config import get_settings, read_file_env


settings = get_settings()


class ExpectedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected_public_key_file: str):
        fields = Path(expected_public_key_file).read_text().strip().split()
        self.expected_type = fields[0]
        self.expected_data = fields[1]

    def missing_host_key(self, client, hostname, key):
        if key.get_name() != self.expected_type or key.get_base64() != self.expected_data:
            raise paramiko.SSHException(f"Untrusted SFTP host key for {hostname}")


def sync_database_url(username: str | None = None, password: str | None = None, database: str | None = None) -> str:
    value = settings.database_url.replace("postgresql+asyncpg://", "postgresql://", 1)
    parsed = urlsplit(value)
    user = username or parsed.username or ""
    secret = password or parsed.password or ""
    host = parsed.hostname or "db"
    port = parsed.port or 5432
    db_name = database or parsed.path.lstrip("/")
    return urlunsplit(("postgresql", f"{user}:{secret}@{host}:{port}", f"/{db_name}", "", ""))


def pg_environment() -> dict[str, str]:
    return {
        **os.environ,
        "PGSSLMODE": "verify-full",
        "PGSSLROOTCERT": settings.internal_ca_file,
    }


def sftp_upload(host: str, local_files: list[Path]) -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(ExpectedHostKeyPolicy("/bootstrap/ssh_host_ed25519_key.pub"))
    private_key = paramiko.Ed25519Key.from_private_key_file("/bootstrap/backup_ssh_key")
    client.connect(
        host,
        port=2222,
        username="backup",
        pkey=private_key,
        allow_agent=False,
        look_for_keys=False,
        timeout=10,
    )
    with client.open_sftp() as sftp:
        for path in local_files:
            remote = "/storage/" + path.name
            try:
                sftp.stat(remote)
                raise RuntimeError(f"Refusing to overwrite immutable backup {remote}")
            except FileNotFoundError:
                sftp.put(str(path), remote, confirm=True)
    client.close()


def sftp_download_latest(host: str, directory: Path) -> tuple[Path, Path]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(ExpectedHostKeyPolicy("/bootstrap/ssh_host_ed25519_key.pub"))
    private_key = paramiko.Ed25519Key.from_private_key_file("/bootstrap/backup_ssh_key")
    client.connect(host, port=2222, username="backup", pkey=private_key, allow_agent=False, look_for_keys=False)
    with client.open_sftp() as sftp:
        manifests = sorted(name for name in sftp.listdir("/storage") if name.endswith(".manifest.json"))
        if not manifests:
            raise RuntimeError("No backup manifest exists")
        manifest_name = manifests[-1]
        data_name = manifest_name.removesuffix(".manifest.json") + ".dump.aesgcm"
        manifest_path = directory / manifest_name
        data_path = directory / data_name
        sftp.get("/storage/" + manifest_name, str(manifest_path))
        sftp.get("/storage/" + data_name, str(data_path))
    client.close()
    return manifest_path, data_path


async def create_backup() -> dict:
    backup_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    with tempfile.TemporaryDirectory() as temp_dir:
        directory = Path(temp_dir)
        dump_path = directory / f"banking-{backup_id}.dump"
        encrypted_path = directory / f"banking-{backup_id}.dump.aesgcm"
        manifest_path = directory / f"banking-{backup_id}.manifest.json"
        subprocess.run(
            ["pg_dump", "--format=custom", "--no-owner", "--file", str(dump_path), sync_database_url()],
            check=True,
            env=pg_environment(),
            capture_output=True,
        )
        plaintext = dump_path.read_bytes()
        data_key = os.urandom(32)
        nonce = os.urandom(12)
        aad = f"secure-bank-backup:{backup_id}:v1".encode()
        ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, aad)
        encrypted_path.write_bytes(ciphertext)
        wrapped = await internal_post(
            settings.key_service_url,
            "/v1/wrap-key",
            {"key": base64.urlsafe_b64encode(data_key).decode()},
        )
        unsigned = {
            "format": "secure-bank-backup-v1",
            "backup_id": backup_id,
            "created_at": datetime.now(UTC).isoformat(),
            "database": "banking",
            "encryption": "AES-256-GCM",
            "nonce": base64.urlsafe_b64encode(nonce).decode(),
            "associated_data": aad.decode(),
            "wrapped_key": wrapped["wrapped_key"],
            "key_version": wrapped["key_version"],
            "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
            "ciphertext_size": len(ciphertext),
        }
        signed = await sign_bytes(canonical_json(unsigned))
        manifest = {**unsigned, "signature": signed["signature"], "signature_algorithm": signed["algorithm"]}
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        await asyncio.to_thread(sftp_upload, "sftp-primary", [encrypted_path, manifest_path])
        await asyncio.to_thread(sftp_upload, "sftp-dr", [encrypted_path, manifest_path])
    await security_event("backup.created", actor="backup-scheduler", details={"backup_id": backup_id})
    return manifest


async def restore_check() -> dict:
    with tempfile.TemporaryDirectory() as temp_dir:
        directory = Path(temp_dir)
        manifest_path, encrypted_path = await asyncio.to_thread(
            sftp_download_latest, "sftp-primary", directory
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        unsigned = {k: v for k, v in manifest.items() if k not in {"signature", "signature_algorithm"}}
        if not await verify_bytes(
            canonical_json(unsigned), manifest["signature"], manifest["key_version"]
        ):
            await security_event("backup.invalid", actor="restore-check", details={"reason": "signature"})
            raise RuntimeError("Backup manifest signature is invalid")
        ciphertext = encrypted_path.read_bytes()
        if hashlib.sha256(ciphertext).hexdigest() != manifest["ciphertext_sha256"]:
            await security_event("backup.invalid", actor="restore-check", details={"reason": "hash"})
            raise RuntimeError("Encrypted backup hash is invalid")
        unwrapped = await internal_post(
            settings.key_service_url,
            "/v1/unwrap-key",
            {"key": manifest["wrapped_key"], "key_version": manifest["key_version"]},
        )
        data_key = base64.urlsafe_b64decode(unwrapped["key"])
        plaintext = AESGCM(data_key).decrypt(
            base64.urlsafe_b64decode(manifest["nonce"]),
            ciphertext,
            manifest["associated_data"].encode(),
        )
        dump_path = directory / "verified.dump"
        dump_path.write_bytes(plaintext)
        admin_password = read_file_env("DB_ADMIN_PASSWORD")
        admin_url = sync_database_url("banking_root", admin_password, "postgres")
        restore_url = sync_database_url("banking_root", admin_password, "restore_validation")
        subprocess.run(
            ["psql", admin_url, "-v", "ON_ERROR_STOP=1", "-c", "DROP DATABASE IF EXISTS restore_validation WITH (FORCE)", "-c", "CREATE DATABASE restore_validation"],
            check=True,
            env=pg_environment(),
            capture_output=True,
        )
        subprocess.run(["pg_restore", "--no-owner", "--dbname", restore_url, str(dump_path)], check=True, env=pg_environment(), capture_output=True)
        check = subprocess.run(["psql", restore_url, "-tAc", "SELECT COUNT(*) FROM accounts"], check=True, env=pg_environment(), capture_output=True, text=True)
        subprocess.run(["psql", admin_url, "-v", "ON_ERROR_STOP=1", "-c", "DROP DATABASE restore_validation WITH (FORCE)"], check=True, env=pg_environment(), capture_output=True)
    result = {"valid": True, "backup_id": manifest["backup_id"], "accounts": int(check.stdout.strip())}
    print(json.dumps(result, indent=2))
    return result


async def scheduler() -> None:
    while True:
        delay = 24 * 60 * 60
        try:
            result = await create_backup()
            print(json.dumps({"backup": result["backup_id"], "status": "created"}))
        except Exception as exc:
            print(json.dumps({"backup": "failed", "error": str(exc)}), file=sys.stderr)
            await security_event("backup.invalid", actor="backup-scheduler", details={"reason": "creation-failed"})
            delay = 30
        await asyncio.sleep(delay)


async def main() -> None:
    command = sys.argv[1] if len(sys.argv) > 1 else "create"
    if command == "schedule":
        await scheduler()
    elif command == "create":
        print(json.dumps(await create_backup(), indent=2))
    elif command == "restore-check":
        await restore_check()
    else:
        raise SystemExit(f"Unknown backup command: {command}")


if __name__ == "__main__":
    asyncio.run(main())
