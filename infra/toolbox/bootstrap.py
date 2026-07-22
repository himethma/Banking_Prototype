from __future__ import annotations

import base64
import json
import os
import secrets
import stat
import smtplib
import socket
import ssl
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


CERTS = Path("/certs")
SECRETS = Path("/run/secrets")
BOOTSTRAP = Path("/bootstrap")
OUTPUT = Path("/output")


def atomic_write(path: Path, data: bytes, mode: int = 0o444) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_bytes(data)
    os.chmod(temp, mode)
    temp.replace(path)


def password() -> str:
    return secrets.token_urlsafe(24)


def pem_private(key: object) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def cert_name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Bank Coursework"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def create_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP384R1())
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(cert_name("Secure Bank Local Development CA"))
        .issuer_name(cert_name("Secure Bank Local Development CA"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA384())
    )
    return key, cert


def create_leaf(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    common_name: str,
    dns_names: list[str],
) -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP384R1())
    now = datetime.now(UTC)
    sans: list[x509.GeneralName] = [x509.DNSName(name) for name in dns_names]
    if "localhost" in dns_names:
        import ipaddress

        sans.extend(
            [
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                x509.IPAddress(ipaddress.ip_address("::1")),
            ]
        )
    cert = (
        x509.CertificateBuilder()
        .subject_name(cert_name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA384())
    )
    return pem_private(key), cert.public_bytes(serialization.Encoding.PEM)


def build_realm(credentials: dict[str, str], ids: dict[str, str]) -> dict:
    users = []
    for username, role in (
        ("alice", "customer"),
        ("bob", "customer"),
        ("security-admin", "security-admin"),
    ):
        users.append(
            {
                "id": ids[username],
                "username": username,
                "email": f"{username}@secure-bank.test",
                "emailVerified": True,
                "enabled": True,
                "requiredActions": ["CONFIGURE_TOTP"],
                "credentials": [
                    {
                        "type": "password",
                        "value": credentials[username],
                        "temporary": False,
                    }
                ],
                "realmRoles": [role],
            }
        )
    return {
        "realm": "secure-bank",
        "enabled": True,
        "displayName": "Secure Bank Identity",
        "sslRequired": "external",
        "registrationAllowed": False,
        "resetPasswordAllowed": False,
        "bruteForceProtected": True,
        "failureFactor": 5,
        "waitIncrementSeconds": 30,
        "maxFailureWaitSeconds": 900,
        "maxDeltaTimeSeconds": 43200,
        "permanentLockout": False,
        "otpPolicyType": "totp",
        "otpPolicyAlgorithm": "HmacSHA256",
        "otpPolicyDigits": 6,
        "otpPolicyPeriod": 30,
        "passwordPolicy": "hashAlgorithm(argon2)|length(12)|digits(1)|upperCase(1)|lowerCase(1)",
        "defaultSignatureAlgorithm": "ES384",
        "accessTokenLifespan": 300,
        "ssoSessionIdleTimeout": 1800,
        "roles": {
            "realm": [
                {"name": "customer", "description": "Banking customer"},
                {"name": "security-admin", "description": "Read-only security administrator"},
            ]
        },
        "clients": [
            {
                "clientId": "bank-spa",
                "name": "Secure Bank Web Application",
                "enabled": True,
                "publicClient": True,
                "standardFlowEnabled": True,
                "implicitFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "serviceAccountsEnabled": False,
                "rootUrl": "https://localhost:8443",
                "baseUrl": "/",
                "redirectUris": ["https://localhost:8443/*"],
                "webOrigins": ["https://localhost:8443"],
                "attributes": {
                    "pkce.code.challenge.method": "S256",
                    "post.logout.redirect.uris": "https://localhost:8443/*",
                },
                "protocolMappers": [
                    {
                        "name": "bank-spa-audience",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "consentRequired": False,
                        "config": {
                            "included.client.audience": "bank-spa",
                            "id.token.claim": "false",
                            "access.token.claim": "true",
                        },
                    }
                ],
                "defaultClientScopes": ["web-origins", "acr", "roles", "profile", "email"],
            }
        ],
        "users": users,
        "components": {
            "org.keycloak.keys.KeyProvider": [
                {
                    "name": "ecdsa-p384",
                    "providerId": "ecdsa-generated",
                    "subComponents": {},
                    "config": {
                        "priority": ["200"],
                        "enabled": ["true"],
                        "active": ["true"],
                        "ellipticCurve": ["P-384"],
                    },
                }
            ]
        },
    }


def setup() -> None:
    for directory in (CERTS, SECRETS, BOOTSTRAP, OUTPUT):
        directory.mkdir(parents=True, exist_ok=True)

    marker = BOOTSTRAP / ".initialized"
    if marker.exists():
        print("Secure Bank is already initialized. Use 'reset' to rotate local demo material.")
        return

    ca_key, ca_cert = create_ca()
    atomic_write(CERTS / "ca.crt", ca_cert.public_bytes(serialization.Encoding.PEM))
    atomic_write(CERTS / "ca.key", pem_private(ca_key), 0o400)

    services = {
        "gateway": ["localhost", "waf"],
        "waf-client": ["waf"],
        "frontend": ["frontend"],
        "api": ["api", "api-a", "api-b"],
        "keycloak": ["keycloak"],
        "key-service": ["key-service"],
        "audit": ["audit-service"],
        "monitor": ["monitor"],
        "db": ["db"],
        "mail": ["mailpit"],
        "backup": ["backup-scheduler", "restore-check"],
    }
    for name, dns_names in services.items():
        key_pem, cert_pem = create_leaf(ca_key, ca_cert, name, dns_names)
        key_mode = 0o600 if name == "db" else 0o444
        atomic_write(CERTS / f"{name}.key", key_pem, key_mode)
        atomic_write(CERTS / f"{name}.crt", cert_pem)
    try:
        os.chown(CERTS / "db.key", 999, 999)
    except PermissionError:
        pass

    secret_values = {
        "db_admin_password": password(),
        "app_db_password": password(),
        "keycloak_db_password": password(),
    }
    for name, value in secret_values.items():
        atomic_write(SECRETS / name, value.encode(), 0o444)
    database_url = (
        "postgresql+asyncpg://banking_app:"
        + secret_values["app_db_password"]
        + "@db:5432/banking"
    )
    atomic_write(SECRETS / "app_database_url", database_url.encode(), 0o444)
    atomic_write(
        SECRETS / "kms_aes_key",
        base64.urlsafe_b64encode(secrets.token_bytes(32)),
        0o444,
    )
    signing_key = ec.generate_private_key(ec.SECP384R1())
    atomic_write(SECRETS / "kms_signing_key.pem", pem_private(signing_key), 0o444)

    ssh_key = ed25519.Ed25519PrivateKey.generate()
    atomic_write(
        BOOTSTRAP / "backup_ssh_key",
        ssh_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        ),
        0o400,
    )
    atomic_write(
        BOOTSTRAP / "backup_ssh_key.pub",
        ssh_key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        )
        + b" secure-bank-backup\n",
    )
    host_key = ed25519.Ed25519PrivateKey.generate()
    atomic_write(
        BOOTSTRAP / "ssh_host_ed25519_key",
        host_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        ),
        0o400,
    )
    atomic_write(
        BOOTSTRAP / "ssh_host_ed25519_key.pub",
        host_key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        )
        + b" secure-bank-sftp-host\n",
    )

    credentials = {
        "alice": password(),
        "bob": password(),
        "security-admin": password(),
    }
    ids = {name: secrets.token_hex(16) for name in credentials}
    seed = {
        "users": [
            {"subject": ids["alice"], "username": "alice", "full_name": "Alice Perera"},
            {"subject": ids["bob"], "username": "bob", "full_name": "Bob Silva"},
            {
                "subject": ids["security-admin"],
                "username": "security-admin",
                "full_name": "Security Administrator",
            },
        ]
    }
    atomic_write(BOOTSTRAP / "seed.json", json.dumps(seed, indent=2).encode())
    atomic_write(
        BOOTSTRAP / "secure-bank-realm.json",
        json.dumps(build_realm(credentials, ids), indent=2).encode(),
    )

    credential_text = [
        "SECURE BANK - LOCAL DEMO CREDENTIALS",
        "Generated: " + datetime.now(UTC).isoformat(),
        "All users must enroll a TOTP authenticator on first login.",
        "",
    ]
    credential_text.extend(f"{name}: {value}" for name, value in credentials.items())
    atomic_write(
        OUTPUT / "demo-credentials.txt",
        ("\n".join(credential_text) + "\n").encode(),
        0o600,
    )
    atomic_write(marker, datetime.now(UTC).isoformat().encode())
    print("Secure Bank initialized successfully.")
    print("Credentials: .local/demo-credentials.txt")
    print("CA certificate: stored in Docker volume 'certs'; use the 'export-ca' command to copy it.")


def export_ca() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    if not (CERTS / "ca.crt").exists():
        raise SystemExit("Run setup first.")
    atomic_write(OUTPUT / "secure-bank-ca.crt", (CERTS / "ca.crt").read_bytes(), 0o644)
    print("Exported .local/secure-bank-ca.crt")


def tls_probe(host: str, port: int, minimum: ssl.TLSVersion, maximum: ssl.TLSVersion, with_client: bool = False) -> str:
    context = ssl.create_default_context(cafile=str(CERTS / "ca.crt"))
    context.minimum_version = minimum
    context.maximum_version = maximum
    if with_client:
        context.load_cert_chain(CERTS / "api.crt", CERTS / "api.key")
    with socket.create_connection((host, port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=host) as secured:
            return secured.version() or "unknown"


def protocol_check() -> None:
    results: list[dict] = []

    version = tls_probe("waf", 8443, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
    results.append({"control": "Public TLS 1.3", "passed": version == "TLSv1.3", "evidence": version})
    try:
        tls_probe("waf", 8443, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
        tls12_rejected = False
    except (OSError, ssl.SSLError):
        tls12_rejected = True
    results.append({"control": "TLS 1.2 rejected", "passed": tls12_rejected, "evidence": "handshake rejected" if tls12_rejected else "unexpectedly accepted"})

    try:
        tls_probe("key-service", 8443, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
        anonymous_rejected = False
    except (OSError, ssl.SSLError):
        anonymous_rejected = True
    mtls_version = tls_probe("key-service", 8443, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.MAXIMUM_SUPPORTED, with_client=True)
    results.append({"control": "mTLS client authentication", "passed": anonymous_rejected and bool(mtls_version), "evidence": f"anonymous rejected; authenticated {mtls_version}"})

    smtp_context = ssl.create_default_context(cafile=str(CERTS / "ca.crt"))
    with smtplib.SMTP("mailpit", 1025, timeout=5) as smtp:
        smtp.ehlo()
        before = smtp.has_extn("starttls")
        smtp.starttls(context=smtp_context)
        smtp.ehlo()
        after = smtp.noop()[0] == 250
    results.append({"control": "SMTP STARTTLS", "passed": before and after, "evidence": "STARTTLS advertised and certificate verified"})

    database_url = (SECRETS / "app_database_url").read_text().replace("postgresql+asyncpg://", "postgresql://", 1)
    pg_env = {**os.environ, "PGSSLMODE": "verify-full", "PGSSLROOTCERT": str(CERTS / "ca.crt")}
    postgres = subprocess.run(["psql", database_url, "-tAc", "SHOW ssl"], env=pg_env, capture_output=True, text=True, timeout=10)
    results.append({"control": "PostgreSQL TLS", "passed": postgres.returncode == 0 and postgres.stdout.strip() == "on", "evidence": postgres.stdout.strip() or postgres.stderr.strip()[-120:]})

    sftp = subprocess.run(
        [
            "sftp", "-b", "/dev/null", "-P", "2222", "-i", str(BOOTSTRAP / "backup_ssh_key"),
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "backup@sftp-primary"
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    password_attempt = subprocess.run(
        [
            "ssh", "-p", "2222", "-o", "BatchMode=yes", "-o", "PreferredAuthentications=password",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "backup@sftp-primary", "true"
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    results.append({"control": "SFTP key-only authentication", "passed": sftp.returncode == 0 and password_attempt.returncode != 0, "evidence": "public key accepted; password path rejected"})

    passed = all(item["passed"] for item in results)
    report = {"generated_at": datetime.now(UTC).isoformat(), "passed": passed, "results": results}
    atomic_write(OUTPUT / "protocol-check.json", json.dumps(report, indent=2).encode(), 0o644)
    print(json.dumps(report, indent=2))
    if not passed:
        raise SystemExit(1)


def main() -> None:
    command = sys.argv[1] if len(sys.argv) > 1 else "setup"
    if command == "setup":
        setup()
    elif command == "export-ca":
        export_ca()
    elif command == "protocol-check":
        protocol_check()
    else:
        raise SystemExit(f"Unknown toolbox command: {command}")


if __name__ == "__main__":
    main()
