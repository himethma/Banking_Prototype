# Security implementation and evidence map

The percentages in the assignment are marking weights, not implementation allocation. All three layers below have executable controls and verification evidence.

## Algorithm-level security

| Control | Implementation | Threats addressed | Evidence |
|---|---|---|---|
| Symmetric encryption/decryption | AES-256-GCM with random 96-bit nonces, authenticated record metadata, and key versions | Disclosure and ciphertext modification | `test_crypto_controls.py`; encrypted profile/description/statement paths |
| Key management | Private mTLS-only key service owns AES KEK and P-384 signing key | Key exposure and unauthorized cryptographic operations | Anonymous TLS client rejected by `toolbox protocol-check` |
| Password hashing | Keycloak password policy uses Argon2id | Offline cracking and credential compromise | Realm bootstrap configuration and first-login test |
| Asymmetric signing | ES384/P-384 for Keycloak tokens, receipts, audit entries, and manifests | Token/receipt forgery and repudiation | Signature and tamper unit tests; receipt verification endpoint |
| Hashing | SHA-256 audit chain and backup ciphertext digest | Log or backup modification | Admin audit verifier and restore check |
| Prototype OTP flow | A random six-digit code is generated and verified by the browser after Keycloak login; transfers separately force recent password re-authentication | Demonstrates an OTP user journey only; it does **not** mitigate a compromised browser or access token | Browser console message, verification screen, and prepare/re-authenticate/commit flow |
| Envelope backup encryption | Unique AES-256-GCM data key wrapped by the key service | Backup theft and master-key exposure | `restore-check` verifies signature, hash, wrap and GCM tag |

Cryptographic code uses `cryptography`, PyJWT, and Keycloak rather than custom primitives. Encryption operations bind ciphertext to a record-specific associated-data value, so copying ciphertext between records fails authentication.

## Protocol-level security

| Protocol | Configuration | Negative test |
|---|---|---|
| HTTPS / TLS 1.3 | Local P-384 CA; WAF exposes 8443; HSTS and secure headers | TLS 1.2-only handshake is rejected |
| OpenID Connect | Authorization Code + PKCE; implicit and password grants disabled | Forged/expired/wrong-audience tokens return 401 |
| Internal mTLS | WAF/router/API/key/audit/monitor certificates from the local CA | Anonymous key-service handshake is rejected |
| PostgreSQL TLS | `hostssl`, SCRAM-SHA-256, CA and hostname verification | Non-TLS host rules reject before authentication |
| SMTP STARTTLS | Mailpit requires STARTTLS; API validates the mail certificate | Plaintext message submission is not used or accepted |
| SFTP / SSH | Ed25519 public key, password authentication disabled, chroot storage | Password-only SSH attempt fails |
| Secure event transport | Security events use mTLS JSON ingestion; architecture maps this to syslog-TLS in production | Untrusted clients cannot open the ingestion connection |

`docker compose run --rm toolbox protocol-check` executes the positive and negative protocol checks and writes JSON evidence.

## System-level security

| Control | Implementation | Threats addressed |
|---|---|---|
| WAF | Official OWASP CRS LTS container in blocking mode | SQLi, XSS, command injection, malicious request bodies |
| Segmentation | Edge, DMZ, app, data, audit, backup, management, and lab networks | Lateral movement and direct database/service access |
| Database firewall policy | No published port, `pg_hba.conf`, TLS-only roles, separate Keycloak/application identities | Direct database attack and privilege spread |
| Load balancing and health checks | TLS router distributes across two stateless API replicas | Single replica failure and basic availability |
| IDS/SIEM | Threshold correlation for authentication, tokens, authorization, transfer velocity, audit, and backup failures | Delayed detection and repeated attacks |
| Append-only logging | Separate service, SQLite update/delete denial triggers, SHA-256 chain, P-384 signatures | Log deletion, alteration, and repudiation |
| Backup/DR | Daily and on-demand encrypted copies to independent SFTP volumes; no overwrite behavior | Data loss, ransomware, and backup tampering |
| Bastion | Loopback-only SSH, key authentication, no forwarding, verbose session logs | Unrestricted administration and unaudited access |
| Container hardening | Non-root custom images, dropped capabilities, read-only roots/tmpfs, health checks, resource boundaries | Container escape opportunities and persistence |
| Vulnerable-lab containment | Explicit profile, synthetic in-memory data, isolated network, no banking volumes/secrets | Accidental exposure of deliberate vulnerabilities |

## Security event rules

- Five authentication failures in five minutes: medium alert.
- Three WAF or invalid-token events in their configured windows: high alert.
- Three forbidden-resource attempts in five minutes: medium alert.
- Five completed transfers per minute per actor: velocity alert.
- Any audit-chain or backup-integrity failure: critical alert.

The administrator role can acknowledge alerts but cannot view decrypted PII or mutate balances. Customer endpoints enforce account ownership and return 404 for inaccessible resources to reduce identifier discovery.

## Data and trust boundaries

- Only WAF ports 8080/8443 are public; mail UI, SFTP, DR SFTP, and bastion are loopback-only development interfaces.
- PostgreSQL, APIs, Keycloak database, key service, audit service, and monitor have no host-published ports.
- Master AES/signing keys stay inside the key-service container's read-only secret mount. APIs receive only operation results or per-backup data keys.
- Access tokens remain in Keycloak JS memory and are not intentionally stored in localStorage.
- Emails omit balances, account numbers, and transfer amounts.
- All committed data and credentials are synthetic; randomized local secrets live in Docker volumes and `.local`, both outside version control.

## Limitations

The controls demonstrate the architecture without claiming physical infrastructure. Hardware HSM certification, enterprise NGFW functions, packet-mirroring NIDS, IPsec remote-access infrastructure, immutable cloud object locks, multi-region recovery, certificate revocation services, and externally trusted certificates belong in a production deployment.
