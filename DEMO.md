# Demonstration guide

This sequence fits a concise coursework presentation while showing working evidence from every marking section.

## 1. Establish the secure baseline

1. Run `docker compose ps` and show that only WAF, loopback mail/SFTP/bastion, and the intended services are exposed.
2. Open `https://localhost:8443` and point out TLS 1.3 and the locally trusted P-384 certificate.
3. Sign in as `alice` using the randomized password from `.local/demo-credentials.txt`.
4. After the Keycloak password login, open the browser console, copy the printed six-digit demonstration code, and enter it in the application. Explain that this is an intentionally simplified prototype step, not production MFA.

## 2. Complete a protected transfer

1. Show Alice's synthetic balance and account number.
2. Transfer LKR 1,000.00 to Bob's account `100000000002`.
3. Explain that preparation validates ownership, balance, daily/per-transfer limits, and creates a five-minute request hash.
4. Complete the forced password re-authentication.
5. Show the completed transfer reference and explain row locks, ACID balance updates, and the idempotency key.
6. Explain that the description is AES-256-GCM encrypted and the receipt is ECDSA P-384 signed.

## 3. Show algorithm evidence

Run:

```text
docker compose run --rm test-runner
```

Highlight the AES round trip, unique nonces, wrong-key/AAD/ciphertext rejection, ECDSA tamper rejection, and hash-chain tests.

## 4. Show protocol evidence

Run:

```text
docker compose run --rm toolbox protocol-check
```

Highlight successful TLS 1.3, rejected TLS 1.2, rejected anonymous key-service access, authenticated mTLS, PostgreSQL TLS, SMTP STARTTLS, and rejected SFTP passwords.

## 5. Show monitoring and audit evidence

1. Sign out and sign in as `security-admin`, then complete the browser-console OTP demonstration.
2. Show the IDS/SIEM totals and audit-chain status.
3. Show the control inventory and honest prototype limitations.
4. Verify that this role has no customer transfer interface.

## 6. Compare attacks safely

Run:

```text
docker compose --profile lab run --rm attack-runner
```

Explain that the same payload is sent to the WAF-protected application and a deliberately unsafe synthetic service. Show that SQLi, XSS, IDOR, weak tokens, CSRF/replay, and brute force succeed only against the isolated lab.

## 7. Demonstrate recovery

Run:

```text
docker compose --profile restore run --rm restore-check
```

Explain the signed manifest, SHA-256 ciphertext digest, wrapped AES data key, GCM authentication tag, primary/DR SFTP copies, and disposable restore validation.

Finish by stating that the 40/30/30 values are marking weights: every security layer has an implemented control, a negative test, and visible evidence.
