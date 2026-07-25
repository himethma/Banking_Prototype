# Secure Bank

## Demonstration runbook

**Target duration:** 12 minutes 40 seconds  
**Format:** Slides support the story; the browser and terminal provide the evidence.  
**Presenters:** Three equal sections, followed by questions.

| Presenter | Time | Focus | Main evidence |
|---|---:|---|---|
| Presenter 1 | 0:00–4:10 | Context and algorithm security | Protected transfer and negative tests |
| Presenter 2 | 4:10–8:20 | Protocol security and attack comparison | Protocol checker and isolated lab |
| Presenter 3 | 8:20–12:40 | System security, recovery, and conclusion | Admin dashboard and restore check |

The timings leave roughly two minutes for questions within a 15-minute slot.

---

## Preflight

Complete this before the audience arrives.

1. Open the repository root in a terminal. Increase the font until the back row can read it.
2. Prepare the generated certificates, randomized accounts, and containers:

   ```text
   docker compose run --rm --build toolbox setup
   docker compose up --build -d
   docker compose ps
   ```

3. Open `https://localhost:8443`. Trust the local coursework CA if needed.
4. Keep browser developer tools open on the **Console** tab.
5. Keep `.local/demo-credentials.txt` available privately. Never project or paste a password.
6. Run the four evidence commands once. Keep each successful result in a separate terminal tab:

   ```text
   docker compose run --rm test-runner
   docker compose run --rm toolbox protocol-check
   docker compose --profile lab run --rm attack-runner
   docker compose --profile restore run --rm restore-check
   ```

7. Confirm that Alice and Bob exist. Bob’s destination account is `100000000002`.
8. Use a synthetic transfer of **LKR 1,000.00**.
9. Confirm that an encrypted backup exists. The backup scheduler creates one when the stack starts.
10. Do not reset volumes, delete `.local`, alter firewall rules, or improvise fixes during the presentation.

### Stage arrangement

- Only one view is projected at a time: either the slides or the regular laptop screen.
- Finish explaining a slide before switching to the browser or terminal.
- Once the demonstration view is visible, describe only what the audience can currently see.
- Put the browser, terminal tabs, and slide deck in their final positions before starting. Switching should take only a few seconds.
- One person should control the screen changes throughout the presentation if possible.

### Screen sequence

| Time | Audience sees | Purpose |
|---|---|---|
| 0:00–1:35 | Slides 1–3 | Introduce the project and explain the algorithm controls |
| 1:35–4:10 | Laptop: customer browser, then tests | Demonstrate the protected transfer and algorithm evidence |
| 4:10–4:40 | Slide 4 | Explain the protocol path |
| 4:40–6:35 | Laptop: protocol terminal | Run the protocol checks |
| 6:35–7:00 | Slide 5 | Explain the secure-versus-vulnerable comparison |
| 7:00–8:20 | Laptop: attack terminal | Run the isolated attack comparison |
| 8:20–8:50 | Slide 6 | Explain prevention, detection, and recovery |
| 8:50–10:15 | Laptop: administrator browser | Show RBAC, alerts, and audit evidence |
| 10:15–10:40 | Slide 7 | Explain the backup and restore chain |
| 10:40–11:50 | Laptop: restore terminal | Verify the encrypted backup |
| 11:50–12:40 | Slide 8 | Limitations and conclusion |

### Switching rule

Use a short transition sentence while the operator changes views. Do not begin the next explanation until the correct view is visible.

---

# Presenter 1

## Context and algorithm security — 4 minutes 10 seconds

### 0:00–0:30 — Opening claim

**SCREEN:** SLIDE 1

**DO**

Show the cover slide. Pause briefly on the layered-security image.

**SAY**

> So for CW1, we built a layered security architecture for an online bank. But we didn't just want to show you a diagram — we wanted to prove it actually holds up. So we built the core controls ourselves, tried to break them, and we're going to show you exactly what happened.

### 0:30–1:10 — Frame the three layers

**SCREEN:** SLIDE 2

**DO**

Trace the single transaction path from the browser to the database and audit evidence.

**SAY**

> Instead of walking through every box on this diagram one by one, we're going to follow a single test transaction as it moves through the system. We'll start with how the data gets encrypted and signed, then look at how the connections between services are secured, and finish up with monitoring and recovery.


### 1:10–1:35 — Explain the algorithm controls

**SCREEN:** SLIDE 3

**DO**

Advance to slide 3. Explain the three algorithm controls before opening the live system.

**SAY**

> At the algorithm level, there are three main controls we're relying on. AES-256-GCM protects sensitive data and also catches any tampering. ECDSA P-384 signs our receipts and other evidence. And SHA-256 chains the audit records together, so if oneever goes missing or gets changed, we'll know.
>Let's step away from the slides now and show you these controls in action — first with areal transfer, then with our automated negative tests.

**SWITCH**

Change from the slide deck to the regular laptop screen. Wait until the customer browser is visible.

### 1:35–3:25 — Complete a protected transfer

**SCREEN:** LAPTOP — CUSTOMER BROWSER

**DO**

1. Open `https://localhost:8443`.
2. Sign in as **Alice** using the private randomized password.
3. Open the browser console.
4. Copy the short-lived demonstration OTP and enter it in the application.
5. Open Alice’s dashboard.
6. Start a transfer of **LKR 1,000.00** to Bob at `100000000002`.
7. Review the prepared transfer.
8. Complete the forced password re-authentication.
9. Show the completed transfer reference and updated balance.

**SAY**

> I'll sign in as Alice — she's got the customer role. She logs in through OpenID Connect,authorization code flow with PKCE, and then there's a one-time code. For this prototype, that code just pops up in the browser console — quick heads-up, that's not real MFA, just showing the flow.
>
>Now let's send Bob a thousand rupees. Before it goes through, the API double-checksAlice owns the account, has enough balance, and is within her limits — then makes herre-enter her password before the money actually moves.
>
>Once I confirm, the balance updates exactly once. We're using row locks and anidempotency key, so refreshing or resending never double-charges. And under theood, the description's encrypted with AES-256-GCM, receipt signed with ECDSA P384.

**EXPECT**

- Alice’s balance changes once.
- A completed transfer reference appears.
- The console OTP is short-lived and clearly part of the demonstration.

**FALLBACK**

If re-authentication is slow, do not click the commit button repeatedly. Show the prepared transfer and an earlier successful reference, then continue.

### 3:25–4:00 — Show negative algorithm tests

**SCREEN:** LAPTOP — TERMINAL

**DO**

Switch from the browser to the prepared algorithm-test terminal tab. Do not return to slide 3.

Run:

```text
docker compose run --rm test-runner
```

Point to the test-name lines and their PASS statuses:

- `test_aes_256_gcm_round_trip_and_unique_nonces` passes.
- `test_aes_gcm_rejects_ciphertext_and_metadata_tampering` passes.
- `test_ecdsa_p384_signature_rejects_modified_receipt` passes.
- `test_sha256_hash_chain_detects_reordering` passes.

**SAY**

> Getting your data back after encryption — that part's easy. What really matters is whathappens when something goes wrong.

>You can see the test output here covers the AES round trip, unique nonces, tamperingrejection, signature rejection, and the hash-chain check, each as its own passing test.So we're not just testing that it works — we're testing that it fails safely too.

**FALLBACK**

Use the pre-run successful output and state that it was produced by the same containerized test runner.

### 4:00–4:10 — Handover

**DO**

Leave the terminal result visible and pass control to Presenter 2.

**SAY**

> So that's the algorithm layer around the transaction covered. We'll jump back to theslides for a second, and Presenter 2 is going to take you through how the connectionsbetween our services are protected.

**SWITCH**

Change from the laptop screen to slide 4. Presenter 2 should wait for the slide to appear before speaking.

---

# Presenter 2

## Protocol security and attack comparison — 4 minutes 10 seconds

### 4:10–4:40 — Explain the protocol path

**SCREEN:** SLIDE 4

**DO**

Trace the path across slide 4 while the audience can see it.

**SAY**

> This slide shows the main connections we are going to test. The browser connects to the public system using TLS 1.3. Inside the system, services communicate through mutual TLS, the database uses a verified encrypted connection, email upgrades using STARTTLS, and files are transferred through SFTP using security keys instead of passwords.
>
>We also test connections that should be rejected, such as an older TLS version, anonymous access to the key service, and password-based SFTP login.

**SWITCH**

Change from slide 4 to the regular laptop screen. Wait until the protocol terminal is visible.

### 4:40–6:35 — Prove the secure paths

**SCREEN:** LAPTOP — PROTOCOL TERMINAL

**DO**

Run:

```text
docker compose run --rm toolbox protocol-check
```

Point to each success and rejection pair:

- TLS 1.3 succeeds.
- TLS 1.2 is rejected.
- Anonymous key-service access is rejected.
- Authenticated mTLS succeeds.
- PostgreSQL uses verified TLS.
- SMTP upgrades with STARTTLS.
- SFTP accepts an Ed25519 key and rejects passwords.

**SAY**

> I am now running our protocol checker. First, it confirms that the public website accepts TLS 1.3, while the older TLS 1.2 connection is blocked.
>
>Inside the system, the services use mutual TLS. This means an anonymous client cannot access the key service, but a properly authenticated service is allowed.
>
>We also test the other connections instead of simply assuming they are secure. PostgreSQL verifies its TLS certificate, the local mail service upgrades using STARTTLS, and SFTP accepts the Ed25519 key but rejects password login. Each connection has a clear rule for authentication and encryption.

**EXPECT**

The machine-readable result is also written to `.local/protocol-check.json`.

**FALLBACK**

Open the pre-run output or `.local/protocol-check.json` and walk through the same pass/reject pairs.

### 6:35–7:00 — Explain the attack comparison

**SWITCH**

Change from the terminal back to slide 5. Wait until the comparison slide is visible.

**SCREEN:** SLIDE 5

**DO**

Explain the two sides of the comparison before running the attack lab.

**SAY**

> For the next part, we test the same attacks on two applications. One is our protected application, and the other is a deliberately vulnerable application created only for this comparison.
>
>In the secure application, every attack should be blocked. In the vulnerable application, the same attack should succeed. We will now switch back to the laptop and run the comparison.
**SWITCH**

Change from slide 5 to the attack-runner terminal.

### 7:00–8:10 — Compare the same attacks

**SCREEN:** LAPTOP — ATTACK TERMINAL

**DO**

Run:

```text
docker compose --profile lab run --rm attack-runner
```

Point to the PASS rows and their comparison labels, then summarize:

- SQL injection
- Stored XSS
- IDOR
- Weak-token tampering
- CSRF or replay
- Brute force

**SAY**

> This next test makes the difference easier to understand. We send the same attack to both our protected application and a deliberately vulnerable test application.
>
>The results show each attack as a PASS, with `secure=... [blocked]` and `vulnerable=... [exploited]`. The test repeats this comparison for stored XSS, IDOR, token tampering, replay attacks, and brute-force attacks.
>
>The vulnerable application is completely separate from the banking system and uses only fake test data. It is included only to show the difference safely.

**EXPECT**

Every row shows **secure target blocked** and **vulnerable target exploited**.

**FALLBACK**

Show the prepared result. If time is tight, explain SQL injection and replay in detail and summarize the other four cases.

### 8:10–8:20 — Handover

**DO**

Leave the secure-versus-vulnerable result visible and pass control to Presenter 3.

**SAY**

> At this point, we have confirmed that the secure system blocks the attacks. Gamitha will explain what the system records and how it responds if something still goes wrong.

**SWITCH**

Change from the laptop screen to slide 6. Presenter 3 should wait for the slide to appear before speaking.

---

# Presenter 3

## System security, recovery, and conclusion — 4 minutes 20 seconds

### 8:20–8:50 — Explain the system controls

**SCREEN:** SLIDE 6

**DO**

Use slide 6 to explain prevention, detection, and recovery before opening the administrator dashboard.

**SAY**

> At the system level, our security controls focus on three main areas. First, we limit unnecessary access using role-based permissions and network segmentation. Second, we monitor for suspicious activity through the WAF, application logs, and IDS or SIEM rules. Finally, we ensure recovery with encrypted backups that are securely stored in restricted backup locations.
>
> Next, we'll switch to the administrator dashboard to demonstrate these access restrictions and the evidence generated by our monitoring controls.

**SWITCH**

Change from slide 6 to the regular laptop screen. Wait until the administrator browser is visible.

### 8:50–10:15 — Show the security administrator view

**SCREEN:** LAPTOP — ADMINISTRATOR BROWSER

**DO**

1. Sign out from Alice.
2. Sign in as **security-admin** using the private randomized password.
3. Complete the console OTP demonstration.
4. Show the security totals and recent alerts.
5. Show the control inventory and stated prototype limitations.
6. Show recent transfers, user status, and security events.
7. Show the audit-chain status.
8. Confirm that this role has no customer transfer interface.

**SAY**

> I’m now signing in with a different role: security-admin. This account can view security information, but it cannot perform customer transfers. This demonstrates the principle of least privilege, where each role is limited to only the permissions it needs.
>
> The dashboard brings together WAF events, application logs, and IDS or SIEM alerts in one place. From here, we can see what happened, which rule was triggered, and whether the audit trail remains valid.
>
> The audit records are append-only and linked using SHA-256. They’re also digitally signed, so any attempt to modify or remove a record would invalidate the verification. We’ve also documented the prototype’s limitations here to clearly distinguish simulated controls from production-grade hardware.

**EXPECT**

- Security metrics and events are visible.
- The audit chain is valid.
- The security-admin navigation contains no transfer action.

**FALLBACK**

If alerts have not refreshed, show the event stream and audit-chain status. Do not rerun the attack lab until after the presentation.

### 10:15–10:40 — Explain the recovery chain

**SWITCH**

Change from the administrator browser back to slide 7.

**SCREEN:** SLIDE 7

**DO**

Explain the backup path from encryption to the tested restore.

**SAY**

> This slide shows the backup and recovery process before we run it. The database backup is encrypted with a unique data key, which is then protected by the key management service. A signed manifest records the backup's digest and metadata, and the encrypted backup is stored in both the primary and disaster recovery locations.
>
> The final step is the most important one. We restore the backup into a temporary database and run a query to confirm everything was recovered correctly. We'll now switch to the terminal and verify the entire process.

**SWITCH**

Change from slide 7 to the prepared restore terminal.

### 10:40–11:50 — Verify recovery

**SCREEN:** LAPTOP — RESTORE TERMINAL

**DO**

Run:

```text
docker compose --profile restore run --rm restore-check
```

Point to the PASS rows and summarize the recovery stages:

- ECDSA manifest signature
- Primary and DR copies
- SHA-256 ciphertext digest
- Wrapped AES data key
- GCM authentication tag
- Disposable PostgreSQL restore and query

**SAY**

> This command verifies the complete backup and recovery process we just described.
>
> Each database backup is encrypted with a unique AES-256-GCM data key. That key is then wrapped by the key management service, and the manifest is digitally signed so we can verify the backup's origin and integrity.
>
> The output shows each stage as a separate PASS check, including the manifest signature, the primary and disaster recovery copies, the ciphertext digest, the wrapped key, the GCM authentication tag, and the temporary restore. As part of the test, we verify every stage, restore the database into a temporary container, and run a query to confirm the backup was recovered successfully.

**EXPECT**

The command reports authenticated decryption and a successful query against the disposable restored database.

**FALLBACK**

Show the prepared successful output and explain each verified stage. Do not interrupt a running restore.

### 11:50–12:40 — Close honestly

**SWITCH**

Change from the restore terminal back to slide 8. Pause until the slide is fully visible.

**SCREEN:** SLIDE 8

**DO**

Pause on:

> CONTROL + REJECTION + EVIDENCE

**SAY**

> To finish, we want to be clear about the scope of this project. This is a coursework prototype, not a production banking system. Docker networks demonstrate network segmentation, but they are not a physical next-generation firewall. Our key management service models the role of an HSM, but it isn't hardware-backed. The monitoring is based on security events rather than mirrored network traffic, and both backup locations are still hosted on the same machine.
>
> Even with those limitations, the core CW1 security concepts are fully demonstrated. At each layer, we can show the security control, demonstrate what happens when it's challenged, and present the evidence the system generates. That's exactly what this prototype was designed to prove.

---

# Contingencies

## If the live environment misbehaves

| Situation | Response |
|---|---|
| The screen switch takes a few seconds | Finish the transition sentence, pause, and wait. Do not start describing the next view while the previous one is still projected. |
| The wrong window appears | Stop speaking, correct the view, and continue from the next **SAY** paragraph. Do not explain the mistake. |
| The stack is still starting | Use the previously opened browser and pre-run evidence tabs. Do not restart the stack in front of the audience. |
| Transfer re-authentication is slow | Do not submit twice. Show the prepared transfer hash and an earlier successful reference. |
| The protocol command is slow | Open `.local/protocol-check.json`. |
| No fresh SIEM alert appears | Show the event stream and valid audit chain. |
| The restore check is slow | Use the pre-run output and explain each verified stage. |
| A service is unhealthy | Do not debug live. State the affected evidence item, show the prepared result, and continue. |

## If time is short

Preserve this evidence spine:

1. Customer transfer and re-authentication
2. Protocol success/rejection summary
3. Administrator audit-chain view
4. Restore result

Cut detailed explanations of secondary tests. Do not cut the negative-test claim.

---

# Likely questions

### Is the browser-console OTP real MFA?

No. That part is only there to demonstrate the extra verification step. In a real system, we would replace it with something verified by the server, such as an authenticator app or WebAuthn. We still require a fresh Keycloak password login before the transfer is committed.

### Is the key service an HSM?

No. It demonstrates the same boundary: the main key is not handed to the banking application, and cryptographic operations go through a separate service. In production, that service would need to be backed by a real HSM or managed KMS.

### Why use AES-GCM instead of encryption alone?

Because we need to know if the encrypted data has been changed, not just hide its contents. GCM gives us confidentiality and authentication together, and our negative tests show that tampered data is rejected.

### Why both a hash chain and digital signatures?

They prove different things. The SHA-256 chain helps reveal a deleted, changed, or reordered record. The ECDSA signature helps prove that the audit evidence came from our audit service.

### Why use both HTTPS and SFTP?

They are used for different jobs. HTTPS protects the interactive website and API requests. SFTP is used for automated file transfers, such as encrypted backups, and it uses an Ed25519 key instead of a password.

### Did the prototype implement database TDE from CW1?

Not as a built-in database-engine feature. In the prototype, sensitive fields use AES-256-GCM and the backups are also encrypted and authenticated. We would still need database-level TDE as part of a production deployment.

### Is the disaster-recovery copy geographically separate?

No. They are separate restricted stores inside the prototype, but both still run on the same Docker host. A production design would place the recovery copy in a genuinely separate location.

---

## Evidence sources

- The supplied CW1 report and architecture diagram
- `README.md`, `SECURITY.md`, and `DEMO.md`
- `test-runner`, `protocol-check`, `attack-runner`, and `restore-check`
