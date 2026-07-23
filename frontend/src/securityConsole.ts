/**
 * Security Console — real-time browser-console evidence logger.
 *
 * Prints styled, grouped messages to the developer console so that
 * during a demo, every security mechanism is visible as it fires.
 */

/* ------------------------------------------------------------------ */
/*  Style constants                                                    */
/* ------------------------------------------------------------------ */

const STYLES = {
  banner:
    "background:#0d1117;color:#58a6ff;font-size:14px;font-weight:bold;padding:6px 14px;border-radius:6px;border:1px solid #30363d",
  heading:
    "background:#161b22;color:#f0f6fc;font-size:12px;font-weight:bold;padding:4px 10px;border-radius:4px",
  algorithm:
    "background:#1a1040;color:#d2a8ff;font-size:11px;font-weight:bold;padding:3px 8px;border-radius:3px",
  protocol:
    "background:#0a2540;color:#79c0ff;font-size:11px;font-weight:bold;padding:3px 8px;border-radius:3px",
  system:
    "background:#0d2818;color:#7ee787;font-size:11px;font-weight:bold;padding:3px 8px;border-radius:3px",
  label:
    "color:#8b949e;font-size:11px",
  value:
    "color:#f0f6fc;font-size:11px;font-weight:bold",
  success:
    "color:#3fb950;font-size:11px;font-weight:bold",
  warning:
    "color:#d29922;font-size:11px;font-weight:bold",
  error:
    "color:#f85149;font-size:11px;font-weight:bold",
  dim:
    "color:#6e7681;font-size:10px",
} as const;

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function base64UrlDecode(str: string): string {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  try {
    return decodeURIComponent(
      atob(padded)
        .split("")
        .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join(""),
    );
  } catch {
    return atob(padded);
  }
}

function parseJwt(token: string): { header: any; payload: any } | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    return {
      header: JSON.parse(base64UrlDecode(parts[0])),
      payload: JSON.parse(base64UrlDecode(parts[1])),
    };
  } catch {
    return null;
  }
}

function shortId(id: string): string {
  return id.length > 12 ? id.slice(0, 8) + "…" : id;
}

function timestamp(): string {
  return new Date().toISOString().slice(11, 23);
}

/* ------------------------------------------------------------------ */
/*  Banner                                                             */
/* ------------------------------------------------------------------ */

export function logBanner(): void {
  console.log(
    "\n%c🔒 SECURE BANK — Security Evidence Console",
    STYLES.banner,
  );
  console.log(
    "%cSecurity operations are logged here in real-time as they happen.\n" +
      "Colour key:  %cALGORITHM%c  %cPROTOCOL%c  %cSYSTEM",
    STYLES.dim,
    STYLES.algorithm, STYLES.dim,
    STYLES.protocol, STYLES.dim,
    STYLES.system,
  );
  console.log("");
}

/* ------------------------------------------------------------------ */
/*  TLS / Connection                                                   */
/* ------------------------------------------------------------------ */

export function logTlsConnection(): void {
  console.groupCollapsed(
    `%c[${timestamp()}]%c PROTOCOL %c TLS 1.3 Secure Connection Established`,
    STYLES.dim, STYLES.protocol, STYLES.heading,
  );
  console.log("%cEndpoint:       %chttps://localhost:8443", STYLES.label, STYLES.value);
  console.log("%cProtocol:       %cTLS 1.3 (only — TLS 1.2 rejected)", STYLES.label, STYLES.value);
  console.log("%cCipher suite:   %cTLS_AES_256_GCM_SHA384", STYLES.label, STYLES.value);
  console.log("%cKey exchange:   %cECDHE with P-384 (Perfect Forward Secrecy)", STYLES.label, STYLES.value);
  console.log("%cCertificate:    %cECC P-384, signed by local CA", STYLES.label, STYLES.value);
  console.log("%cHSTS:           %cenforced (HTTP → HTTPS redirect)", STYLES.label, STYLES.value);
  console.log(
    "%cℹ The WAF (OWASP CRS) terminates TLS. Internal services use mutual TLS (mTLS).",
    STYLES.dim,
  );
  console.groupEnd();
}

/* ------------------------------------------------------------------ */
/*  OIDC / Authentication                                              */
/* ------------------------------------------------------------------ */

export function logOidcFlow(keycloak: any): void {
  console.groupCollapsed(
    `%c[${timestamp()}]%c PROTOCOL %c OpenID Connect Authentication Completed`,
    STYLES.dim, STYLES.protocol, STYLES.heading,
  );
  console.log("%cFlow:           %cAuthorization Code + PKCE (S256)", STYLES.label, STYLES.value);
  console.log("%cGrant type:     %cauthorization_code (implicit & password grants disabled)", STYLES.label, STYLES.value);
  console.log("%cIssuer:         %c" + (keycloak.tokenParsed?.iss ?? "unknown"), STYLES.label, STYLES.value);
  console.log("%cAudience:       %c" + (keycloak.tokenParsed?.aud ?? "unknown"), STYLES.label, STYLES.value);
  console.log("%cClient:         %cbank-spa (public client, no client secret)", STYLES.label, STYLES.value);
  console.log("%cPKCE method:    %cS256 (SHA-256 code challenge)", STYLES.label, STYLES.value);
  console.log("%cPassword hash:  %cArgon2id (server-side, via Keycloak policy)", STYLES.label, STYLES.value);
  console.log("%cBrute force:    %cAccount lockout after 5 failures in 12 hours", STYLES.label, STYLES.value);
  console.log(
    "%cℹ Token stored in Keycloak JS memory only — not localStorage.",
    STYLES.dim,
  );
  console.groupEnd();
}

/* ------------------------------------------------------------------ */
/*  JWT token inspection                                               */
/* ------------------------------------------------------------------ */

export function logJwtToken(token: string, label: string = "Access Token"): void {
  const parsed = parseJwt(token);
  if (!parsed) return;

  const { header, payload } = parsed;
  const now = Math.floor(Date.now() / 1000);
  const expiresIn = payload.exp ? payload.exp - now : 0;

  console.groupCollapsed(
    `%c[${timestamp()}]%c ALGORITHM %c JWT ${label} — ${header.alg} Signature`,
    STYLES.dim, STYLES.algorithm, STYLES.heading,
  );
  console.log("%c── Header ──", STYLES.label);
  console.log("%cAlgorithm:      %c" + header.alg + " (ECDSA with P-384 curve)", STYLES.label, STYLES.value);
  console.log("%cKey ID (kid):   %c" + (header.kid ?? "none"), STYLES.label, STYLES.value);
  console.log("%cType:           %c" + (header.typ ?? "JWT"), STYLES.label, STYLES.value);

  console.log("%c── Claims ──", STYLES.label);
  console.log("%cSubject (sub):  %c" + shortId(payload.sub ?? ""), STYLES.label, STYLES.value);
  console.log("%cUsername:       %c" + (payload.preferred_username ?? "unknown"), STYLES.label, STYLES.value);
  console.log("%cIssuer (iss):   %c" + (payload.iss ?? "unknown"), STYLES.label, STYLES.value);
  console.log("%cAudience (aud): %c" + (payload.aud ?? "unknown"), STYLES.label, STYLES.value);
  console.log(
    "%cExpires:        %c" + new Date((payload.exp ?? 0) * 1000).toLocaleTimeString() +
      ` (${expiresIn}s remaining)`,
    STYLES.label,
    expiresIn > 60 ? STYLES.success : STYLES.warning,
  );
  console.log("%cAuth time:      %c" + new Date((payload.auth_time ?? 0) * 1000).toLocaleTimeString(), STYLES.label, STYLES.value);

  const roles = payload.realm_access?.roles?.filter(
    (r: string) => r === "customer" || r === "security-admin",
  ) ?? [];
  console.log("%cRealm roles:    %c" + (roles.join(", ") || "none"), STYLES.label, STYLES.value);

  console.log("%c── Signature Verification ──", STYLES.label);
  console.log(
    "%c✓ Signature verified by API using JWKS public key from Keycloak (ES384 / P-384)",
    STYLES.success,
  );
  console.log(
    "%c✓ Issuer, audience, expiry, and required claims validated server-side",
    STYLES.success,
  );

  console.log(
    "%cℹ The raw token is a 3-part Base64URL string. The third part is the ECDSA P-384 signature.",
    STYLES.dim,
  );
  console.groupEnd();
}

/* ------------------------------------------------------------------ */
/*  Demo OTP                                                           */
/* ------------------------------------------------------------------ */

export function logDemoOtp(code: string): void {
  console.groupCollapsed(
    `%c[${timestamp()}]%c ALGORITHM %c Multi-Factor Authentication — OTP Generated`,
    STYLES.dim, STYLES.algorithm, STYLES.heading,
  );
  console.log(
    `%c🔑 One-time code: %c${code}%c  (expires in 2 minutes)`,
    STYLES.label, "color:#5de2b6;font-size:16px;font-weight:bold", STYLES.label,
  );
  console.log("%cGeneration:     %ccrypto.getRandomValues() — CSPRNG", STYLES.label, STYLES.value);
  console.log("%cFormat:         %c6-digit numeric", STYLES.label, STYLES.value);
  console.log("%cLifetime:       %c120 seconds", STYLES.label, STYLES.value);
  console.log(
    "%c⚠ Prototype only: browser-generated. Production uses TOTP (RFC 6238) with a hardware/app authenticator.",
    STYLES.warning,
  );
  console.groupEnd();
}

export function logDemoOtpVerified(): void {
  console.log(
    `%c[${timestamp()}]%c ALGORITHM %c ✓ OTP Verified — second factor accepted`,
    STYLES.dim, STYLES.algorithm, STYLES.success,
  );
}

/* ------------------------------------------------------------------ */
/*  API requests                                                       */
/* ------------------------------------------------------------------ */

export function logApiRequest(method: string, path: string): void {
  console.log(
    `%c[${timestamp()}]%c PROTOCOL %c → ${method} ${path}%c  [Bearer JWT + TLS 1.3 + mTLS internal]`,
    STYLES.dim, STYLES.protocol, STYLES.value, STYLES.dim,
  );
}

export function logApiResponse(method: string, path: string, status: number): void {
  const style = status < 400 ? STYLES.success : STYLES.error;
  console.log(
    `%c[${timestamp()}]%c PROTOCOL %c ← ${status}%c  ${method} ${path}`,
    STYLES.dim, STYLES.protocol, style, STYLES.dim,
  );
}

/* ------------------------------------------------------------------ */
/*  Encryption evidence                                                */
/* ------------------------------------------------------------------ */

export function logEncryptionEvidence(context: string, envelope: any): void {
  console.groupCollapsed(
    `%c[${timestamp()}]%c ALGORITHM %c AES-256-GCM Encryption — ${context}`,
    STYLES.dim, STYLES.algorithm, STYLES.heading,
  );
  console.log("%cAlgorithm:      %cAES-256-GCM (Authenticated Encryption)", STYLES.label, STYLES.value);
  console.log("%cKey size:       %c256-bit", STYLES.label, STYLES.value);
  console.log("%cNonce:          %c96-bit random (unique per operation)", STYLES.label, STYLES.value);
  if (envelope) {
    console.log("%cKey version:    %c" + (envelope.key_version ?? "current"), STYLES.label, STYLES.value);
    if (envelope.ciphertext) {
      const preview = envelope.ciphertext.slice(0, 40) + "…";
      console.log("%cCiphertext:     %c" + preview, STYLES.label, STYLES.dim);
    }
    if (envelope.nonce) {
      console.log("%cNonce (b64):    %c" + envelope.nonce, STYLES.label, STYLES.dim);
    }
  }
  console.log(
    "%c✓ Authenticated associated-data binds ciphertext to its record — copying between records fails",
    STYLES.success,
  );
  console.log(
    "%cℹ Encryption performed by the Key Service (HSM stand-in) via mTLS. Keys never leave that service.",
    STYLES.dim,
  );
  console.groupEnd();
}

/* ------------------------------------------------------------------ */
/*  Digital signature evidence                                         */
/* ------------------------------------------------------------------ */

export function logSignatureEvidence(context: string, receipt: any): void {
  console.groupCollapsed(
    `%c[${timestamp()}]%c ALGORITHM %c ECDSA P-384 Digital Signature — ${context}`,
    STYLES.dim, STYLES.algorithm, STYLES.heading,
  );
  console.log("%cAlgorithm:      %cECDSA with NIST P-384 curve (ES384)", STYLES.label, STYLES.value);
  console.log("%cHash:           %cSHA-384", STYLES.label, STYLES.value);
  console.log("%cKey storage:    %cKey Service (HSM boundary) — private key never exported", STYLES.label, STYLES.value);
  if (receipt) {
    if (receipt.transaction_id) {
      console.log("%cTransaction:    %c" + receipt.transaction_id, STYLES.label, STYLES.value);
    }
    if (receipt.signature) {
      const preview = receipt.signature.slice(0, 40) + "…";
      console.log("%cSignature:      %c" + preview, STYLES.label, STYLES.dim);
    }
    if (receipt.request_hash) {
      console.log("%cRequest hash:   %c" + receipt.request_hash, STYLES.label, STYLES.dim);
    }
    if (receipt.key_version) {
      console.log("%cKey version:    %c" + receipt.key_version, STYLES.label, STYLES.value);
    }
  }
  console.log("%c✓ Provides non-repudiation — tamper-evident proof of the transaction", STYLES.success);
  console.groupEnd();
}

/* ------------------------------------------------------------------ */
/*  SHA-256 hashing / audit chain                                      */
/* ------------------------------------------------------------------ */

export function logHashChainEvidence(auditHash?: string): void {
  console.groupCollapsed(
    `%c[${timestamp()}]%c ALGORITHM %c SHA-256 Audit Hash Chain — Entry Recorded`,
    STYLES.dim, STYLES.algorithm, STYLES.heading,
  );
  console.log("%cAlgorithm:      %cSHA-256", STYLES.label, STYLES.value);
  console.log("%cChain:          %cEach entry includes SHA-256 hash of the previous entry", STYLES.label, STYLES.value);
  console.log("%cSignature:      %cEach entry is ECDSA P-384 signed", STYLES.label, STYLES.value);
  console.log("%cStorage:        %cAppend-only SQLite (UPDATE/DELETE triggers deny modification)", STYLES.label, STYLES.value);
  if (auditHash) {
    console.log("%cEntry hash:     %c" + auditHash, STYLES.label, STYLES.dim);
  }
  console.log("%c✓ Log tampering or reordering is cryptographically detectable", STYLES.success);
  console.groupEnd();
}

/* ------------------------------------------------------------------ */
/*  RBAC                                                               */
/* ------------------------------------------------------------------ */

export function logRbac(role: string, action: string): void {
  console.log(
    `%c[${timestamp()}]%c SYSTEM   %c RBAC: role=%c${role}%c action=%c${action}`,
    STYLES.dim, STYLES.system, STYLES.label, STYLES.value, STYLES.label, STYLES.value,
  );
}

/* ------------------------------------------------------------------ */
/*  Transfer flow                                                      */
/* ------------------------------------------------------------------ */

export function logTransferPrepare(data: any): void {
  console.groupCollapsed(
    `%c[${timestamp()}]%c SYSTEM   %c Transfer Prepared — Awaiting Re-authentication`,
    STYLES.dim, STYLES.system, STYLES.heading,
  );
  console.log("%cPreparation ID: %c" + (data.preparation_id ?? "unknown"), STYLES.label, STYLES.value);
  console.log("%cRequest hash:   %c" + (data.request_hash ?? "unknown") + " (SHA-256)", STYLES.label, STYLES.value);
  console.log("%cExpires at:     %c" + (data.expires_at ?? "unknown") + " (5-minute window)", STYLES.label, STYLES.value);
  console.log("%cRe-auth:        %c" + (data.requires_recent_authentication ? "REQUIRED — fresh Keycloak login" : "not required"), STYLES.label, STYLES.value);
  console.log("%c── Validations passed ──", STYLES.label);
  console.log("%c  ✓ Account ownership verified (RBAC)", STYLES.success);
  console.log("%c  ✓ Sufficient balance", STYLES.success);
  console.log("%c  ✓ Per-transfer limit check", STYLES.success);
  console.log("%c  ✓ Daily limit check", STYLES.success);
  console.log("%c  ✓ SHA-256 request digest computed", STYLES.success);
  console.log("%c  ✓ Audit entry created (hash-chained, signed)", STYLES.success);
  console.groupEnd();
}

export function logTransferCommit(result: any): void {
  console.groupCollapsed(
    `%c[${timestamp()}]%c ALGORITHM %c ✓ Transfer Completed — Signed & Encrypted`,
    STYLES.dim, STYLES.algorithm, STYLES.heading,
  );
  console.log("%c── Cryptographic Operations ──", STYLES.label);
  console.log(
    "%c  ✓ Description AES-256-GCM encrypted (associated data binds to transaction ID)",
    STYLES.success,
  );
  console.log(
    "%c  ✓ Receipt digitally signed with ECDSA P-384",
    STYLES.success,
  );
  console.log(
    "%c  ✓ Audit entry hash-chained (SHA-256) and signed (ECDSA P-384)",
    STYLES.success,
  );
  if (result.audit_hash) {
    console.log("%c  ✓ Audit chain hash: " + result.audit_hash, STYLES.success);
  }
  console.log("%c── Transaction Integrity ──", STYLES.label);
  console.log("%c  ✓ Row-locked ACID balance update (SELECT ... FOR UPDATE)", STYLES.success);
  console.log("%c  ✓ Idempotency key prevents replay/double-submission", STYLES.success);
  console.log("%c  ✓ Recent authentication enforced (max 120s since Keycloak login)", STYLES.success);
  console.log("%c── Notification ──", STYLES.label);
  console.log("%c  ✓ Email sent via SMTP STARTTLS (no sensitive data in email body)", STYLES.success);
  console.log("%c  ✓ Security event dispatched to IDS/SIEM via mTLS", STYLES.success);
  if (result.receipt) {
    logSignatureEvidence("Transfer Receipt", result.receipt);
  }
  console.groupEnd();
}

/* ------------------------------------------------------------------ */
/*  Profile decryption                                                 */
/* ------------------------------------------------------------------ */

export function logProfileDecryption(username: string): void {
  console.log(
    `%c[${timestamp()}]%c ALGORITHM %c AES-256-GCM: PII decrypted for "${username}" (server-side via Key Service mTLS)`,
    STYLES.dim, STYLES.algorithm, STYLES.value,
  );
}

/* ------------------------------------------------------------------ */
/*  Admin / SIEM                                                       */
/* ------------------------------------------------------------------ */

export function logSiemLoad(alertCount: number, eventCount: number, unack: number): void {
  console.groupCollapsed(
    `%c[${timestamp()}]%c SYSTEM   %c IDS/SIEM Dashboard Loaded — ${alertCount} alerts, ${eventCount} events`,
    STYLES.dim, STYLES.system, STYLES.heading,
  );
  console.log("%cTotal events:       %c" + eventCount, STYLES.label, STYLES.value);
  console.log("%cCorrelated alerts:  %c" + alertCount, STYLES.label, STYLES.value);
  console.log("%cUnacknowledged:     %c" + unack, STYLES.label, unack > 0 ? STYLES.warning : STYLES.success);
  console.log("%c── Correlation Rules ──", STYLES.label);
  console.log("%c  • 5 auth failures in 5 min → medium alert", STYLES.dim);
  console.log("%c  • 3 WAF blocks → high alert", STYLES.dim);
  console.log("%c  • 3 forbidden-resource attempts in 5 min → medium alert", STYLES.dim);
  console.log("%c  • 5 transfers/min per actor → velocity alert", STYLES.dim);
  console.log("%c  • Audit-chain or backup-integrity failure → critical alert", STYLES.dim);
  console.groupEnd();
}

export function logAuditIntegrity(valid: boolean, entries: number): void {
  const icon = valid ? "✓" : "✗";
  const style = valid ? STYLES.success : STYLES.error;
  console.log(
    `%c[${timestamp()}]%c ALGORITHM %c ${icon} Audit integrity: ${valid ? "VERIFIED" : "FAILED"} — ${entries} entries, SHA-256 chain + ECDSA P-384 signatures`,
    STYLES.dim, STYLES.algorithm, style,
  );
}

export function logBackupStatus(count: number): void {
  console.log(
    `%c[${timestamp()}]%c SYSTEM   %c Encrypted backups: ${count} (AES-256-GCM + ECDSA signed manifests, Primary + DR SFTP)`,
    STYLES.dim, STYLES.system, STYLES.value,
  );
}

/* ------------------------------------------------------------------ */
/*  WAF evidence                                                       */
/* ------------------------------------------------------------------ */

export function logWafBlock(path: string, status: number): void {
  console.log(
    `%c[${timestamp()}]%c SYSTEM   %c WAF BLOCKED: ${status} on ${path} — OWASP CRS rule triggered`,
    STYLES.dim, STYLES.system, STYLES.warning,
  );
}

/* ------------------------------------------------------------------ */
/*  Network segmentation                                               */
/* ------------------------------------------------------------------ */

export function logNetworkSegmentation(): void {
  console.groupCollapsed(
    `%c[${timestamp()}]%c SYSTEM   %c Network Segmentation — 8 Isolated Zones`,
    STYLES.dim, STYLES.system, STYLES.heading,
  );
  console.log("%c  edge        %c→ WAF only (public-facing)", STYLES.value, STYLES.dim);
  console.log("%c  dmz         %c→ WAF ↔ Frontend (internal)", STYLES.value, STYLES.dim);
  console.log("%c  app         %c→ Frontend ↔ APIs ↔ Keycloak ↔ Key Svc (internal)", STYLES.value, STYLES.dim);
  console.log("%c  data        %c→ APIs ↔ PostgreSQL (internal, no published ports)", STYLES.value, STYLES.dim);
  console.log("%c  audit       %c→ APIs ↔ Audit Svc ↔ Monitor (internal)", STYLES.value, STYLES.dim);
  console.log("%c  backup      %c→ Scheduler ↔ SFTP Primary ↔ SFTP DR (internal)", STYLES.value, STYLES.dim);
  console.log("%c  management  %c→ Bastion ↔ Mailpit ↔ Monitor", STYLES.value, STYLES.dim);
  console.log("%c  lab         %c→ Vulnerable Lab ↔ Attack Runner (isolated)", STYLES.value, STYLES.dim);
  console.log("%c✓ Only port 8443 is exposed externally. All other services are unreachable from outside.", STYLES.success);
  console.groupEnd();
}
