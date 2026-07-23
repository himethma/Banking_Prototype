import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import type Keycloak from "keycloak-js";
import {
  Activity,
  ArrowLeftRight,
  ArrowRight,
  BadgeCheck,
  Banknote,
  FileKey,
  Fingerprint,
  LockKeyhole,
  LogOut,
  Radio,
  RefreshCw,
  ScrollText,
  ShieldCheck,
  Siren,
  UserRound,
  Users,
} from "lucide-react";
import {
  logApiRequest,
  logApiResponse,
  logAuditIntegrity,
  logBackupStatus,
  logBanner,
  logDemoOtp,
  logDemoOtpVerified,
  logEncryptionEvidence,
  logHashChainEvidence,
  logJwtToken,
  logNetworkSegmentation,
  logOidcFlow,
  logProfileDecryption,
  logRbac,
  logSignatureEvidence,
  logSiemLoad,
  logTlsConnection,
  logTransferCommit,
  logTransferPrepare,
  logWafBlock,
} from "./securityConsole";

type Account = {
  id: string;
  account_number: string;
  masked_account_number: string;
  currency: string;
  balance_minor: number;
};
type Profile = { full_name: string; username: string; email: string; roles: string[] };
type Alert = { id: string; severity: string; title: string; actor: string; created_at: string; acknowledged: number };
type AdminTransfer = { id: string; source_account: string; destination_account: string; amount_minor: number; currency: string; request_hash: string; created_at: string };
type AdminUser = { subject: string; username: string; account_count: number; created_at: string };
type AuditEntry = { sequence: number; id: string; occurred_at: string; actor: string; action: string; outcome: string; details: string; entry_hash: string };
type SecurityEvent = { id: string; occurred_at: string; event_type: string; actor: string; source_ip: string; details: string };
type Props = { keycloak: Keycloak };

function money(minor: number) {
  return new Intl.NumberFormat("en-LK", { style: "currency", currency: "LKR" }).format(minor / 100);
}

export default function App({ keycloak }: Props) {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [controls, setControls] = useState<any>(null);
  const [backups, setBackups] = useState<any[]>([]);
  const [adminTransfers, setAdminTransfers] = useState<AdminTransfer[]>([]);
  const [adminUsers, setAdminUsers] = useState<AdminUser[]>([]);
  const [auditLog, setAuditLog] = useState<AuditEntry[]>([]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([]);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [destination, setDestination] = useState("100000000002");
  const [amount, setAmount] = useState("1000.00");
  const [description, setDescription] = useState("Secure prototype transfer");
  const [demoOtp, setDemoOtp] = useState("");
  const [demoOtpInput, setDemoOtpInput] = useState("");
  const [demoOtpExpiresAt, setDemoOtpExpiresAt] = useState(0);
  const [demoOtpVerified, setDemoOtpVerified] = useState(false);
  const [demoOtpError, setDemoOtpError] = useState("");
  const demoOtpIssued = useRef(false);
  const sessionLogged = useRef(false);

  const roles = useMemo(() => new Set(keycloak.realmAccess?.roles ?? []), [keycloak.realmAccess]);
  const isCustomer = roles.has("customer");
  const isAdmin = roles.has("security-admin");

  const issueDemoOtp = useCallback(() => {
    const randomValue = crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000;
    const code = randomValue.toString().padStart(6, "0");
    const expiresAt = Date.now() + 2 * 60 * 1000;
    setDemoOtp(code);
    setDemoOtpExpiresAt(expiresAt);
    setDemoOtpInput("");
    setDemoOtpError("");
    logDemoOtp(code);
  }, []);

  useEffect(() => {
    if (!keycloak.authenticated || demoOtpVerified || demoOtpIssued.current) return;
    demoOtpIssued.current = true;
    issueDemoOtp();
  }, [demoOtpVerified, issueDemoOtp, keycloak.authenticated]);

  function verifyDemoOtp(event: FormEvent) {
    event.preventDefault();
    if (!demoOtp || Date.now() > demoOtpExpiresAt) {
      setDemoOtpError("That code has expired. Generate a new demonstration code.");
      return;
    }
    if (demoOtpInput.trim() !== demoOtp) {
      setDemoOtpError("The demonstration code is incorrect.");
      return;
    }
    setDemoOtpVerified(true);
    setDemoOtp("");
    setDemoOtpInput("");
    setDemoOtpError("");
    logDemoOtpVerified();
  }

  useEffect(() => {
    if (!demoOtpVerified || !keycloak.authenticated || sessionLogged.current) return;
    sessionLogged.current = true;
    logBanner();
    logTlsConnection();
    logNetworkSegmentation();
    logOidcFlow(keycloak);
    if (keycloak.token) logJwtToken(keycloak.token, "Access Token");
  }, [demoOtpVerified, keycloak]);

  const api = useCallback(
    async (path: string, init: RequestInit = {}) => {
      await keycloak.updateToken(30);
      const method = (init.method ?? "GET").toUpperCase();
      logApiRequest(method, path);
      const response = await fetch(path, {
        ...init,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${keycloak.token}`,
          ...(init.headers ?? {}),
        },
      });
      logApiResponse(method, path, response.status);
      if (!response.ok) {
        if (response.status === 403) logWafBlock(path, response.status);
        const body = await response.json().catch(() => ({ detail: "Request failed" }));
        throw new Error(body.detail ?? body.title ?? "Request failed");
      }
      return response.json();
    },
    [keycloak],
  );

  const load = useCallback(async () => {
    if (!keycloak.authenticated || !demoOtpVerified) return;
    try {
      const me = await api("/api/v1/me");
      setProfile(me);
      logProfileDecryption(me.username);
      logRbac(me.roles.join(", ") || "none", "dashboard.load");
      if (isCustomer) {
        const accts = await api("/api/v1/accounts");
        setAccounts(accts);
        logRbac("customer", "accounts.list");
      }
      if (isAdmin) {
        logRbac("security-admin", "admin.dashboard");
        const [nextAlerts, nextSummary, nextControls, nextBackups, nextTransfers, nextUsers, nextAudit, nextEvents] = await Promise.all([
          api("/api/v1/admin/alerts"),
          api("/api/v1/admin/security-summary"),
          api("/api/v1/admin/controls"),
          api("/api/v1/admin/backups"),
          api("/api/v1/admin/transfers"),
          api("/api/v1/admin/users"),
          api("/api/v1/admin/audit"),
          api("/api/v1/admin/events"),
        ]);
        setAlerts(nextAlerts);
        setSummary(nextSummary);
        setControls(nextControls);
        setBackups(nextBackups);
        setAdminTransfers(nextTransfers);
        setAdminUsers(nextUsers);
        setAuditLog(nextAudit);
        setSecurityEvents(nextEvents);
        logSiemLoad(
          nextAlerts.length,
          nextSummary?.monitor?.events ?? 0,
          nextSummary?.monitor?.unacknowledged ?? 0,
        );
        logAuditIntegrity(
          nextSummary?.audit?.valid ?? false,
          nextSummary?.audit?.entries ?? 0,
        );
        logBackupStatus(nextBackups.length);
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to load dashboard");
    }
  }, [api, demoOtpVerified, isAdmin, isCustomer, keycloak.authenticated]);

  useEffect(() => void load(), [load]);

  useEffect(() => {
    const preparationId = new URLSearchParams(window.location.search).get("commit");
    if (!preparationId || !keycloak.authenticated || !demoOtpVerified || !isCustomer) return;
    window.history.replaceState({}, "", "/");
    setBusy(true);
    api("/api/v1/transfers/commit", {
      method: "POST",
      headers: { "Idempotency-Key": crypto.randomUUID() + crypto.randomUUID() },
      body: JSON.stringify({ preparation_id: preparationId }),
    })
      .then((result) => {
        logTransferCommit(result);
        if (result.receipt) {
          logSignatureEvidence("Transfer Receipt", result.receipt);
          if (result.receipt.encrypted_description) {
            logEncryptionEvidence("Transfer Description", result.receipt.encrypted_description);
          }
        }
        if (result.audit_hash) logHashChainEvidence(result.audit_hash);
        setMessage(`Transfer completed. Signed receipt: ${result.receipt.transaction_id}`);
        return load();
      })
      .catch((reason) => setError(reason.message))
      .finally(() => setBusy(false));
  }, [api, demoOtpVerified, isCustomer, keycloak.authenticated, load]);

  async function beginTransfer(event: FormEvent) {
    event.preventDefault();
    if (!accounts[0]) return;
    setBusy(true);
    setError("");
    try {
      const prepared = await api("/api/v1/transfers/prepare", {
        method: "POST",
        body: JSON.stringify({
          source_account_id: accounts[0].id,
          destination_account_number: destination,
          amount_minor: Math.round(Number(amount) * 100),
          currency: "LKR",
          description,
        }),
      });
      logTransferPrepare(prepared);
      await keycloak.login({
        prompt: "login",
        maxAge: 0,
        redirectUri: `${window.location.origin}/?commit=${prepared.preparation_id}`,
      });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Transfer preparation failed");
      setBusy(false);
    }
  }

  if (!keycloak.authenticated) {
    return (
      <main className="login-shell">
        <section className="login-card">
          <div className="brand-mark"><ShieldCheck size={34} /></div>
          <p className="eyebrow">SECURE BANKING LAB</p>
          <h1>Banking built around trust boundaries.</h1>
          <p className="lead">Sign in through OpenID Connect with PKCE and an Argon2id-protected password. A demonstration code is issued after login.</p>
          <button className="primary" onClick={() => keycloak.login()}><Fingerprint size={19} /> Secure sign in</button>
          <div className="trust-row"><span>TLS 1.3</span><span>ES384</span><span>OWASP CRS</span></div>
        </section>
      </main>
    );
  }

  if (!demoOtpVerified) {
    return (
      <main className="login-shell">
        <section className="login-card">
          <div className="brand-mark"><Fingerprint size={34} /></div>
          <p className="eyebrow">PROTOTYPE VERIFICATION</p>
          <h1>Enter the demonstration code.</h1>
          <p className="lead">Open the browser developer tools and select <strong>Console</strong>. Copy the six-digit Secure Bank prototype code printed there.</p>
          {demoOtpError && <div className="notice error">{demoOtpError}</div>}
          <form onSubmit={verifyDemoOtp}>
            <label htmlFor="demo-otp">One-time code
              <input
                id="demo-otp"
                value={demoOtpInput}
                onChange={(event) => setDemoOtpInput(event.target.value.replace(/\D/g, "").slice(0, 6))}
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6}"
                maxLength={6}
                required
                autoFocus
              />
            </label>
            <button className="primary" type="submit"><ShieldCheck size={19} /> Verify code</button>
            <button className="secondary" type="button" onClick={issueDemoOtp}>Generate a new code</button>
          </form>
          <p className="prototype-warning">Demonstration only: the browser generates and verifies this code. Production systems must use a server-side or hardware-backed second factor.</p>
        </section>
      </main>
    );
  }

  return (
    <div className="app-shell">
      <header>
        <div className="brand"><ShieldCheck /><span>Secure Bank</span><em>Prototype</em></div>
        <div className="identity"><div><strong>{profile?.full_name ?? keycloak.tokenParsed?.preferred_username}</strong><span>{isAdmin ? "Security administrator" : "Customer"}</span></div><button className="icon" aria-label="Log out" onClick={() => keycloak.logout({ redirectUri: window.location.origin })}><LogOut size={19} /></button></div>
      </header>
      <main>
        <section className="hero">
          <div><p className="eyebrow">{isAdmin ? "SECURITY OPERATIONS" : "PERSONAL BANKING"}</p><h1>{isAdmin ? "Control-room visibility." : `Good day, ${profile?.full_name?.split(" ")[0] ?? "customer"}.`}</h1><p>{isAdmin ? "Correlated alerts, signed audit evidence, and recovery controls in one view." : "Your account is protected at the algorithm, protocol, and system layers."}</p></div>
          <div className="posture"><BadgeCheck /><span><strong>Security posture</strong>All core controls operational</span></div>
        </section>
        {error && <div className="notice error">{error}<button onClick={() => setError("")}>Dismiss</button></div>}
        {message && <div className="notice success">{message}<button onClick={() => setMessage("")}>Dismiss</button></div>}

        {isCustomer && (
          <>
            <section className="account-grid">
              {accounts.map((account) => <article className="balance-card" key={account.id}><div className="card-top"><span>Everyday account</span><LockKeyhole size={18} /></div><strong>{money(account.balance_minor)}</strong><small>{account.masked_account_number} · {account.currency}</small></article>)}
              <article className="assurance-card"><ShieldCheck /><div><strong>Protected end to end</strong><span>AES-256-GCM at rest, TLS 1.3 in transit, signed audit evidence.</span></div></article>
            </section>
            <section className="content-grid">
              <article className="panel" style={{ gridColumn: "1 / -1" }}>
                <div className="panel-title"><div><p className="eyebrow">PAYMENTS</p><h2>Make a secure transfer</h2></div><Banknote /></div>
                <form onSubmit={beginTransfer}>
                  <label>From<input value={accounts[0]?.masked_account_number ?? "Loading account…"} disabled /></label>
                  <label>Destination account<input value={destination} onChange={(e) => setDestination(e.target.value)} inputMode="numeric" required /></label>
                  <div className="field-row"><label>Amount (LKR)<input value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" required /></label><label>Reference<input value={description} onChange={(e) => setDescription(e.target.value)} maxLength={140} /></label></div>
                  <div className="step-up"><Fingerprint /><span><strong>Fresh authentication required</strong>You will re-enter your password before balances change.</span></div>
                  <button className="primary" disabled={busy}>{busy ? <RefreshCw className="spin" /> : <ArrowRight />} Prepare and verify</button>
                </form>
              </article>
            </section>
          </>
        )}

        {isAdmin && (
          <>
            <section className="metric-grid">
              <article><Activity /><span>Security events</span><strong>{summary?.monitor?.events ?? 0}</strong></article>
              <article><Siren /><span>Open alerts</span><strong>{summary?.monitor?.unacknowledged ?? 0}</strong></article>
              <article><FileKey /><span>Audit entries</span><strong>{summary?.audit?.entries ?? 0}</strong></article>
              <article><BadgeCheck /><span>Audit integrity</span><strong className="status-word">{summary?.audit?.valid ? "VERIFIED" : "CHECK"}</strong></article>
              <article><FileKey /><span>Encrypted backups</span><strong>{backups.length}</strong></article>
            </section>
            <section className="content-grid admin-grid">
              <article className="panel" style={{ gridColumn: "1 / -1" }}><div className="panel-title"><div><p className="eyebrow">IDS / SIEM</p><h2>Correlated alerts</h2></div><button className="icon" onClick={load}><RefreshCw /></button></div><div className="alert-list">{alerts.length === 0 ? <div className="empty">No correlated alerts yet. Run the isolated attack lab to generate evidence.</div> : alerts.map((alert) => <div className="alert-row" key={alert.id}><span className={`severity ${alert.severity}`}>{alert.severity}</span><div><strong>{alert.title}</strong><small>{alert.actor} · {new Date(alert.created_at).toLocaleString()}</small></div></div>)}</div></article>
            </section>

            <section className="detail-grid">
              <article className="panel">
                <div className="panel-title"><div><p className="eyebrow">TRANSFERS</p><h2>Recent transfers</h2></div><ArrowLeftRight /></div>
                <div className="scroll-body">
                  {adminTransfers.length === 0 ? <div className="empty">No transfers recorded yet. Complete a transfer as a customer to see data here.</div> : (
                    <table className="admin-table">
                      <thead><tr><th>Time</th><th>Route</th><th>Amount</th><th>Txn ID</th></tr></thead>
                      <tbody>
                        {adminTransfers.map((t) => <tr key={t.id}>
                          <td>{new Date(t.created_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</td>
                          <td>{t.source_account}<span className="dir-arrow">→</span>{t.destination_account}</td>
                          <td className="amount">{money(t.amount_minor)}</td>
                          <td className="hash">{t.id.slice(0, 8)}…</td>
                        </tr>)}
                      </tbody>
                    </table>
                  )}
                </div>
              </article>

              <article className="panel">
                <div className="panel-title"><div><p className="eyebrow">DIRECTORY</p><h2>Registered users</h2></div><Users /></div>
                <div className="scroll-body">
                  {adminUsers.length === 0 ? <div className="empty">No users registered.</div> : adminUsers.map((u) => (
                    <div className="user-row" key={u.subject}>
                      <div className="user-avatar"><UserRound size={18} /></div>
                      <div className="user-info"><strong>{u.username}</strong><small>{u.subject.slice(0, 12)}…</small></div>
                      <div className="user-badge"><strong>{u.account_count}</strong>{u.account_count === 1 ? "account" : "accounts"}</div>
                    </div>
                  ))}
                </div>
              </article>
            </section>

            <section className="detail-grid">
              <article className="panel">
                <div className="panel-title"><div><p className="eyebrow">IMMUTABLE AUDIT</p><h2>Audit trail</h2></div><ScrollText /></div>
                <div className="scroll-body">
                  {auditLog.length === 0 ? <div className="empty">No audit entries yet.</div> : (
                    <ul className="event-feed">
                      {auditLog.map((entry) => (
                        <li className="event-item" key={entry.id}>
                          <div className="event-top">
                            <span className="seq-num">#{entry.sequence}</span>
                            <span className="tag outcome-success">{entry.action}</span>
                            <span style={{ color: "var(--ink)" }}>{entry.actor.slice(0, 12)}…</span>
                          </div>
                          <span className="hash">{entry.entry_hash.slice(0, 16)}…</span>
                          <div className="event-meta">{new Date(entry.occurred_at).toLocaleString()} · {entry.outcome}</div>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </article>

              <article className="panel">
                <div className="panel-title"><div><p className="eyebrow">IDS / SIEM</p><h2>Security events</h2></div><Radio /></div>
                <div className="scroll-body">
                  {securityEvents.length === 0 ? <div className="empty">No security events recorded yet.</div> : (
                    <ul className="event-feed">
                      {securityEvents.map((ev) => (
                        <li className="event-item" key={ev.id}>
                          <div className="event-top">
                            <span className={`tag type-${ev.event_type.split(".")[0]}`}>{ev.event_type}</span>
                            <span style={{ color: "var(--ink)" }}>{ev.actor === "anonymous" ? "system" : ev.actor.slice(0, 12) + "…"}</span>
                          </div>
                          <span className="hash">{ev.source_ip}</span>
                          <div className="event-meta">{new Date(ev.occurred_at).toLocaleString()}</div>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </article>
            </section>
          </>
        )}
      </main>
      <footer><span><LockKeyhole size={14} /> TLS 1.3 secure session</span><span>Coursework prototype · Synthetic data only</span></footer>
    </div>
  );
}
