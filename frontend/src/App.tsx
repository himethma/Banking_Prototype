import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import type Keycloak from "keycloak-js";
import {
  Activity,
  ArrowRight,
  BadgeCheck,
  Banknote,
  FileKey,
  Fingerprint,
  LockKeyhole,
  LogOut,
  RefreshCw,
  ShieldCheck,
  Siren,
  UserRound,
} from "lucide-react";

type Account = {
  id: string;
  account_number: string;
  masked_account_number: string;
  currency: string;
  balance_minor: number;
};
type Profile = { full_name: string; username: string; email: string; roles: string[] };
type Alert = { id: string; severity: string; title: string; actor: string; created_at: string; acknowledged: number };
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
    console.log(
      `%c[Secure Bank prototype] One-time code: ${code} (expires in 2 minutes)`,
      "color: #5de2b6; font-size: 16px; font-weight: bold",
    );
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
  }

  const api = useCallback(
    async (path: string, init: RequestInit = {}) => {
      await keycloak.updateToken(30);
      const response = await fetch(path, {
        ...init,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${keycloak.token}`,
          ...(init.headers ?? {}),
        },
      });
      if (!response.ok) {
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
      if (isCustomer) setAccounts(await api("/api/v1/accounts"));
      if (isAdmin) {
        const [nextAlerts, nextSummary, nextControls, nextBackups] = await Promise.all([
          api("/api/v1/admin/alerts"),
          api("/api/v1/admin/security-summary"),
          api("/api/v1/admin/controls"),
          api("/api/v1/admin/backups"),
        ]);
        setAlerts(nextAlerts);
        setSummary(nextSummary);
        setControls(nextControls);
        setBackups(nextBackups);
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
              <article className="panel">
                <div className="panel-title"><div><p className="eyebrow">PAYMENTS</p><h2>Make a secure transfer</h2></div><Banknote /></div>
                <form onSubmit={beginTransfer}>
                  <label>From<input value={accounts[0]?.masked_account_number ?? "Loading account…"} disabled /></label>
                  <label>Destination account<input value={destination} onChange={(e) => setDestination(e.target.value)} inputMode="numeric" required /></label>
                  <div className="field-row"><label>Amount (LKR)<input value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" required /></label><label>Reference<input value={description} onChange={(e) => setDescription(e.target.value)} maxLength={140} /></label></div>
                  <div className="step-up"><Fingerprint /><span><strong>Fresh authentication required</strong>You will re-enter your password before balances change.</span></div>
                  <button className="primary" disabled={busy}>{busy ? <RefreshCw className="spin" /> : <ArrowRight />} Prepare and verify</button>
                </form>
              </article>
              <article className="panel evidence">
                <div className="panel-title"><div><p className="eyebrow">LIVE EVIDENCE</p><h2>Your protection</h2></div><FileKey /></div>
                {["Argon2id password + prototype console OTP", "AES-256-GCM encrypted customer data", "ES384 signed tokens and receipts", "Idempotent, row-locked transfers", "Immutable SHA-256 audit chain"].map((item) => <div className="evidence-row" key={item}><BadgeCheck />{item}</div>)}
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
              <article className="panel"><div className="panel-title"><div><p className="eyebrow">IDS / SIEM</p><h2>Correlated alerts</h2></div><button className="icon" onClick={load}><RefreshCw /></button></div><div className="alert-list">{alerts.length === 0 ? <div className="empty">No correlated alerts yet. Run the isolated attack lab to generate evidence.</div> : alerts.map((alert) => <div className="alert-row" key={alert.id}><span className={`severity ${alert.severity}`}>{alert.severity}</span><div><strong>{alert.title}</strong><small>{alert.actor} · {new Date(alert.created_at).toLocaleString()}</small></div></div>)}</div></article>
              <article className="panel"><div className="panel-title"><div><p className="eyebrow">TRUST CONTROLS</p><h2>Implementation coverage</h2></div><ShieldCheck /></div>{controls && ["algorithm", "protocol", "system"].map((group) => <div className="control-group" key={group}><h3>{group}</h3>{controls[group].map((item: string) => <div className="evidence-row" key={item}><BadgeCheck />{item}</div>)}</div>)}</article>
            </section>
            <section className="panel lab-panel"><div><p className="eyebrow">ISOLATED SECURITY LAB</p><h2>Secure versus vulnerable evidence</h2><p>The lab is disabled in normal operation and uses a separate network, synthetic database, and no banking secrets.</p></div><code>docker compose --profile lab run --rm attack-runner</code></section>
          </>
        )}
      </main>
      <footer><span><LockKeyhole size={14} /> TLS 1.3 secure session</span><span>Coursework prototype · Synthetic data only</span></footer>
    </div>
  );
}
