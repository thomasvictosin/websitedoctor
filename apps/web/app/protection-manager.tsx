"use client";

import { useCallback, useEffect, useState } from "react";
import { useConfirm } from "./confirm-dialog";

type Measure = { id: string; title: string; enabled: boolean; verified: boolean | null; detail: string; reported: boolean };
type Alert = { id: string; category: string; title: string; body: string; createdAt: string };
type RunSummary = { id: string; status: string; createdAt: string; title: string; protection: boolean; steps: string[]; results: Array<{ status: string; message: string }> | null };
type Protection = {
  pending: RunSummary | null;
  latest: RunSummary | null;
  pluginVersion: string | null;
  supported: boolean;
  measures: Measure[];
  settings: { selfHealing: boolean; autoUpdates: boolean };
  alerts: Alert[];
};

const DESCRIPTIONS: Record<string, string> = {
  block_php_uploads: "Files in the uploads folder can never run as code. Stops the most common way attackers run dropped files.",
  protect_sensitive_files: "Denies direct access to wp-config.php, logs, backups, hidden files and PHP files inside wp-includes.",
  disable_file_editor: "Removes the built-in theme and plugin code editor, so a stolen admin login cannot edit code.",
  disable_xmlrpc: "Closes a common password-guessing and pingback route. Kept on automatically if Jetpack needs it.",
  block_user_enumeration: "Stops visitors from listing administrator usernames.",
  security_headers: "Stops content sniffing, framing by other sites and unneeded browser features.",
  verified_crawlers: "Blocks attack tools, and fake Googlebot/Bingbot on login, admin and API requests. Real search engines are verified and keep access.",
};

function measureState(measure: Measure) {
  if (!measure.enabled) return { label: "Off", tone: "off" };
  if (measure.verified === false) return { label: "Not effective on this server", tone: "warn" };
  if (measure.verified === true) return { label: "On · verified", tone: "on" };
  return { label: "On", tone: "on" };
}

/** Site protection: hardening measures, automatic responses and recent alerts. */
export function ProtectionManager({ websiteId, onNotice }: { websiteId: string; onNotice: (message: string) => void }) {
  const dialogs = useConfirm();
  const [data, setData] = useState<Protection | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [loadError, setLoadError] = useState("");

  const load = useCallback(async () => {
    try {
      const response = await fetch(`/api/sites/${websiteId}/protection`, { cache: "no-store" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "Could not load protection status.");
      setData(body);
      setLoadError("");
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "Could not load protection status.");
    }
  }, [websiteId]);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    if (!data?.pending) return;
    const timer = setInterval(() => void load(), 5_000);
    return () => clearInterval(timer);
  }, [data?.pending, load]);

  async function send(key: string, method: "POST" | "PUT", body: Record<string, unknown>, dialog?: { title: string; body: string; confirmLabel: string; danger?: boolean }) {
    if (dialog && !await dialogs.confirm(dialog)) return;
    setBusy(key);
    try {
      const response = await fetch(`/api/sites/${websiteId}/protection`, { method, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "The change could not be made.");
      onNotice(result.message ?? "Saved.");
      await load();
    } catch (error) {
      onNotice(error instanceof Error ? error.message : "The change could not be made.");
      await load();
    } finally {
      setBusy(null);
    }
  }

  if (!data) return <div className="detail-content"><h3>Protection</h3><p>{loadError || "Loading protection status…"}</p></div>;
  const off = data.measures.filter((measure) => !measure.enabled);
  const locked = Boolean(busy) || Boolean(data.pending) || !data.supported;
  const latestFailures = data.latest?.results?.filter((result) => result.status === "failed") ?? [];

  return (
    <div className="detail-content tab-stack">
      {data.pending && (
        <div className="progress-banner" role="status">
          <span className="spinner" aria-hidden="true" />
          <div>
            <strong>{data.pending.protection ? `Applying: ${data.pending.steps.join(" ")}` : `The site is working on “${data.pending.title}”`}</strong>
            <small>{data.pending.protection
              ? `Approved ${new Date(data.pending.createdAt).toLocaleTimeString()}. The site usually applies it within seconds and tests each rule; this list updates by itself.`
              : "The site handles one change at a time. Protection can be changed as soon as it finishes (usually within seconds); this page updates by itself."}</small>
          </div>
        </div>
      )}
      {!data.pending && latestFailures.length > 0 && (
        <div className="callout callout-warn" role="alert">
          <strong>The last protection change did not fully apply</strong>
          <ul>{latestFailures.map((result) => <li key={result.message}>{result.message}</li>)}</ul>
        </div>
      )}
      {!data.supported && (
        <div className="callout callout-warn" role="alert">
          <strong>Plugin update needed</strong>
          <p>Protection needs AI Website Doctor 0.5.0 or later on the site (it reports {data.pluginVersion ?? "an older version"}). Upload the new plugin ZIP with “Replace current with uploaded”, then select Collect and sync diagnostics.</p>
        </div>
      )}

      <section className="tab-section">
        <div className="tab-section-head">
          <div>
            <h3>Protection measures</h3>
            <p className="lead">Each measure is reversible. Rules that change .htaccess are tested on your server and removed again if they break the site.</p>
          </div>
          {off.length > 0 && (
            <button className="button primary" disabled={locked}
              onClick={() => send("recommended", "POST", { recommended: true, confirm: true }, {
                title: `Turn on ${off.length} protection measure(s)?`,
                body: `${off.map((measure) => measure.title).join(", ")}. Each one is reversible and tested on your server.`,
                confirmLabel: "Turn on protection",
              })}>
              {busy === "recommended" ? "Approving…" : `Turn on all recommended (${off.length})`}
            </button>
          )}
        </div>
        <div className="measure-list">
          {data.measures.map((measure) => {
            const state = measureState(measure);
            return (
              <div className="measure-row" key={measure.id}>
                <div className="measure-text">
                  <div className="measure-title"><strong>{measure.title}</strong><span className={`pill pill-${state.tone}`}>{state.label}</span></div>
                  <p>{DESCRIPTIONS[measure.id]}</p>
                  {measure.enabled && measure.detail && <small>{measure.detail}</small>}
                </div>
                <button className={`button measure-toggle ${measure.enabled ? "is-on" : ""}`} disabled={locked}
                  onClick={() => send(`measure:${measure.id}`, "POST", { measure: measure.id, state: measure.enabled ? "off" : "on", confirm: true }, {
                    title: `${measure.enabled ? "Turn off" : "Turn on"} protection: ${measure.title}?`,
                    body: measure.enabled ? "The site loses this protection until you turn it on again." : DESCRIPTIONS[measure.id],
                    confirmLabel: measure.enabled ? "Turn off" : "Turn on",
                    danger: measure.enabled,
                  })}>
                  {busy === `measure:${measure.id}` ? "Approving…" : measure.enabled ? "Turn off" : "Turn on"}
                </button>
              </div>
            );
          })}
        </div>
      </section>

      <section className="tab-section">
        <div className="tab-section-head">
          <div>
            <h3>Automatic responses</h3>
            <p className="lead">Alerts are emailed by your WordPress site to its administration email address (Settings → General).</p>
          </div>
        </div>
        <div className="measure-list">
          {([
            ["selfHealing", "Self-healing", "When new malware files appear, quarantine them, restore core files, remove injected .htaccess rules and reinstall tampered WordPress.org plugins automatically (at most 3 times a day), then alert you. Salts, users and plugin removal still wait for you."],
            ["autoUpdates", "Automatic plugin updates", "Once a day, update WordPress.org plugins, verified against the official checksums and rolled back automatically if the site breaks. Never while security findings are open."],
          ] as const).map(([key, title, description]) => (
            <div className="measure-row" key={key}>
              <div className="measure-text">
                <div className="measure-title"><strong>{title}</strong><span className={`pill pill-${data.settings[key] ? "on" : "off"}`}>{data.settings[key] ? "On" : "Off"}</span></div>
                <p>{description}</p>
              </div>
              <button className={`button measure-toggle ${data.settings[key] ? "is-on" : ""}`} disabled={Boolean(busy)}
                onClick={() => send(`setting:${key}`, "PUT", { [key]: !data.settings[key] }, data.settings[key] ? undefined : { title: `Turn on ${title.toLowerCase()}?`, body: description, confirmLabel: "Turn on" })}>
                {busy === `setting:${key}` ? "Saving…" : data.settings[key] ? "Turn off" : "Turn on"}
              </button>
            </div>
          ))}
        </div>
      </section>

      <section className="tab-section">
        <div className="tab-section-head"><div><h3>Recent alerts</h3><p className="lead">The last 7 days.</p></div></div>
        {data.alerts.length === 0 ? <p className="empty-note">No alerts in the last 7 days.</p> : (
          <div className="run-list">
            {data.alerts.map((alert) => (
              <article className="run-card" key={alert.id}>
                <div className="run-card-head"><div><strong>{alert.title}</strong><small>{new Date(alert.createdAt).toLocaleString()}</small></div></div>
                <details><summary>Details</summary><pre className="alert-body">{alert.body}</pre></details>
              </article>
            ))}
          </div>
        )}
      </section>
      {loadError && <p className="empty-note">{loadError}</p>}
    </div>
  );
}

type CloudflareState =
  | { connected: false; requiredPermissions: string[] }
  | { connected: true; zoneName: string; zoneStatus: string; plan: string; proxied: boolean; securityLevel: unknown; awdFirewallRules: number; otherFirewallRules: number; awdRateLimitRules: number; botFightMode: unknown; applied: { at: string; botFightMode: boolean; verified: boolean | null; verification: string } | null; requiredPermissions: string[] };

/** Edge protection through the owner's Cloudflare account. */
export function CloudflarePanel({ websiteId, onNotice }: { websiteId: string; onNotice: (message: string) => void }) {
  const dialogs = useConfirm();
  const [state, setState] = useState<CloudflareState | null>(null);
  const [token, setToken] = useState("");
  const [botFight, setBotFight] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [steps, setSteps] = useState<Array<{ step: string; ok: boolean; detail: string }>>([]);
  const [loadError, setLoadError] = useState("");

  const load = useCallback(async () => {
    try {
      const response = await fetch(`/api/sites/${websiteId}/cloudflare`, { cache: "no-store" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "Could not load the Cloudflare status.");
      setState(body);
      setLoadError("");
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "Could not load the Cloudflare status.");
    }
  }, [websiteId]);
  useEffect(() => { void load(); }, [load]);

  async function act(key: string, body: Record<string, unknown>, dialog?: { title: string; body: string; confirmLabel: string; danger?: boolean }) {
    if (dialog && !await dialogs.confirm(dialog)) return;
    setBusy(key);
    try {
      const response = await fetch(`/api/sites/${websiteId}/cloudflare`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "The Cloudflare change failed.");
      if (Array.isArray(result.steps)) setSteps(result.steps);
      onNotice(result.verification ?? (body.action === "connect" ? `Connected to the Cloudflare zone ${result.zoneName} (${result.status}).` : "Done."));
      setToken("");
      await load();
    } catch (error) {
      onNotice(error instanceof Error ? error.message : "The Cloudflare change failed.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="detail-content tab-stack cloudflare-tab">
      <section className="tab-section">
        <div className="tab-section-head">
          <div>
            <h3>Cloudflare edge protection</h3>
            <p className="lead">Cloudflare sits in front of your server, so these rules stop attack traffic before it reaches WordPress or any file on the server. The free plan is enough.</p>
          </div>
          {state?.connected && <span className={`pill pill-${state.proxied ? "on" : "warn"}`}>{state.proxied ? "Traffic passes through Cloudflare" : "Traffic not through Cloudflare yet"}</span>}
        </div>
        {!state ? <p className="empty-note">{loadError || "Loading…"}</p> : !state.connected ? (
          <>
            <ol className="step-list numbered">
              <li><span>Add the site to a free Cloudflare account and change the domain&apos;s nameservers (at your registrar) to the two Cloudflare gives you. Keep the DNS records proxied (orange cloud).</span></li>
              <li><span>In Cloudflare open My Profile → API Tokens → Create Token → Custom token, limited to this site&apos;s zone, with: {state.requiredPermissions.join("; ")}.</span></li>
              <li><span>Paste the token below. It is stored encrypted and never shown again.</span></li>
            </ol>
            <div className="inline-form">
              <input type="password" autoComplete="off" placeholder="Cloudflare API token" value={token} onChange={(event) => setToken(event.target.value)} disabled={Boolean(busy)} aria-label="Cloudflare API token" />
              <button className="button primary" disabled={Boolean(busy) || token.trim().length < 30} onClick={() => act("connect", { action: "connect", token })}>{busy === "connect" ? "Connecting…" : "Connect Cloudflare"}</button>
            </div>
          </>
        ) : (
          <>
            <div className="fact-grid">
              <div><small>ZONE</small><strong>{state.zoneName}</strong></div>
              <div><small>STATUS</small><strong>{state.zoneStatus}{state.plan ? ` · ${state.plan}` : ""}</strong></div>
              <div><small>APP RULES</small><strong>{state.awdFirewallRules ? `${state.awdFirewallRules} firewall · rate limit ${state.awdRateLimitRules ? "on" : "off"}` : "Not applied"}</strong></div>
              <div><small>BOT FIGHT MODE</small><strong>{state.botFightMode === true ? "On" : state.botFightMode === false ? "Off" : "Unknown"}</strong></div>
            </div>
            {state.otherFirewallRules > 0 && <p className="muted-meta">{state.otherFirewallRules} of your own Cloudflare rule(s) are kept untouched.</p>}
            {state.applied && <div className={`callout ${state.applied.verified ? "callout-ok" : "callout-warn"}`}><p>{state.applied.verification}</p></div>}
            <div className="check-list">
              <label>
                <input type="checkbox" checked={botFight} onChange={(event) => setBotFight(event.target.checked)} disabled={Boolean(busy)} />
                <span><strong>Also turn on Bot Fight Mode</strong> (optional). It challenges automated traffic site-wide, including this app&apos;s outside cloaking check, which then reports “inconclusive” instead of checking what Googlebot sees.</span>
              </label>
            </div>
            <div className="section-actions">
              <button className="button primary" disabled={Boolean(busy)}
                onClick={() => act("apply", { action: "apply", botFightMode: botFight, confirm: true }, {
                  title: "Apply Cloudflare protection?",
                  body: "Security level medium, HTTPS only, TLS 1.2+, browser integrity check, one firewall rule (PHP in uploads, sensitive files, fake crawlers on login/admin, attack tools), a login challenge and a login rate limit. Your own Cloudflare rules are kept.",
                  confirmLabel: "Apply protection",
                })}>
                {busy === "apply" ? "Applying…" : state.awdFirewallRules ? "Re-apply protection" : "Apply Cloudflare protection"}
              </button>
              {state.awdFirewallRules > 0 && (
                <button className="button ghost" disabled={Boolean(busy)}
                  onClick={() => act("remove", { action: "remove", confirm: true }, { title: "Remove the app's Cloudflare rules?", body: "Bot Fight Mode is turned off too. Your own rules are kept.", confirmLabel: "Remove rules", danger: true })}>
                  {busy === "remove" ? "Removing…" : "Remove app rules"}
                </button>
              )}
              <button className="button ghost danger-text" disabled={Boolean(busy)}
                onClick={() => act("disconnect", { action: "disconnect", confirm: true }, { title: "Disconnect Cloudflare?", body: "The stored token is deleted. Rules already applied stay in Cloudflare until you remove them.", confirmLabel: "Disconnect", danger: true })}>
                Disconnect
              </button>
            </div>
          </>
        )}
        {steps.length > 0 && (
          <ul className="step-list">{steps.map((step) => <li key={step.step}><span className={`pill ${step.ok ? "pill-on" : "pill-warn"}`}>{step.ok ? "done" : "failed"}</span><span>{step.step}{step.ok ? "" : `: ${step.detail}`}</span></li>)}</ul>
        )}
      </section>
    </div>
  );
}
