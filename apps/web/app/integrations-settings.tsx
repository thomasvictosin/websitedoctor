"use client";

import { useCallback, useEffect, useState } from "react";

type Status = {
  wordfence: { configured: boolean; source: string | null };
  pagespeed: { configured: boolean; source: string | null };
  ai: { configured: boolean; source: string | null; model: string; models: Array<{ id: string; label: string; note: string }> };
  email: { configured: boolean; source: string | null; from: string | null; reminderEmails: string[] };
  vulnerabilities: { keyConfigured: boolean; feedFetchedAt: string | null; feedEntries: number; matchedSoftware: number; lastError: { reason: string; at: string } | null; closedPluginsCheckedAt: string | null };
  accountEmail: string;
  refreshing?: boolean;
};

function KeyRow({ label, configured, source, placeholder, busy, onSave, onClear, help }: { label: string; configured: boolean; source: string | null; placeholder: string; busy: boolean; onSave: (value: string) => void; onClear: () => void; help: React.ReactNode }) {
  const [value, setValue] = useState("");
  return (
    <div className="integration-key">
      <div className="measure-title"><strong>{label}</strong><span className={`pill pill-${configured ? "on" : "off"}`}>{configured ? source === "environment" ? "Set on the server" : "Connected" : "Not set"}</span></div>
      <div className="lead">{help}</div>
      <div className="inline-form">
        <input type="password" autoComplete="off" placeholder={configured ? "Paste a new key to replace it" : placeholder} value={value} onChange={(event) => setValue(event.target.value)} disabled={busy} aria-label={label} />
        <button className="button primary" disabled={busy || value.trim().length < 8} onClick={() => { onSave(value.trim()); setValue(""); }}>{busy ? "Saving…" : "Save key"}</button>
        {configured && source === "settings" && <button className="button ghost danger-text" disabled={busy} onClick={onClear}>Remove</button>}
      </div>
    </div>
  );
}

/** Keys for the vulnerability database, PageSpeed and email, pasted here instead of the hosting dashboard. */
export function IntegrationsSettings({ onNotice }: { onNotice: (message: string) => void }) {
  const [status, setStatus] = useState<Status | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [from, setFrom] = useState("");
  const [emails, setEmails] = useState("");
  const [loadError, setLoadError] = useState("");

  const load = useCallback(async () => {
    try {
      const response = await fetch("/api/integrations/settings", { cache: "no-store" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "Could not load integrations.");
      setStatus(body);
      setFrom(body.email.from ?? "");
      setEmails((body.email.reminderEmails ?? []).join(", "));
      setLoadError("");
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "Could not load integrations.");
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  async function call(key: string, method: "PUT" | "POST", body: Record<string, unknown>, success: string) {
    setBusy(key);
    try {
      const response = await fetch("/api/integrations/settings", { method, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "The change failed.");
      onNotice(result.message ?? (result.refreshing ? `${success} Downloading the vulnerability database now; findings appear in Issues within a minute or two.` : success));
      await load();
    } catch (error) {
      onNotice(error instanceof Error ? error.message : "The change failed.");
    } finally {
      setBusy(null);
    }
  }

  if (!status) return <section className="panel"><p className="empty-note">{loadError || "Loading…"}</p></section>;
  const vuln = status.vulnerabilities;
  return (
    <section className="panel integrations-panel">
      <div className="panel-heading"><div><p className="eyebrow">INTEGRATIONS</p><h2>Connected services</h2></div></div>
      <p className="lead">Keys that switch on known-vulnerability checks, PageSpeed scores, the AI assistant and email reminders. Keys are stored encrypted and never shown again.</p>
      <div className="tab-stack">
        <section className="tab-section">
          <KeyRow label="Vulnerability database (Wordfence Intelligence)" configured={status.wordfence.configured} source={status.wordfence.source} placeholder="Wordfence Intelligence API key" busy={busy === "wordfence"}
            onSave={(value) => call("wordfence", "PUT", { wordfenceKey: value }, "Wordfence key saved.")} onClear={() => call("wordfence", "PUT", { wordfenceKey: null }, "Wordfence key removed.")}
            help={<>Checks every plugin, theme and WordPress version, premium ones included, against 30,000+ known vulnerabilities, daily. Free: create an account at <a href="https://www.wordfence.com/products/wordfence-intelligence/" target="_blank" rel="noreferrer">wordfence.com</a>, then <strong>Account → Integrations → Wordfence Intelligence API key</strong>.</>} />
          <div className="fact-grid">
            <div><small>DATABASE</small><strong>{vuln.feedFetchedAt ? `Updated ${new Date(vuln.feedFetchedAt).toLocaleString()}` : "Not downloaded yet"}</strong></div>
            <div><small>ENTRIES</small><strong>{vuln.feedEntries ? vuln.feedEntries.toLocaleString() : "—"}</strong></div>
            <div><small>YOUR SOFTWARE WITH RECORDS</small><strong>{vuln.feedFetchedAt ? vuln.matchedSoftware : "—"}</strong></div>
            <div><small>CLOSED-PLUGIN CHECK (NO KEY NEEDED)</small><strong>{vuln.closedPluginsCheckedAt ? `Checked ${new Date(vuln.closedPluginsCheckedAt).toLocaleDateString()}` : "Not run yet"}</strong></div>
          </div>
          {vuln.lastError && <div className="callout callout-warn"><p>{vuln.lastError.reason}</p></div>}
          <div className="section-actions"><button className="button secondary" disabled={Boolean(busy)} onClick={() => call("refresh", "POST", { action: "refresh_vulnerabilities" }, "Vulnerability check finished; see Issues.")}>{busy === "refresh" ? "Checking all sites…" : "Check all sites now"}</button></div>
        </section>

        <section className="tab-section">
          <KeyRow label="PageSpeed Insights (Google)" configured={status.pagespeed.configured} source={status.pagespeed.source} placeholder="Google API key" busy={busy === "pagespeed"}
            onSave={(value) => call("pagespeed", "PUT", { pagespeedKey: value }, "PageSpeed key saved. Open a website's Performance tab and run a test.")} onClear={() => call("pagespeed", "PUT", { pagespeedKey: null }, "PageSpeed key removed.")}
            help={<>Performance score, LCP, INP, CLS, FCP and TTFB for mobile and desktop, the same data as pagespeed.web.dev. Free: in <a href="https://developers.google.com/speed/docs/insights/v5/get-started#APIKey" target="_blank" rel="noreferrer">Google&apos;s PageSpeed guide</a> click <strong>Get a Key</strong> (25,000 tests a day). Google refuses most tests without a key.</>} />
        </section>

        <section className="tab-section">
          <KeyRow label="AI assistant (Claude by Anthropic)" configured={status.ai.configured} source={status.ai.source} placeholder="Anthropic API key (sk-ant-…)" busy={busy === "anthropic"}
            onSave={(value) => call("anthropic", "PUT", { anthropicKey: value }, "Anthropic key saved. Send a test question below.")} onClear={() => call("anthropic", "PUT", { anthropicKey: null }, "Anthropic key removed.")}
            help={<>Answers questions in each website&apos;s assistant and writes AI diagnoses, only from the evidence the app has collected. Create a key at <a href="https://platform.claude.com/settings/keys" target="_blank" rel="noreferrer">platform.claude.com</a> → API Keys; Anthropic bills usage to that account. A question sends the site&apos;s stored diagnostics, usually tens of thousands of tokens.</>} />
          <div className="settings-grid">
            <label>Model<select value={status.ai.model} disabled={Boolean(busy)} onChange={(event) => call("model", "PUT", { aiModel: event.target.value }, "Model saved.")}>
              {status.ai.models.map((model) => <option key={model.id} value={model.id}>{model.label}</option>)}
            </select><small>{status.ai.models.find((model) => model.id === status.ai.model)?.note}</small></label>
          </div>
          <div className="section-actions">
            <button className="button ghost" disabled={Boolean(busy) || !status.ai.configured} onClick={() => call("test-ai", "POST", { action: "test_ai" }, "Claude answered.")}>{busy === "test-ai" ? "Asking…" : "Send a test question"}</button>
          </div>
        </section>

        <section className="tab-section">
          <KeyRow label="Email (Resend)" configured={status.email.configured} source={status.email.source} placeholder="Resend API key (re_…)" busy={busy === "resend"}
            onSave={(value) => call("resend", "PUT", { resendKey: value }, "Email key saved. Send a test email below.")} onClear={() => call("resend", "PUT", { resendKey: null }, "Email key removed.")}
            help={<>Sends renewal reminders (30 days, 10 days and on the day) and alerts from the app itself, so they still arrive when a site is down. Free: sign up at <a href="https://resend.com" target="_blank" rel="noreferrer">resend.com</a> → API Keys. Without it, each WordPress site emails its own administrator instead.</>} />
          <div className="settings-grid">
            <label>Send reminders to<input value={emails} onChange={(event) => setEmails(event.target.value)} placeholder={status.accountEmail} disabled={Boolean(busy)} /><small>Comma-separated. Empty means organization owners and administrators.</small></label>
            <label>Sender<input value={from} onChange={(event) => setFrom(event.target.value)} placeholder="Website Doctor <alerts@yourdomain.com>" disabled={Boolean(busy)} /><small>Needs a domain verified in Resend. Empty uses Resend&apos;s test sender, which only delivers to your Resend account email.</small></label>
          </div>
          <div className="section-actions">
            <button className="button secondary" disabled={Boolean(busy)} onClick={() => call("email", "PUT", { emailFrom: from.trim() || null, reminderEmails: emails.split(/[,\s]+/).map((item) => item.trim()).filter(Boolean) }, "Email settings saved.")}>{busy === "email" ? "Saving…" : "Save email settings"}</button>
            <button className="button ghost" disabled={Boolean(busy) || !status.email.configured} onClick={() => call("test", "POST", { action: "test_email" }, "Test email sent.")}>{busy === "test" ? "Sending…" : "Send test email"}</button>
          </div>
        </section>
      </div>
    </section>
  );
}
