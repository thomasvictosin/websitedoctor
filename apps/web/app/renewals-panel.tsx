"use client";

import { useCallback, useEffect, useState } from "react";

export type Renewal = { kind: string; label: string; status: string; expiresAt: string | null; daysLeft: number | null; source: "manual" | "automatic" | null; detectedExpiry: string | null; provider: string | null; notes: string | null; error: string | null; checkedAt: string | null; details: Record<string, unknown> | null; lastReminder: string | null };

export function renewalTone(renewal: Pick<Renewal, "status" | "daysLeft">) {
  if (renewal.status === "expired" || renewal.status === "missing" || renewal.status === "invalid") return "bad";
  if (renewal.status === "expiring") return (renewal.daysLeft ?? 99) <= 10 ? "bad" : "warn";
  if (renewal.status === "ok") return "on";
  return "off";
}

export function renewalSummary(renewal: Pick<Renewal, "kind" | "status" | "daysLeft" | "expiresAt">) {
  if (renewal.status === "missing") return "SSL not available";
  if (renewal.status === "invalid") return "Not trusted by browsers";
  if (renewal.status === "expired") return `Expired ${renewal.expiresAt ? new Date(renewal.expiresAt).toLocaleDateString() : ""}`;
  if (renewal.status === "not_set") return "Date not entered";
  if (!renewal.expiresAt) return "Expiry unknown";
  return `${renewal.daysLeft} day${renewal.daysLeft === 1 ? "" : "s"} left`;
}

const HINT: Record<string, string> = {
  ssl: "Read from the certificate your server presents to visitors. Checked daily.",
  domain: "From the domain registry's public record (RDAP). Checked daily. Some country domains don't publish it; enter the date yourself.",
  hosting: "Hosting companies don't publish renewal dates, so enter it from your hosting invoice or account.",
};

/** SSL certificate, domain and hosting renewal dates for one website. */
export function RenewalsPanel({ websiteId, onNotice }: { websiteId: string; onNotice: (message: string) => void }) {
  const [renewals, setRenewals] = useState<Renewal[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [form, setForm] = useState({ expiresAt: "", provider: "", notes: "" });
  const [loadError, setLoadError] = useState("");

  const load = useCallback(async () => {
    try {
      const response = await fetch(`/api/sites/${websiteId}/renewals`, { cache: "no-store" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "Could not load renewal dates.");
      setRenewals(body.renewals);
      setLoadError("");
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "Could not load renewal dates.");
    }
  }, [websiteId]);
  useEffect(() => { void load(); }, [load]);

  async function send(key: string, method: "POST" | "PUT", body?: Record<string, unknown>) {
    setBusy(key);
    try {
      const response = await fetch(`/api/sites/${websiteId}/renewals`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "The change failed.");
      setRenewals(result.renewals);
      setEditing(null);
      onNotice(method === "POST" ? "SSL certificate and domain checked again." : "Saved. Reminders go out 30 days before, 10 days before and on the day it expires.");
    } catch (error) {
      onNotice(error instanceof Error ? error.message : "The change failed.");
    } finally {
      setBusy(null);
    }
  }

  function startEdit(renewal: Renewal) {
    setEditing(renewal.kind);
    setForm({ expiresAt: renewal.source === "manual" && renewal.expiresAt ? renewal.expiresAt.slice(0, 10) : "", provider: renewal.provider ?? "", notes: renewal.notes ?? "" });
  }

  return (
    <div className="detail-content tab-stack">
      <section className="tab-section">
        <div className="tab-section-head">
          <div>
            <h3>Renewals &amp; expiry dates</h3>
            <p className="lead">You get an email 30 days before, 10 days before, and on the day something expires. Expiring items also appear in Issues.</p>
          </div>
          <button className="button secondary" disabled={Boolean(busy)} onClick={() => send("refresh", "POST")}>{busy === "refresh" ? "Checking…" : "Check again"}</button>
        </div>
        {!renewals ? <p className="empty-note">{loadError || "Checking the certificate and domain…"}</p> : (
          <div className="renewal-grid">
            {renewals.map((renewal) => {
              const tone = renewalTone(renewal);
              const domain = typeof renewal.details?.domain === "string" ? renewal.details.domain : null;
              return (
                <article className={`renewal-card renewal-${tone}`} key={renewal.kind}>
                  <div className="renewal-head">
                    <strong>{renewal.label}</strong>
                    <span className={`pill pill-${tone}`}>{renewalSummary(renewal)}</span>
                  </div>
                  <div className="renewal-date">{renewal.expiresAt ? new Date(renewal.expiresAt).toLocaleDateString(undefined, { day: "numeric", month: "long", year: "numeric" }) : "—"}</div>
                  <dl className="renewal-facts">
                    {renewal.provider && <><dt>{renewal.kind === "ssl" ? "Issued by" : renewal.kind === "domain" ? "Registrar" : "Provider"}</dt><dd>{renewal.provider}</dd></>}
                    {domain && <><dt>Domain</dt><dd>{domain}</dd></>}
                    {renewal.source && <><dt>Source</dt><dd>{renewal.source === "manual" ? "Entered by you" : "Detected automatically"}</dd></>}
                    {renewal.notes && <><dt>Notes</dt><dd>{renewal.notes}</dd></>}
                    {renewal.lastReminder && <><dt>Last reminder</dt><dd>{renewal.lastReminder === "expired" ? "On expiry" : `${renewal.lastReminder} days before`}</dd></>}
                  </dl>
                  {renewal.error && renewal.status !== "ok" && <p className="renewal-note">{renewal.error}</p>}
                  <p className="muted-meta">{HINT[renewal.kind]}</p>
                  {renewal.kind !== "ssl" && (editing === renewal.kind ? (
                    <div className="renewal-form">
                      <label>Expiry date<input type="date" value={form.expiresAt} onChange={(event) => setForm({ ...form, expiresAt: event.target.value })} /></label>
                      <label>{renewal.kind === "domain" ? "Registrar" : "Hosting company"}<input value={form.provider} maxLength={120} onChange={(event) => setForm({ ...form, provider: event.target.value })} /></label>
                      <label>Notes<input value={form.notes} maxLength={500} placeholder="Plan, account, auto-renew…" onChange={(event) => setForm({ ...form, notes: event.target.value })} /></label>
                      <div className="section-actions">
                        <button className="button primary" disabled={Boolean(busy) || (renewal.kind === "hosting" && !form.expiresAt)} onClick={() => send(`save:${renewal.kind}`, "PUT", { kind: renewal.kind, expiresAt: form.expiresAt || null, provider: form.provider || null, notes: form.notes || null })}>{busy === `save:${renewal.kind}` ? "Saving…" : "Save"}</button>
                        <button className="button ghost" onClick={() => setEditing(null)}>Cancel</button>
                      </div>
                    </div>
                  ) : (
                    <button className="button ghost" onClick={() => startEdit(renewal)}>{renewal.kind === "hosting" ? renewal.expiresAt ? "Edit hosting date" : "Enter hosting renewal date" : renewal.source === "manual" ? "Edit date" : "Enter date yourself"}</button>
                  ))}
                </article>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}

/** Organization-wide: the next renewals across all websites (overview). */
export function UpcomingRenewals({ onOpenSite }: { onOpenSite: (siteId: string) => void }) {
  const [rows, setRows] = useState<Array<Renewal & { siteId: string; siteName: string }> | null>(null);
  useEffect(() => {
    void (async () => {
      try {
        const response = await fetch("/api/renewals", { cache: "no-store" });
        const body = await response.json();
        if (response.ok) setRows(body.renewals);
      } catch { /* the panel stays hidden */ }
    })();
  }, []);
  if (!rows) return null;
  const attention = rows.filter((row) => ["expired", "expiring", "missing", "invalid"].includes(row.status));
  const upcoming = rows.filter((row) => row.expiresAt && !attention.includes(row)).slice(0, Math.max(0, 6 - attention.length));
  const missingHosting = rows.filter((row) => row.kind === "hosting" && row.status === "not_set").length;
  return (
    <section className="panel renewals-overview">
      <div className="panel-heading"><div><p className="eyebrow">RENEWALS</p><h2>SSL, domains &amp; hosting</h2></div></div>
      {attention.length === 0 && upcoming.length === 0 ? <p className="empty-note">No dates yet. They appear after the first daily check, or open a website&apos;s Renewals tab.</p> : (
        <ul className="renewal-list">
          {[...attention, ...upcoming].map((row) => (
            <li key={`${row.siteId}:${row.kind}`}>
              <span className={`pill pill-${renewalTone(row)}`}>{renewalSummary(row)}</span>
              <div><strong>{row.siteName} · {row.label}</strong><small>{row.expiresAt ? new Date(row.expiresAt).toLocaleDateString() : row.error ?? ""}{row.provider ? ` · ${row.provider}` : ""}</small></div>
              <button className="button ghost" onClick={() => onOpenSite(row.siteId)}>Open</button>
            </li>
          ))}
        </ul>
      )}
      {missingHosting > 0 && <p className="muted-meta">{missingHosting} website(s) have no hosting renewal date yet; add it in each website&apos;s Renewals tab to get reminders.</p>}
    </section>
  );
}
