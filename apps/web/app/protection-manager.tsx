"use client";

import { useCallback, useEffect, useState } from "react";

type Measure = { id: string; title: string; enabled: boolean; verified: boolean | null; detail: string; reported: boolean };
type Alert = { id: string; category: string; title: string; body: string; createdAt: string };
type Protection = {
  pluginVersion: string | null;
  supported: boolean;
  measures: Measure[];
  settings: { selfHealing: boolean; autoUpdates: boolean };
  alerts: Alert[];
};

/** Site protection: hardening measures, automatic responses and recent alerts. */
export function ProtectionManager({ websiteId }: { websiteId: string }) {
  const [data, setData] = useState<Protection | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  const load = useCallback(async () => {
    try {
      const response = await fetch(`/api/sites/${websiteId}/protection`, { cache: "no-store" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "Could not load protection status.");
      setData(body);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not load protection status.");
    }
  }, [websiteId]);
  useEffect(() => { void load(); }, [load]);

  async function send(method: "POST" | "PUT", body: Record<string, unknown>, confirmText?: string) {
    if (confirmText && !window.confirm(confirmText)) return;
    setBusy(true);
    setMessage("");
    try {
      const response = await fetch(`/api/sites/${websiteId}/protection`, { method, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "The change could not be made.");
      setMessage(result.message ?? "Saved.");
      await load();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The change could not be made.");
    } finally {
      setBusy(false);
    }
  }

  if (!data) return <div className="detail-panel"><h3>Protection</h3><p>{message || "Loading…"}</p></div>;
  const off = data.measures.filter((measure) => !measure.enabled).length;
  return (
    <div className="detail-panel">
      <h3>Protection</h3>
      {!data.supported && (
        <div className="cleanup-blockers" role="alert">
          Protection needs AI Website Doctor 0.5.0 or later on the site (it reports {data.pluginVersion ?? "an older version"}). Install the new plugin ZIP with “Replace current with uploaded”, then select Collect and sync diagnostics.
        </div>
      )}
      <p className="diagnostic-limit">These measures make attacks much harder and limit what a successful attacker can do. No setting makes a WordPress site impossible to hack, so the hourly scans, alerts and self-healing below stay important.</p>
      <ul className="protection-list">
        {data.measures.map((measure) => (
          <li key={measure.id}>
            <div>
              <strong>{measure.title}</strong>
              <span className={`protection-state ${measure.enabled ? measure.verified === false ? "warn" : "on" : "off"}`}>
                {!measure.enabled ? "Off" : measure.verified === false ? "On, not effective on this server" : measure.verified ? "On, verified" : "On"}
              </span>
              {measure.enabled && measure.detail && <small>{measure.detail}</small>}
            </div>
            <button className="button ghost" disabled={busy || !data.supported}
              onClick={() => send("POST", { measure: measure.id, state: measure.enabled ? "off" : "on", confirm: true }, `${measure.enabled ? "Turn off" : "Turn on"} “${measure.title}” on the live site?`)}>
              {measure.enabled ? "Turn off" : "Turn on"}
            </button>
          </li>
        ))}
      </ul>
      {off > 0 && (
        <button className="button primary" disabled={busy || !data.supported}
          onClick={() => send("POST", { recommended: true, confirm: true }, `Turn on ${off} recommended protection measure(s)? Each one is reversible, and rules that change .htaccess are tested on your server and removed again if they break the site.`)}>
          Turn on all recommended protection ({off})
        </button>
      )}

      <h4>Automatic responses</h4>
      <label className="protection-toggle">
        <input type="checkbox" checked={data.settings.selfHealing} disabled={busy}
          onChange={(event) => send("PUT", { selfHealing: event.target.checked }, event.target.checked
            ? "Turn on self-healing? When a new compromise is found, the app automatically quarantines dropped files, restores core files, removes injected .htaccess rules and reinstalls tampered WordPress.org plugins, then alerts you. Salts, users and plugin removal still wait for you."
            : undefined)} />
        <span><strong>Self-healing</strong>: automatically repair new malware files with the safe, verified cleanup steps (at most 3 times a day), then alert you.</span>
      </label>
      <label className="protection-toggle">
        <input type="checkbox" checked={data.settings.autoUpdates} disabled={busy}
          onChange={(event) => send("PUT", { autoUpdates: event.target.checked }, event.target.checked
            ? "Turn on automatic plugin updates? Once a day, WordPress.org plugins with an update are updated, verified against the official checksums, and rolled back automatically if the site breaks. Never while security findings are open."
            : undefined)} />
        <span><strong>Automatic plugin updates</strong>: once a day, verified, with automatic rollback. Premium plugins still update from their vendors.</span>
      </label>
      <p className="diagnostic-limit">Alerts are emailed by your WordPress site to its administrator address (Settings → General → Administration Email Address).</p>

      {message && <p role="status">{message}</p>}
      <h4>Recent alerts</h4>
      {data.alerts.length === 0 ? <p className="diagnostic-limit">No alerts in the last 7 days.</p> : (
        <ul className="issue-list">
          {data.alerts.map((alert) => (
            <li key={alert.id}>
              <strong>{alert.title}</strong> · {new Date(alert.createdAt).toLocaleString()}
              <details><summary>Details</summary><pre className="protection-alert-body">{alert.body}</pre></details>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
