"use client";

import { useCallback, useEffect, useState } from "react";
import { useConfirm } from "./confirm-dialog";

type Step = { step: string; ok: boolean; detail: string };
type Option = { id: string; label: string; current: boolean; blockers: string[]; warnings: string[] };
type Change = { status: "verified" | "rolled_back" | "rollback_failed" | "failed" | "blocked"; message: string; from: { label: string } | null; to: { label: string }; steps: Step[]; finishedAt: string };
type PhpConnection = {
  connectionId: string;
  hostname: string;
  vhost?: string;
  current?: { id: string; label: string | null; inherited: boolean; phpFpm: boolean };
  systemDefault?: string | null;
  installed?: Option[];
  running: boolean;
  lastChange: Change | null;
  confirmation: { state: "confirmed" | "waiting" | "mismatch" | "unavailable"; detail: string } | null;
  error?: string;
};
type PhpStatus = { connections: PhpConnection[]; plugin: { phpVersion: string; reportedAt: string | null } | null };

function newer(a: string, b: string) {
  const left = a.split(".").map(Number);
  const right = b.split(".").map(Number);
  return (left[0] - right[0] || (left[1] ?? 0) - (right[1] ?? 0)) > 0;
}

const statusText: Record<Change["status"], string> = {
  verified: "Switched and verified",
  rolled_back: "Switched back automatically",
  rollback_failed: "Switch-back failed: act now",
  failed: "Not switched",
  blocked: "Not switched",
};

/** Switch the site's PHP version through its cPanel connection, with a compatibility check and automatic switch-back. */
export function PhpVersionPanel({ websiteId, connectionId, onNotice }: { websiteId: string; connectionId: string; onNotice?: (message: string) => void }) {
  const dialogs = useConfirm();
  const [status, setStatus] = useState<PhpStatus | null>(null);
  const [loadError, setLoadError] = useState("");
  const [selected, setSelected] = useState("");
  const [busy, setBusy] = useState(false);
  const [steps, setSteps] = useState<Step[]>([]);

  const load = useCallback(async () => {
    try {
      const response = await fetch(`/api/sites/${websiteId}/hosting/php?connectionId=${encodeURIComponent(connectionId)}`, { cache: "no-store" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "Could not read the PHP version from cPanel.");
      setStatus(body);
      setLoadError("");
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "Could not read the PHP version from cPanel.");
    }
  }, [websiteId, connectionId]);
  useEffect(() => { void load(); }, [load]);

  const connection = status?.connections[0];
  const choices = (connection?.installed ?? []).filter((option) => !option.current);
  const choice = choices.find((option) => option.id === selected) ?? choices.find((option) => !option.blockers.length && newer(option.label, connection?.current?.label ?? "0")) ?? choices[0];

  async function switchVersion(option: Option) {
    const from = connection?.current?.label ?? "the current version";
    const confirmed = await dialogs.confirm({
      title: `Switch ${connection?.vhost ?? "the site"} to PHP ${option.label}?`,
      body: [
        `The app records PHP ${from}, switches in cPanel, then loads the home page, login page, REST API and admin-ajax from outside. If a page that worked before fails, it switches back to PHP ${from} automatically. This takes up to two minutes.`,
        ...option.warnings,
      ].join("\n\n"),
      confirmLabel: `Switch to PHP ${option.label}`,
    });
    if (!confirmed) return;
    setBusy(true);
    setSteps([]);
    try {
      const response = await fetch(`/api/sites/${websiteId}/hosting/php`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ connectionId, version: option.label, expectedCurrent: connection?.current?.id, confirm: true }),
      });
      const result = await response.json();
      if (Array.isArray(result.steps)) setSteps(result.steps);
      onNotice?.(result.message ?? result.error ?? "The PHP switch finished.");
    } catch (error) {
      onNotice?.(error instanceof Error ? error.message : "The PHP switch failed.");
    } finally {
      setBusy(false);
      await load();
    }
  }

  if (!status) return <div className="hosting-inspection"><strong>PHP version</strong><p className="empty-note">{loadError || "Reading the PHP version from cPanel…"}</p></div>;
  if (!connection) return null;
  const change = connection.lastChange;
  return (
    <div className="hosting-inspection php-version-panel">
      <strong>PHP version</strong>
      {connection.error ? <p className="empty-note">{connection.error}</p> : <>
        <div className="fact-grid">
          <div><small>CPANEL ({connection.vhost})</small><strong>PHP {connection.current?.label ?? connection.current?.id}{connection.current?.inherited ? " · server default" : ""}</strong></div>
          <div><small>WORDPRESS REPORTS</small><strong>{status.plugin ? `PHP ${status.plugin.phpVersion}` : "Plugin not connected"}</strong></div>
          <div><small>SERVER DEFAULT</small><strong>{connection.systemDefault ? `PHP ${connection.systemDefault}` : "Unknown"}</strong></div>
        </div>
        {change && (
          <div className={`callout ${change.status === "verified" ? "callout-ok" : "callout-warn"}`}>
            <p><strong>{statusText[change.status]}</strong> · {new Date(change.finishedAt).toLocaleString()}</p>
            <p>{change.message}</p>
            {connection.confirmation && <p>{connection.confirmation.state === "confirmed" ? "✓ " : ""}{connection.confirmation.detail}</p>}
          </div>
        )}
        {choices.length === 0 ? <p className="muted-meta">No other PHP version is installed on this server.</p> : choice && <>
          <label>
            Switch to
            <select value={choice.id} onChange={(event) => setSelected(event.target.value)} disabled={busy || connection.running}>
              {choices.map((option) => <option key={option.id} value={option.id}>PHP {option.label}{option.blockers.length ? " (blocked)" : ""}</option>)}
            </select>
          </label>
          {choice.blockers.length > 0 && <ul className="step-list">{choice.blockers.map((line) => <li key={line}><span className="pill pill-bad">blocked</span><span>{line}</span></li>)}</ul>}
          {choice.warnings.length > 0 && <ul className="step-list">{choice.warnings.map((line) => <li key={line}><span className="pill pill-warn">check</span><span>{line}</span></li>)}</ul>}
          <div className="section-actions">
            <button type="button" className="button primary" disabled={busy || connection.running || choice.blockers.length > 0} onClick={() => void switchVersion(choice)}>
              {busy || connection.running ? "Switching and checking the site…" : `Switch to PHP ${choice.label}`}
            </button>
            <button type="button" className="button ghost" disabled={busy} onClick={() => void load()}>Refresh</button>
          </div>
        </>}
        {steps.length > 0 && (
          <ul className="step-list">{steps.map((step) => <li key={step.step}><span className={`pill ${step.ok ? "pill-on" : "pill-warn"}`}>{step.ok ? "done" : "failed"}</span><span>{step.step}: {step.detail}</span></li>)}</ul>
        )}
      </>}
    </div>
  );
}
