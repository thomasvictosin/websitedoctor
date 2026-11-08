"use client";

import { useCallback, useEffect, useState } from "react";
import { useConfirm } from "./confirm-dialog";

type CleanupStep = { description: string; operation: string; parameters: Record<string, string> };
type CleanupPlan = {
  generatedAt: string;
  summary: string;
  steps: CleanupStep[];
  optional: Array<{ id: string; description: string }>;
  manual: string[];
  warnings: string[];
  blockers: string[];
  evidence: { integrityScannedAt: string | null; pluginVersion: string | null; openSecurityFindings: string[] };
  planDigest: string;
};
type CleanupRun = {
  id: string;
  title: string;
  mode: string;
  status: string;
  executionStatus: string;
  verificationStatus: string;
  rollbackStatus: string;
  createdAt: string;
  initiatingInterface: string;
  stepCount: number;
  plannedSteps: string[];
  results: Array<{ index: number; operation?: string; status: string; message: string }> | null;
  verification: { status: string; reasons: string[] } | null;
  runId: string | null;
  purgedAt: string | null;
  restoredAt: string | null;
  hasQuarantine: boolean;
};
type Maintenance = { pluginUpdates: Array<{ plugin: string; description: string }>; notUpdatable: string[] };

const OPERATION_LABELS: Record<string, string> = {
  quarantine_file: "Quarantine file",
  restore_core_file: "Restore core file",
  remove_htaccess_rules: "Clean .htaccess",
  quarantine_plugin: "Remove plugin",
  demote_user: "Demote administrator",
  rotate_salts: "Rotate salts",
  purge_page_cache: "Purge cache",
  purge_quarantine: "Delete quarantine",
  update_plugin: "Update plugin",
  reinstall_plugin: "Reinstall plugin",
  install_plugin: "Install plugin",
  set_hardening: "Protection",
  restore_run: "Restore run",
  update_theme: "Update theme",
  reinstall_theme: "Reinstall theme",
  quarantine_theme: "Remove theme",
  quarantine_theme_file: "Quarantine theme file",
};

const ACTIVE = ["approved", "executing"];

export function runStatusLabel(run: { status: string; verificationStatus: string }) {
  if (run.status === "approved") return { label: "Waiting for the site", tone: "pending" };
  if (run.status === "executing") return { label: "Running on the site", tone: "pending" };
  if (run.status === "verified") return { label: "Verified", tone: "on" };
  if (run.status === "rolled_back") return { label: "Restored", tone: "off" };
  if (run.verificationStatus === "inconclusive") return { label: "Inconclusive", tone: "warn" };
  return { label: "Needs attention", tone: "warn" };
}

/** Cleanup plan, plugin updates, and earlier runs with restore / permanent delete. */
export function CleanupManager({ websiteId, onNotice }: { websiteId: string; onNotice: (message: string) => void }) {
  const dialogs = useConfirm();
  const [plan, setPlan] = useState<CleanupPlan | null>(null);
  const [maintenance, setMaintenance] = useState<Maintenance | null>(null);
  const [runs, setRuns] = useState<CleanupRun[]>([]);
  const [include, setInclude] = useState<string[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [loadError, setLoadError] = useState("");

  const load = useCallback(async () => {
    try {
      const response = await fetch(`/api/sites/${websiteId}/cleanup`, { cache: "no-store" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "Could not load the cleanup plan.");
      setPlan(body.plan);
      setMaintenance(body.maintenance ?? null);
      setRuns(body.runs ?? []);
      setInclude((current) => current.filter((id) => body.plan.optional.some((item: { id: string }) => item.id === id)));
      setLoadError("");
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "Could not load the cleanup plan.");
    }
  }, [websiteId]);

  useEffect(() => { void load(); }, [load]);
  const activeRun = runs.find((run) => ACTIVE.includes(run.status)) ?? null;
  useEffect(() => {
    if (!activeRun) return;
    const timer = setInterval(() => void load(), 5_000);
    return () => clearInterval(timer);
  }, [activeRun, load]);

  async function post(key: string, body: Record<string, unknown>, dialog: { title: string; body: string; confirmLabel: string; danger?: boolean }) {
    if (!await dialogs.confirm(dialog)) return;
    setBusy(key);
    try {
      const response = await fetch(`/api/sites/${websiteId}/cleanup`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "The request could not be approved.");
      onNotice(result.message ?? "Approved.");
      await load();
    } catch (error) {
      onNotice(error instanceof Error ? error.message : "The request could not be approved.");
      await load();
    } finally {
      setBusy(null);
    }
  }

  if (!plan) {
    return <div className="detail-content"><h3>Clean up &amp; fixes</h3><p>{loadError || "Loading the cleanup plan…"}</p></div>;
  }
  const stepsToRun = plan.steps.length + include.length;
  const locked = Boolean(busy) || Boolean(activeRun);
  const quarantineRuns = runs.filter((run) => run.hasQuarantine);

  return (
    <div className="detail-content tab-stack">
      {activeRun && (
        <div className="progress-banner" role="status">
          <span className="spinner" aria-hidden="true" />
          <div>
            <strong>{activeRun.title}: {runStatusLabel(activeRun).label.toLowerCase()}…</strong>
            <small>Approved {new Date(activeRun.createdAt).toLocaleTimeString()}. The site usually picks it up within seconds; if it is unreachable, on its next check-in (within 5 minutes). This page updates by itself.</small>
          </div>
        </div>
      )}

      <section className="tab-section">
        <div className="tab-section-head">
          <div>
            <h3>Compromise cleanup</h3>
            <p className="lead">{plan.summary}</p>
          </div>
          <small className="muted-meta">Scan: {plan.evidence.integrityScannedAt ? new Date(plan.evidence.integrityScannedAt).toLocaleString() : "not received"} · plugin {plan.evidence.pluginVersion ?? "unknown"}</small>
        </div>
        {plan.blockers.length > 0 && (
          <div className="callout callout-warn" role="alert">
            <strong>Cleanup cannot start yet</strong>
            <ul>{plan.blockers.map((blocker) => <li key={blocker}>{blocker}</li>)}</ul>
          </div>
        )}
        {plan.steps.length > 0 && (
          <>
            <h4>Changes that will be made ({plan.steps.length})</h4>
            <ol className="step-list">
              {plan.steps.map((step, index) => (
                <li key={`${step.operation}:${index}`}><span className="pill pill-neutral">{OPERATION_LABELS[step.operation] ?? step.operation}</span><span>{step.description}</span></li>
              ))}
            </ol>
          </>
        )}
        {plan.optional.length > 0 && (
          <>
            <h4>Optional, only if you tick them</h4>
            <div className="check-list">
              {plan.optional.map((item) => (
                <label key={item.id}>
                  <input type="checkbox" checked={include.includes(item.id)} disabled={locked}
                    onChange={(event) => setInclude((current) => event.target.checked ? [...current, item.id] : current.filter((id) => id !== item.id))} />
                  <span>{item.description}</span>
                </label>
              ))}
            </div>
          </>
        )}
        {plan.warnings.length > 0 && <div className="callout">{plan.warnings.map((warning) => <p key={warning}>{warning}</p>)}</div>}
        {stepsToRun > 0 && plan.blockers.length === 0 && (
          <div className="section-actions">
            <button className="button primary" disabled={locked}
              onClick={() => post("start", { action: "start", planDigest: plan.planDigest, include, confirm: true }, {
                title: `Approve ${stepsToRun} change(s) on the live site?`,
                body: "Changed and removed files are kept in the quarantine, so the run can be restored. Rotating salts signs everyone out, including you.",
                confirmLabel: "Approve & run cleanup",
              })}>
              {busy === "start" ? "Approving…" : activeRun ? "A run is in progress…" : `Approve & run cleanup (${stepsToRun} steps)`}
            </button>
          </div>
        )}
        {plan.manual.length > 0 && (
          <>
            <h4>Also do manually</h4>
            <ul className="plain-list">{plan.manual.map((item) => <li key={item}>{item}</li>)}</ul>
          </>
        )}
      </section>

      {maintenance && (maintenance.pluginUpdates.length > 0 || maintenance.notUpdatable.length > 0) && (
        <section className="tab-section">
          <div className="tab-section-head">
            <div>
              <h3>Plugin updates</h3>
              <p className="lead">Each update is downloaded from WordPress.org, checked against the official checksums, and rolled back automatically if the site breaks.</p>
            </div>
          </div>
          {maintenance.pluginUpdates.length > 0 && <ul className="plain-list">{maintenance.pluginUpdates.map((item) => <li key={item.plugin}>{item.description}</li>)}</ul>}
          {maintenance.notUpdatable.length > 0 && <div className="callout"><p>Not updated here:</p><ul>{maintenance.notUpdatable.map((item) => <li key={item}>{item}</li>)}</ul></div>}
          {maintenance.pluginUpdates.length > 0 && (
            <div className="section-actions">
              <button className="button secondary" disabled={locked}
                onClick={() => post("updates", { action: "update_plugins", confirm: true }, {
                  title: `Update ${maintenance.pluginUpdates.length} plugin(s)?`,
                  body: "The previous version of each plugin is kept in the quarantine and put back automatically if an update fails its checks or breaks the site.",
                  confirmLabel: "Update plugins",
                })}>
                {busy === "updates" ? "Approving…" : `Update ${maintenance.pluginUpdates.length} plugin(s)`}
              </button>
            </div>
          )}
        </section>
      )}

      <section className="tab-section">
        <div className="tab-section-head">
          <div>
            <h3>Quarantine</h3>
            <p className="lead">Every file a cleanup or update changed or removed is kept here. Restore puts a run back on the site. Delete permanently frees the space once you are sure the site works; it cannot be undone.</p>
          </div>
        </div>
        {quarantineRuns.length === 0 ? <p className="empty-note">Nothing is in quarantine.</p> : (
          <div className="run-list">
            {quarantineRuns.map((run) => {
              const status = runStatusLabel(run);
              const inQuarantine = !run.purgedAt && run.status !== "rolled_back" && Boolean(run.runId);
              return (
                <article className="run-card" key={run.id}>
                  <div className="run-card-head">
                    <div>
                      <strong>{run.title}</strong>
                      <small>{new Date(run.createdAt).toLocaleString()} · {run.stepCount} step(s) · {run.initiatingInterface.replaceAll("_", " ")}</small>
                    </div>
                    <span className={`pill pill-${run.purgedAt ? "off" : status.tone}`}>{run.purgedAt ? "Quarantine deleted" : status.label}</span>
                  </div>
                  {run.verification?.reasons?.length ? <ul className="plain-list">{run.verification.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul> : null}
                  {run.results && (
                    <details>
                      <summary>Step results</summary>
                      <ol className="step-list">{run.results.map((result) => <li key={result.index}><span className={`pill ${result.status === "applied" || result.status === "restored" ? "pill-on" : result.status === "failed" || result.status === "conflict" ? "pill-warn" : "pill-neutral"}`}>{result.status.replaceAll("_", " ")}</span><span>{OPERATION_LABELS[result.operation ?? ""] ?? result.operation}: {result.message}</span></li>)}</ol>
                    </details>
                  )}
                  {inQuarantine && !ACTIVE.includes(run.status) && (
                    <div className="section-actions">
                      <button className="button secondary" disabled={locked}
                        onClick={() => post(`restore:${run.id}`, { action: "restore", repairId: run.id, confirm: true }, {
                          title: "Restore this run?",
                          body: run.mode === "compromise"
                            ? "Everything this cleanup changed or quarantined is put back on the site, except files changed since. This puts the malware back: only do it if the cleanup broke something."
                            : "The previous versions and settings from this run are put back on the site, except anything changed since.",
                          confirmLabel: "Restore run",
                          danger: run.mode === "compromise",
                        })}>
                        {busy === `restore:${run.id}` ? "Approving…" : "Restore"}
                      </button>
                      <button className="button danger" disabled={locked}
                        onClick={() => post(`purge:${run.id}`, { action: "purge", repairId: run.id, confirm: true }, {
                          title: "Delete these quarantined files permanently?",
                          body: run.status === "verified"
                            ? "This run was verified. Deleting is safe once you have checked the site works; afterwards the run can no longer be restored."
                            : "This run was not verified. Only delete if you have checked the site works without these files; afterwards the run can no longer be restored.",
                          confirmLabel: "Delete permanently",
                          danger: true,
                        })}>
                        {busy === `purge:${run.id}` ? "Approving…" : "Delete permanently"}
                      </button>
                    </div>
                  )}
                </article>
              );
            })}
          </div>
        )}
      </section>
      {loadError && <p className="empty-note">{loadError}</p>}
    </div>
  );
}
