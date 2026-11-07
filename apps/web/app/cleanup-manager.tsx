"use client";

import { useCallback, useEffect, useState } from "react";

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
  status: string;
  executionStatus: string;
  verificationStatus: string;
  rollbackStatus: string;
  createdAt: string;
  initiatingInterface: string;
  stepCount: number;
  results: Array<{ index: number; operation?: string; status: string; message: string }> | null;
  verification: { status: string; reasons: string[] } | null;
};

const OPERATION_LABELS: Record<string, string> = {
  quarantine_file: "Quarantine file",
  restore_core_file: "Restore core file",
  remove_htaccess_rules: "Clean .htaccess",
  quarantine_plugin: "Remove plugin",
  demote_user: "Demote administrator",
  rotate_salts: "Rotate salts",
  purge_page_cache: "Purge cache",
  purge_quarantine: "Delete quarantine",
};

/** One-click compromise cleanup: review the exact plan, approve it, follow verification. */
export function CleanupManager({ websiteId }: { websiteId: string }) {
  const [plan, setPlan] = useState<CleanupPlan | null>(null);
  const [runs, setRuns] = useState<CleanupRun[]>([]);
  const [include, setInclude] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  const load = useCallback(async () => {
    try {
      const response = await fetch(`/api/sites/${websiteId}/cleanup`, { cache: "no-store" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "Could not load the cleanup plan.");
      setPlan(body.plan);
      setRuns(body.runs ?? []);
      setInclude((current) => current.filter((id) => body.plan.optional.some((item: { id: string }) => item.id === id)));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not load the cleanup plan.");
    }
  }, [websiteId]);

  useEffect(() => { void load(); }, [load]);
  const active = runs.some((run) => run.status === "approved" || run.status === "executing");
  useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => void load(), 15_000);
    return () => clearInterval(timer);
  }, [active, load]);

  async function post(body: Record<string, unknown>, confirmText: string) {
    if (!window.confirm(confirmText)) return;
    setBusy(true);
    setMessage("");
    try {
      const response = await fetch(`/api/sites/${websiteId}/cleanup`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "The cleanup could not be approved.");
      setMessage(result.message);
      await load();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The cleanup could not be approved.");
      await load();
    } finally {
      setBusy(false);
    }
  }

  if (!plan) return <div className="detail-panel"><h3>Compromise cleanup</h3><p>{message || "Loading the cleanup plan…"}</p></div>;
  const stepsToRun = plan.steps.length + include.length;
  return (
    <div className="detail-panel">
      <h3>Compromise cleanup</h3>
      <p>{plan.summary}</p>
      <p className="diagnostic-limit">
        Integrity scan: {plan.evidence.integrityScannedAt ? new Date(plan.evidence.integrityScannedAt).toLocaleString() : "not received"} · plugin {plan.evidence.pluginVersion ?? "version unknown"}
      </p>
      {plan.blockers.length > 0 && (
        <div className="cleanup-blockers" role="alert">
          <strong>Cleanup cannot start yet</strong>
          <ul>{plan.blockers.map((blocker) => <li key={blocker}>{blocker}</li>)}</ul>
        </div>
      )}
      {plan.steps.length > 0 && (
        <>
          <h4>Changes that will be made ({plan.steps.length})</h4>
          <ol className="cleanup-steps">
            {plan.steps.map((step, index) => (
              <li key={`${step.operation}:${index}`}><strong>{OPERATION_LABELS[step.operation] ?? step.operation}:</strong> {step.description}</li>
            ))}
          </ol>
        </>
      )}
      {plan.optional.length > 0 && (
        <>
          <h4>Optional, only if you tick them</h4>
          <ul className="cleanup-optional">
            {plan.optional.map((item) => (
              <li key={item.id}>
                <label>
                  <input type="checkbox" checked={include.includes(item.id)} disabled={busy}
                    onChange={(event) => setInclude((current) => event.target.checked ? [...current, item.id] : current.filter((id) => id !== item.id))} />{" "}
                  {item.description}
                </label>
              </li>
            ))}
          </ul>
        </>
      )}
      {plan.warnings.map((warning) => <p key={warning} className="diagnostic-limit">{warning}</p>)}
      {stepsToRun > 0 && plan.blockers.length === 0 && (
        <button className="button primary" disabled={busy || active}
          onClick={() => post({ action: "start", planDigest: plan.planDigest, include, confirm: true },
            `Approve ${stepsToRun} change(s) on the live site? Files are quarantined (not deleted) and the run can be restored from the plugin. Rotating salts signs everyone out.`)}>
          {active ? "Cleanup in progress…" : busy ? "Approving…" : `Approve & run cleanup (${stepsToRun} steps)`}
        </button>
      )}
      {plan.manual.length > 0 && (
        <>
          <h4>Also do manually</h4>
          <ul>{plan.manual.map((item) => <li key={item}>{item}</li>)}</ul>
        </>
      )}
      {message && <p role="status">{message}</p>}
      {runs.length > 0 && (
        <>
          <h4>Cleanup runs</h4>
          <ul className="issue-list">
            {runs.map((run) => (
              <li key={run.id}>
                <strong>{run.title}</strong> · {new Date(run.createdAt).toLocaleString()} · {run.stepCount} steps · status <strong>{run.status}</strong>
                {run.verificationStatus !== "not_started" && <> · verification <strong>{run.verificationStatus}</strong></>}
                {run.rollbackStatus !== "not_requested" && <> · restore {run.rollbackStatus}</>}
                {run.verification?.reasons?.length ? <ul>{run.verification.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul> : null}
                {run.results && (
                  <details><summary>Step results</summary>
                    <ol>{run.results.map((result) => <li key={result.index}>{OPERATION_LABELS[result.operation ?? ""] ?? result.operation}: {result.status} · {result.message}</li>)}</ol>
                  </details>
                )}
                {run.status === "verified" && run.title !== "Permanently delete quarantined files" && (
                  <button className="button ghost" disabled={busy}
                    onClick={() => post({ action: "purge", repairId: run.id, confirm: true }, "Permanently delete the files this cleanup quarantined? The run can no longer be restored afterwards.")}>
                    Delete quarantined files permanently
                  </button>
                )}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
