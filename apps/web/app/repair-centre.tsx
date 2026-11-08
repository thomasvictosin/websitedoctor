"use client";

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { useConfirm } from "./confirm-dialog";

/** A one-click run: cleanup, fix, update, protection change, restore or quarantine delete. */
type Run = {
  id: string;
  site: { id: string; name: string };
  title: string;
  mode: string;
  operations: string[];
  status: string;
  verificationStatus: string;
  rollbackStatus: string;
  startedBy: string;
  createdAt: string;
  plannedSteps: string[];
  results: Array<{ index: number; operation?: string; status: string; message: string }> | null;
  applied: number;
  failed: number;
  reasons: string[];
  purgedAt: string | null;
};

/** A proposal from the original single-operation repair engine (scan-based repairs and manual plans). */
export type LegacyRepairRow = {
  id: string;
  siteId: string;
  siteName: string;
  title: string;
  status: string;
  risk: string;
  createdAt: string;
  rationale: string;
  changes: string[];
  executable: boolean;
};

type Automation = { siteId: string; name: string; selfHealing: boolean; autoUpdates: boolean; linkRepairs: boolean; paused: boolean };
type HistoryEntry = { id: string; kind: string; title: string; siteId: string; siteName: string; createdAt: string; outcome: { label: string; tone: string; group: string }; detail: ReactNode };

const ACTIVE = ["approved", "executing"];
const HISTORY_PAGE = 25;

function runKind(run: Run) {
  if (run.operations.includes("restore_run")) return "Restore";
  if (run.operations.includes("purge_quarantine")) return "Quarantine delete";
  if (run.operations.every((operation) => operation === "set_hardening")) return "Protection";
  if (run.mode === "compromise") return run.startedBy === "self_healing" ? "Self-healing" : "Cleanup";
  if (run.startedBy === "auto_update") return "Automatic update";
  return run.operations.some((operation) => operation.startsWith("update_")) ? "Update" : "Fix";
}

function runOutcome(run: Run) {
  if (run.status === "verified") return { label: "Verified", tone: "on", group: "succeeded" };
  if (run.status === "rolled_back") return { label: "Restored", tone: "off", group: "restored" };
  if (run.status === "rejected") return { label: "Stopped", tone: "off", group: "rejected" };
  if (run.verificationStatus === "inconclusive") return { label: "Did not finish", tone: "warn", group: "attention" };
  return { label: "Needs attention", tone: "warn", group: "attention" };
}

function legacyOutcome(row: LegacyRepairRow) {
  switch (row.status) {
    case "verified": return { label: "Verified", tone: "on", group: "succeeded" };
    case "rolled_back": return { label: "Rolled back", tone: "off", group: "restored" };
    case "rejected": return { label: "Rejected", tone: "off", group: "rejected" };
    case "rollback_required": return { label: "Recovery needed", tone: "warn", group: "attention" };
    case "approved": return { label: "Plan acknowledged (manual)", tone: "neutral", group: "plans" };
    default: return { label: row.status.replaceAll("_", " "), tone: "warn", group: "attention" };
  }
}

const CAPABILITIES: Array<{ title: string; what: string; where: string; automatic: string; tab?: string }> = [
  { title: "Malware cleanup", what: "Quarantines malicious and unknown files, restores modified WordPress core files, removes injected .htaccess rules, reinstalls tampered plugins and themes, rotates salts and purges the cache.", where: "Website → Clean up & fixes", automatic: "Optional: self-healing repairs new malware files by itself (salts, users and plugin removal always wait for you).", tab: "cleanup" },
  { title: "Plugin & theme updates", what: "Installs the exact new version from WordPress.org, checks it against the official files and puts the old version back if the site breaks.", where: "Issues → Fix, or Update all", automatic: "Optional: automatic updates once a day, never while security problems are open.", tab: "cleanup" },
  { title: "Vulnerable plugins & themes", what: "Updates to the fixed version, or removes an unused plugin or theme that has no fix yet.", where: "Issues → Fix vulnerability", automatic: "No: you approve each one." },
  { title: "Protection", what: "Blocks PHP in uploads, hides sensitive files, turns off the code editor and XML-RPC, hides usernames, adds security headers and blocks fake crawlers. Each one is tested on your server.", where: "Website → Protection", automatic: "Stays on once switched on.", tab: "protection" },
  { title: "Cloudflare edge rules", what: "Blocks attacks before they reach your server: PHP in uploads, sensitive files, fake crawlers and attack tools, login rate limits.", where: "Website → Protection → Cloudflare", automatic: "Stays on once applied.", tab: "protection" },
  { title: "Quarantine", what: "Everything a cleanup or update changes is kept, so you can restore a run or delete it permanently.", where: "Website → Clean up & fixes → Quarantine", automatic: "No: restore and delete are always your choice.", tab: "cleanup" },
  { title: "Link and site-title repairs", what: "Updates links that permanently redirect, replaces broken links with a page you choose, and changes the site title or tagline.", where: "Issues → Review repair plan, or Advanced below", automatic: "Optional: links that permanently redirect can be updated automatically." },
  { title: "Plugin or theme isolation", what: "Deactivates a plugin proven to cause a PHP fatal error, or switches theme based on a staging comparison.", where: "Issues → Review repair plan", automatic: "No: high risk, so always your approval." },
];

export function RepairCentre({ legacy, decisionSlot, advancedSlot, onOpenSite, onNotice }: {
  legacy: LegacyRepairRow[];
  decisionSlot: ReactNode;
  advancedSlot: ReactNode;
  onOpenSite: (siteId: string, tab: "overview" | "cleanup" | "protection") => void;
  onNotice: (message: string) => void;
}) {
  const dialogs = useConfirm();
  const [runs, setRuns] = useState<Run[] | null>(null);
  const [automation, setAutomation] = useState<Automation[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [siteFilter, setSiteFilter] = useState("all");
  const [outcomeFilter, setOutcomeFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [shown, setShown] = useState(HISTORY_PAGE);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const loadRuns = useCallback(async () => {
    try {
      const response = await fetch("/api/runs", { cache: "no-store" });
      const body = await response.json();
      if (response.ok) setRuns(body.runs);
    } catch { /* The next refresh retries. */ }
  }, []);
  const loadAutomation = useCallback(async () => {
    try {
      const response = await fetch("/api/automation", { cache: "no-store" });
      const body = await response.json();
      if (response.ok) setAutomation(body.sites);
    } catch { /* The next refresh retries. */ }
  }, []);
  useEffect(() => { void loadRuns(); void loadAutomation(); }, [loadRuns, loadAutomation]);
  const activeRuns = (runs ?? []).filter((run) => ACTIVE.includes(run.status));
  useEffect(() => {
    const timer = setInterval(() => void loadRuns(), activeRuns.length ? 5_000 : 30_000);
    return () => clearInterval(timer);
  }, [activeRuns.length, loadRuns]);

  async function changeAutomation(key: string, body: Record<string, unknown>, dialog?: { title: string; body: string; confirmLabel: string; danger?: boolean }) {
    if (dialog && !await dialogs.confirm(dialog)) return;
    setBusy(key);
    try {
      const response = await fetch("/api/automation", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "The change could not be saved.");
      onNotice(result.message ?? "Saved.");
      await loadAutomation();
    } catch (error) {
      onNotice(error instanceof Error ? error.message : "The change could not be saved.");
    } finally {
      setBusy(null);
    }
  }

  const legacyInProgress = legacy.filter((row) => row.status === "executing" || row.status === "in_progress" || (row.status === "approved" && row.executable));
  const history = useMemo<HistoryEntry[]>(() => {
    const fromRuns = (runs ?? []).filter((run) => !ACTIVE.includes(run.status)).map((run) => ({
      id: run.id, kind: runKind(run), title: run.title, siteId: run.site.id, siteName: run.site.name, createdAt: run.createdAt, outcome: runOutcome(run),
      detail: (
        <>
          {run.reasons.length > 0 && <ul className="plain-list">{run.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>}
          {run.results ? (
            <ol className="step-list">{run.results.map((result) => <li key={result.index}><span className={`pill ${result.status === "applied" || result.status === "restored" ? "pill-on" : result.status === "failed" || result.status === "conflict" ? "pill-warn" : "pill-neutral"}`}>{result.status.replaceAll("_", " ")}</span><span>{result.message}</span></li>)}</ol>
          ) : <ul className="plain-list">{run.plannedSteps.map((step) => <li key={step}>{step}</li>)}</ul>}
          {run.purgedAt && <p className="muted-meta">Quarantine deleted {new Date(run.purgedAt).toLocaleString()}.</p>}
        </>
      ),
    }));
    const fromLegacy = legacy.filter((row) => !legacyInProgress.includes(row) && row.status !== "pending_approval").map((row) => ({
      id: row.id, kind: row.executable ? "Repair" : "Manual plan", title: row.title, siteId: row.siteId, siteName: row.siteName, createdAt: row.createdAt, outcome: legacyOutcome(row),
      detail: (
        <>
          {row.rationale && <p>{row.rationale}</p>}
          {row.changes.length > 0 && <ul className="plain-list">{row.changes.map((change) => <li key={change}>{change}</li>)}</ul>}
          {!row.executable && <p className="muted-meta">This was guidance only: the app does not change the site for it. Follow the steps yourself, then the finding clears on the next scan.</p>}
        </>
      ),
    }));
    return [...fromRuns, ...fromLegacy].sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
  }, [runs, legacy, legacyInProgress]);

  const sites = useMemo(() => [...new Map(history.map((entry) => [entry.siteId, entry.siteName])).entries()].sort((a, b) => a[1].localeCompare(b[1])), [history]);
  const filtered = history.filter((entry) => (siteFilter === "all" || entry.siteId === siteFilter)
    && (outcomeFilter === "all" || entry.outcome.group === outcomeFilter)
    && (!query.trim() || `${entry.title} ${entry.siteName} ${entry.kind}`.toLowerCase().includes(query.trim().toLowerCase())));
  const anyPaused = (automation ?? []).some((site) => site.paused);
  const anyAutomatic = (automation ?? []).some((site) => site.selfHealing || site.autoUpdates || site.linkRepairs);
  const toggle = (id: string) => setExpanded((current) => { const next = new Set(current); if (next.has(id)) next.delete(id); else next.add(id); return next; });

  return (
    <section className="repair-centre">
      <section className="panel">
        <div className="panel-heading"><div><p className="eyebrow">WHAT THE APP CAN DO</p><h2>Repairs available for your websites</h2></div></div>
        <div className="capability-grid">
          {CAPABILITIES.map((item) => (
            <article className="capability-card" key={item.title}>
              <strong>{item.title}</strong>
              <p>{item.what}</p>
              <small><b>Where:</b> {item.where}</small>
              <small><b>Automatic:</b> {item.automatic}</small>
            </article>
          ))}
        </div>
        <p className="capability-note">Every change keeps an undo copy and is verified afterwards. The app never runs code you did not approve, and nothing outside this list is changed automatically.</p>
      </section>

      <section className="panel">
        <div className="panel-heading"><div><p className="eyebrow">LIVE</p><h2>In progress</h2></div><span className="count-pill">{activeRuns.length + legacyInProgress.length}</span></div>
        {runs === null ? <p className="activity-empty">Loading…</p> : activeRuns.length + legacyInProgress.length === 0 ? <p className="activity-empty">Nothing is running right now.</p> : (
          <ul className="board-compact-list run-progress-list">
            {activeRuns.map((run) => (
              <li key={run.id}>
                <span className="spinner" aria-hidden="true" />
                <div><strong>{run.title}</strong><small>{run.site.name} · {runKind(run)} · {run.status === "approved" ? "waiting for the site" : "running on the site"} · approved {new Date(run.createdAt).toLocaleTimeString()}</small></div>
                <button className="button ghost" onClick={() => onOpenSite(run.site.id, "cleanup")}>Open</button>
              </li>
            ))}
            {legacyInProgress.map((row) => (
              <li key={row.id}>
                <span className="spinner" aria-hidden="true" />
                <div><strong>{row.title}</strong><small>{row.siteName} · repair · {row.status === "approved" ? "waiting for the site" : "running on the site"}</small></div>
                <button className="button ghost" onClick={() => onOpenSite(row.siteId, "overview")}>Open</button>
              </li>
            ))}
          </ul>
        )}
      </section>

      {decisionSlot}

      <section className="panel">
        <div className="panel-heading">
          <div><p className="eyebrow">AUTOMATION</p><h2>What runs without you</h2></div>
          {automation && automation.length > 0 && (anyPaused
            ? <button className="button primary" disabled={busy !== null} onClick={() => changeAutomation("resume", { action: "resume_all" })}>{busy === "resume" ? "Resuming…" : "Resume all automation"}</button>
            : <button className="button danger" disabled={busy !== null || !anyAutomatic} onClick={() => changeAutomation("pause", { action: "pause_all" }, { title: "Pause all automation?", body: "Self-healing, automatic updates and automatic link repairs stop on every website. Queued automatic work that has not started is cancelled. Your switches are kept, so Resume turns them back on.", confirmLabel: "Pause everything", danger: true })}>{busy === "pause" ? "Pausing…" : "Pause all automation"}</button>)}
        </div>
        {automation === null ? <p className="activity-empty">Loading…</p> : automation.length === 0 ? <p className="activity-empty">Add a website first.</p> : (
          <div className="automation-table" role="table" aria-label="Automation per website">
            <div className="automation-row automation-head" role="row">
              <span role="columnheader">Website</span><span role="columnheader">Self-healing</span><span role="columnheader">Automatic updates</span><span role="columnheader">Redirecting links</span>
            </div>
            {automation.map((site) => (
              <div className="automation-row" role="row" key={site.siteId}>
                <span role="cell" className="automation-site"><strong>{site.name}</strong>{site.paused && <span className="pill pill-warn">Paused</span>}</span>
                {(["selfHealing", "autoUpdates", "linkRepairs"] as const).map((key) => (
                  <span role="cell" key={key} className="automation-cell">
                    <span className="automation-label">{key === "selfHealing" ? "Self-healing" : key === "autoUpdates" ? "Automatic updates" : "Redirecting links"}</span>
                    <button className={`switch ${site[key] ? "switch-on" : ""}`} role="switch" aria-checked={site[key]} aria-label={`${key === "selfHealing" ? "Self-healing" : key === "autoUpdates" ? "Automatic updates" : "Automatic link repairs"} for ${site.name}`} disabled={busy !== null}
                      onClick={() => changeAutomation(`${site.siteId}:${key}`, { siteId: site.siteId, [key]: !site[key] }, site[key] ? undefined : {
                        title: `Turn on ${key === "selfHealing" ? "self-healing" : key === "autoUpdates" ? "automatic updates" : "automatic link repairs"} for ${site.name}?`,
                        body: key === "selfHealing" ? "New malware files are quarantined, core files restored, injected .htaccess rules removed and tampered WordPress.org plugins and themes reinstalled automatically (at most 3 times a day), then you are alerted."
                          : key === "autoUpdates" ? "Once a day, WordPress.org plugins and themes with updates are updated, verified and rolled back automatically if the site breaks. Never while security problems are open."
                            : "Links found by the browser scan that permanently redirect are updated to their final address, one exact link at a time, with an undo copy.",
                        confirmLabel: "Turn on",
                      })}>
                      <span className="switch-track" aria-hidden="true"><span className="switch-knob" /></span>
                      <span className="switch-text">{busy === `${site.siteId}:${key}` ? "Saving…" : site[key] ? "On" : "Off"}</span>
                    </button>
                  </span>
                ))}
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-heading"><div><p className="eyebrow">HISTORY</p><h2>What happened</h2></div><span className="count-pill">{history.length}</span></div>
        <div className="board-toolbar history-toolbar" role="search">
          <input type="search" placeholder="Search history" value={query} onChange={(event) => setQuery(event.target.value)} aria-label="Search history" />
          <select value={outcomeFilter} onChange={(event) => setOutcomeFilter(event.target.value)} aria-label="Outcome">
            <option value="all">All outcomes</option><option value="succeeded">Verified</option><option value="attention">Needs attention</option><option value="restored">Restored or rolled back</option><option value="plans">Manual plans</option><option value="rejected">Rejected or stopped</option>
          </select>
          {sites.length > 1 && <select value={siteFilter} onChange={(event) => setSiteFilter(event.target.value)} aria-label="Website"><option value="all">All websites</option>{sites.map(([id, name]) => <option key={id} value={id}>{name}</option>)}</select>}
        </div>
        {filtered.length === 0 ? <p className="activity-empty">{history.length ? "Nothing matches these filters." : "No repairs have run yet."}</p> : (
          <ul className="board-resolved-list history-list">
            {filtered.slice(0, shown).map((entry) => (
              <li key={entry.id}>
                <span className={`pill pill-${entry.outcome.tone}`}>{entry.outcome.label}</span>
                <div><strong>{entry.title}</strong><small>{entry.siteName} · {entry.kind} · {new Date(entry.createdAt).toLocaleString()}</small></div>
                <button className="button ghost board-toggle" aria-expanded={expanded.has(entry.id)} onClick={() => toggle(entry.id)}>{expanded.has(entry.id) ? "Hide" : "Details"}</button>
                {expanded.has(entry.id) && <div className="board-card-details">{entry.detail}</div>}
              </li>
            ))}
          </ul>
        )}
        {filtered.length > shown && <div className="board-footer"><button className="button ghost" onClick={() => setShown((count) => count + HISTORY_PAGE)}>Show more ({filtered.length - shown})</button></div>}
      </section>

      {advancedSlot}
    </section>
  );
}
