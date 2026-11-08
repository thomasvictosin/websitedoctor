"use client";

import { useMemo, useState, type ReactNode } from "react";

/** The fields the board needs; the dashboard's full Issue type satisfies it. */
export type BoardIssue = {
  id: string;
  fingerprint: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  source: string;
  lastSeenAt: string;
  resolvedAt?: string | null;
  website: { id: string; name: string };
};

type StatusFilter = "open" | "resolved" | "all";
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const RESOLVED_PAGE = 20;
const OPEN_PAGE = 30;

export const isOpenIssue = (issue: { status: string }) => issue.status !== "resolved";
const bySeverityThenRecent = (a: BoardIssue, b: BoardIssue) =>
  (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0) || Date.parse(b.lastSeenAt) - Date.parse(a.lastSeenAt);
const isPluginUpdate = (issue: BoardIssue) => issue.fingerprint.startsWith("wp:plugin-update:");

function sourceLabel(source: string) {
  return ({ wordpress_plugin: "WordPress plugin", security_probe: "Outside security check", vulnerability_feed: "Known vulnerability", browser_monitor: "Browser scan", availability_check: "Availability" } as Record<string, string>)[source] ?? source.replaceAll("_", " ");
}

function timeAgo(value: string | null | undefined) {
  if (!value) return "";
  const minutes = Math.round((Date.now() - Date.parse(value)) / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} h ago`;
  return new Date(value).toLocaleDateString();
}

/**
 * Issues organised for many websites: open first and worst first, grouped by
 * website, compact cards with details on demand, plugin updates folded into
 * one card per site, and resolved issues tucked into a short paged list.
 */
export function IssueBoard<T extends BoardIssue>({
  issues,
  mode,
  renderDetails,
  renderPrimary,
  onOpenSite,
  onUpdateAll,
  onViewAll,
  updateAllBusySiteId,
}: {
  issues: T[];
  mode: "full" | "summary" | "site";
  renderDetails: (issue: T) => ReactNode;
  renderPrimary: (issue: T) => ReactNode;
  onOpenSite?: (siteId: string) => void;
  onUpdateAll?: (siteId: string) => void;
  onViewAll?: () => void;
  updateAllBusySiteId?: string | null;
}) {
  const [status, setStatus] = useState<StatusFilter>("open");
  const [severity, setSeverity] = useState("all");
  const [siteId, setSiteId] = useState("all");
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [resolvedShown, setResolvedShown] = useState(RESOLVED_PAGE);
  const [openShown, setOpenShown] = useState(OPEN_PAGE);

  const sites = useMemo(() => {
    const map = new Map<string, string>();
    for (const issue of issues) map.set(issue.website.id, issue.website.name);
    return [...map.entries()].sort((a, b) => a[1].localeCompare(b[1]));
  }, [issues]);
  const openCount = issues.filter(isOpenIssue).length;
  const resolvedCount = issues.length - openCount;

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return issues.filter((issue) => (status === "all" || (status === "open" ? isOpenIssue(issue) : !isOpenIssue(issue)))
      && (severity === "all" || issue.severity === severity)
      && (siteId === "all" || issue.website.id === siteId)
      && (!needle || `${issue.title} ${issue.description} ${issue.website.name}`.toLowerCase().includes(needle)));
  }, [issues, status, severity, siteId, query]);

  const toggle = (id: string) => setExpanded((current) => {
    const next = new Set(current);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });

  if (mode === "summary") {
    const top = issues.filter(isOpenIssue).sort(bySeverityThenRecent).slice(0, 5);
    return (
      <div className="board-summary">
        {top.length === 0 ? <p className="activity-empty">No open issues. Everything that was found has been resolved.</p> : (
          <ul className="board-compact-list">
            {top.map((issue) => (
              <li key={issue.id}>
                <span className={`severity severity-${issue.severity}`}>{issue.severity}</span>
                <div><strong>{issue.title}</strong><small>{issue.website.name} · {timeAgo(issue.lastSeenAt)}</small></div>
                {onOpenSite && <button className="button ghost" onClick={() => onOpenSite(issue.website.id)}>Open site</button>}
              </li>
            ))}
          </ul>
        )}
        {onViewAll && <div className="board-footer"><button className="button secondary" onClick={onViewAll}>View all issues ({openCount} open · {resolvedCount} resolved)</button></div>}
      </div>
    );
  }

  const open = filtered.filter(isOpenIssue).sort(bySeverityThenRecent);
  const resolved = filtered.filter((issue) => !isOpenIssue(issue)).sort((a, b) => Date.parse(b.resolvedAt ?? b.lastSeenAt) - Date.parse(a.resolvedAt ?? a.lastSeenAt));
  const visibleOpen = open.slice(0, openShown);
  const groupBySite = mode === "full" && siteId === "all" && sites.length > 1;
  const groups = groupBySite
    ? sites.map(([id, name]) => ({ id, name, items: visibleOpen.filter((issue) => issue.website.id === id) })).filter((group) => group.items.length)
      .sort((a, b) => bySeverityThenRecent(a.items[0], b.items[0]))
    : [{ id: siteId, name: "", items: visibleOpen }];

  const renderCard = (issue: T) => {
    const isExpanded = expanded.has(issue.id);
    return (
      <article className={`board-card severity-edge-${issue.severity}`} key={issue.id}>
        <div className="board-card-head">
          <span className={`severity severity-${issue.severity}`}>{issue.severity}</span>
          <div className="board-card-title">
            <strong>{issue.title}</strong>
            <small>{mode === "full" && !groupBySite ? `${issue.website.name} · ` : ""}{sourceLabel(issue.source)} · {timeAgo(issue.lastSeenAt)}</small>
          </div>
          {issue.status === "acknowledged" && <span className="issue-state">acknowledged</span>}
        </div>
        <p className="board-card-description">{issue.description}</p>
        <div className="board-card-actions">
          {renderPrimary(issue)}
          <button className="button ghost board-toggle" aria-expanded={isExpanded} onClick={() => toggle(issue.id)}>{isExpanded ? "Hide details" : "Details & more actions"}</button>
        </div>
        {isExpanded && <div className="board-card-details">{renderDetails(issue)}</div>}
      </article>
    );
  };

  const renderItems = (items: T[], groupSiteId: string) => {
    const updates = items.filter(isPluginUpdate);
    const others = items.filter((issue) => !isPluginUpdate(issue));
    const folded = updates.length >= 2;
    const updatesCard = folded ? (
      <article className="board-card severity-edge-low" key={`updates-${groupSiteId}`}>
        <div className="board-card-head">
          <span className="severity severity-low">low</span>
          <div className="board-card-title"><strong>{updates.length} plugin updates available</strong><small>WordPress plugin · updates are verified and rolled back if the site breaks</small></div>
          {onUpdateAll && groupSiteId !== "all" && (
            <button className="button secondary" disabled={updateAllBusySiteId === groupSiteId} onClick={() => onUpdateAll(groupSiteId)}>
              {updateAllBusySiteId === groupSiteId ? "Approving…" : "Update all"}
            </button>
          )}
        </div>
        <ul className="board-update-list">
          {updates.map((issue) => (
            <li key={issue.id}>
              <span>{issue.title.replace(/^Plugin update available:\s*/, "")}</span>
              <div className="board-update-actions">
                {renderPrimary(issue)}
                <button className="button ghost board-toggle" aria-expanded={expanded.has(issue.id)} onClick={() => toggle(issue.id)}>{expanded.has(issue.id) ? "Hide" : "Details"}</button>
              </div>
              {expanded.has(issue.id) && <div className="board-card-details">{renderDetails(issue)}</div>}
            </li>
          ))}
        </ul>
      </article>
    ) : null;
    return <>{others.map(renderCard)}{folded ? updatesCard : updates.map(renderCard)}</>;
  };

  return (
    <div className="issue-board">
      <div className="board-toolbar" role="search">
        <div className="segmented" role="tablist" aria-label="Issue status">
          {([["open", `Open (${openCount})`], ["resolved", `Resolved (${resolvedCount})`], ["all", "All"]] as const).map(([value, label]) => (
            <button key={value} role="tab" aria-selected={status === value} className={status === value ? "active" : ""} onClick={() => setStatus(value)}>{label}</button>
          ))}
        </div>
        <input type="search" placeholder="Search issues" value={query} onChange={(event) => setQuery(event.target.value)} aria-label="Search issues" />
        <select value={severity} onChange={(event) => setSeverity(event.target.value)} aria-label="Severity">
          <option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
        </select>
        {mode === "full" && sites.length > 1 && (
          <select value={siteId} onChange={(event) => setSiteId(event.target.value)} aria-label="Website">
            <option value="all">All websites ({sites.length})</option>
            {sites.map(([id, name]) => <option key={id} value={id}>{name}</option>)}
          </select>
        )}
      </div>

      {status !== "resolved" && (
        open.length === 0
          ? <p className="board-empty">{issues.some(isOpenIssue) ? "No open issues match these filters." : "No open issues. Everything that was found has been resolved."}</p>
          : <>
            {groups.map((group) => (
              <section className="board-group" key={group.id}>
                {groupBySite && (
                  <header className="board-group-head">
                    <div><strong>{group.name}</strong><small>{group.items.length} open issue(s)</small></div>
                    {onOpenSite && <button className="button ghost" onClick={() => onOpenSite(group.id)}>Open website</button>}
                  </header>
                )}
                <div className="board-cards">{renderItems(group.items, group.id)}</div>
              </section>
            ))}
            {open.length > openShown && <div className="board-footer"><button className="button secondary" onClick={() => setOpenShown((count) => count + OPEN_PAGE)}>Show more open issues ({open.length - openShown} more)</button></div>}
          </>
      )}

      {status !== "open" && (
        <section className="board-resolved">
          {status === "all" && <h3 className="board-section-title">Resolved ({resolved.length})</h3>}
          {resolved.length === 0 ? <p className="board-empty">No resolved issues match these filters.</p> : (
            <ul className="board-resolved-list">
              {resolved.slice(0, resolvedShown).map((issue) => (
                <li key={issue.id}>
                  <span className="board-resolved-mark" aria-hidden="true">✓</span>
                  <div><strong>{issue.title}</strong><small>{issue.website.name} · {issue.severity} · resolved {timeAgo(issue.resolvedAt ?? issue.lastSeenAt)}</small></div>
                  <button className="button ghost board-toggle" aria-expanded={expanded.has(issue.id)} onClick={() => toggle(issue.id)}>{expanded.has(issue.id) ? "Hide" : "Details"}</button>
                  {expanded.has(issue.id) && <div className="board-card-details">{renderDetails(issue)}</div>}
                </li>
              ))}
            </ul>
          )}
          {resolved.length > resolvedShown && <div className="board-footer"><button className="button ghost" onClick={() => setResolvedShown((count) => count + RESOLVED_PAGE)}>Show {Math.min(RESOLVED_PAGE, resolved.length - resolvedShown)} more resolved</button></div>}
        </section>
      )}
    </div>
  );
}
