"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useConfirm } from "./confirm-dialog";

type Metric = { label: string; value: number | null; display: string | null; score: number | null };
type FieldMetric = { label: string; p75: number; category: string };
type Opportunity = { id: string; title: string; why: string; displayValue: string | null; savingsMs: number | null; savingsBytes: number | null; fix: string | null; manual: string | null; sources: Array<{ name: string; kind: string; bytes: number | null; ms: number | null }> };
type Report = { id: string; strategy: string; score: number | null; metrics: Record<string, Metric>; field: { scope: string; overall: string; metrics: Record<string, FieldMetric> } | null; opportunities: Opportunity[]; error: string | null; createdAt: string };
type Measure = { id: string; title: string; description: string; enabled: boolean; verified: boolean | null; detail: string };
type Performance = {
  keyConfigured: boolean; running: boolean; mobile: Report | null; desktop: Report | null;
  history: Array<{ strategy: string; score: number; createdAt: string }>;
  supported: boolean; pluginVersion: string | null; server: string | null; cachePlugins: string[]; measures: Measure[];
  run: { id: string; status: string; verificationStatus: string; createdAt: string; title: string; steps: string[]; results: Array<{ status: string; message: string }> | null; reasons: string[] } | null;
};

const band = (score: number | null) => score === null ? "unknown" : score >= 90 ? "good" : score >= 50 ? "average" : "poor";
const metricBand = (score: number | null) => score === null ? "unknown" : score >= 0.9 ? "good" : score >= 0.5 ? "average" : "poor";
const fieldBand = (category: string) => category === "FAST" ? "good" : category === "AVERAGE" ? "average" : category === "SLOW" ? "poor" : "unknown";
const formatField = (key: string, value: number) => key === "cls" ? value.toFixed(2) : value >= 1000 ? `${(value / 1000).toFixed(1)} s` : `${Math.round(value)} ms`;
const kb = (bytes: number | null) => bytes === null ? null : bytes >= 1_048_576 ? `${(bytes / 1_048_576).toFixed(1)} MB` : `${Math.round(bytes / 1024)} KB`;
const LAB_ORDER = ["fcp", "lcp", "tbt", "cls", "si", "ttfb"];
const FIELD_ORDER = ["lcp", "inp", "cls", "fcp", "ttfb"];

/** PageSpeed scores, Core Web Vitals, the reasons for a low score and one-click speed fixes. */
export function PerformancePanel({ websiteId, onNotice }: { websiteId: string; onNotice: (message: string) => void }) {
  const dialogs = useConfirm();
  const [data, setData] = useState<Performance | null>(null);
  const [strategy, setStrategy] = useState<"mobile" | "desktop">("mobile");
  const [busy, setBusy] = useState<string | null>(null);
  const [loadError, setLoadError] = useState("");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const load = useCallback(async () => {
    try {
      const response = await fetch(`/api/sites/${websiteId}/performance`, { cache: "no-store" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "Could not load performance data.");
      setData(body);
      setLoadError("");
      return body as Performance;
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "Could not load performance data.");
      return null;
    }
  }, [websiteId]);

  // Poll while a test or a fix is running on the site.
  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      const current = await load();
      if (cancelled) return;
      const active = current && (current.running || (current.run && ["approved", "executing"].includes(current.run.status)));
      timer.current = setTimeout(tick, active ? 5_000 : 60_000);
    };
    void tick();
    return () => { cancelled = true; if (timer.current) clearTimeout(timer.current); };
  }, [load]);

  async function post(key: string, body: Record<string, unknown>, dialog?: { title: string; body: string; confirmLabel: string; danger?: boolean }) {
    if (dialog && !await dialogs.confirm(dialog)) return;
    setBusy(key);
    try {
      const response = await fetch(`/api/sites/${websiteId}/performance`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "The request failed.");
      onNotice(result.message ?? "Approved and sent to the site. It usually runs within a few seconds; the home page is checked after each change and anything that breaks it is switched off again.");
      await load();
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(async function poll() { const current = await load(); if (current && (current.running || (current.run && ["approved", "executing"].includes(current.run.status)))) timer.current = setTimeout(poll, 5_000); }, 5_000);
    } catch (error) {
      onNotice(error instanceof Error ? error.message : "The request failed.");
    } finally {
      setBusy(null);
    }
  }

  if (!data) return <div className="detail-content"><p className="empty-note">{loadError || "Loading…"}</p></div>;
  const report = strategy === "mobile" ? data.mobile : data.desktop;
  const measures = new Map(data.measures.map((measure) => [measure.id, measure]));
  const runActive = Boolean(data.run && ["approved", "executing"].includes(data.run.status));
  const locked = Boolean(busy) || runActive;
  const pluginReady = data.supported;
  const recommended = [...new Set((report?.opportunities ?? []).map((item) => item.fix).filter((fix): fix is string => Boolean(fix) && !measures.get(fix!)?.enabled))];
  const allOff = data.measures.filter((measure) => !measure.enabled).map((measure) => measure.id);
  const titleOf = (id: string) => measures.get(id)?.title ?? id;
  const fixDialog = (ids: string[]) => ({
    title: ids.length === 1 ? `Turn on ${titleOf(ids[0])}?` : `Apply ${ids.length} speed fixes?`,
    body: `${ids.map((id) => `${titleOf(id)}: ${measures.get(id)?.description ?? ""}`).join("\n\n")}\n\nThe home page is checked after each change; anything that breaks it is switched off again automatically, and every change can be switched off here.`,
    confirmLabel: ids.length === 1 ? "Turn on" : "Apply fixes",
  });
  const history = data.history.filter((item) => item.strategy === strategy).slice(-8);

  return (
    <div className="detail-content tab-stack performance-tab">
      <section className="tab-section">
        <div className="tab-section-head">
          <div>
            <h3>Speed &amp; performance</h3>
            <p className="lead">Google PageSpeed Insights for mobile and desktop: the score, Core Web Vitals, what slows the site down, and fixes you can apply here.</p>
          </div>
          <div className="section-actions">
            <div className="segmented" role="tablist" aria-label="Device">
              {(["mobile", "desktop"] as const).map((value) => <button key={value} role="tab" aria-selected={strategy === value} className={strategy === value ? "active" : ""} onClick={() => setStrategy(value)}>{value === "mobile" ? "Mobile" : "Desktop"}</button>)}
            </div>
            <button className="button primary" disabled={Boolean(busy) || data.running} onClick={() => post("test", { action: "test" })}>
              {data.running ? <><span className="spinner" aria-hidden="true" /> Testing…</> : busy === "test" ? "Starting…" : report ? "Test again" : "Run PageSpeed test"}
            </button>
          </div>
        </div>
        {!data.keyConfigured && <div className="callout callout-warn"><p>Google refuses most PageSpeed tests without a key. Add a free PageSpeed key in <strong>Settings → Integrations</strong> (it takes a minute), then run the test.</p></div>}
        {data.running && <div className="progress-banner" role="status"><span className="spinner" aria-hidden="true" /> Testing mobile and desktop. This takes about a minute.</div>}
        {!report ? <p className="empty-note">No test yet. Run a PageSpeed test to see the score and what to fix.</p> : report.error ? <div className="callout callout-warn"><p>{report.error}</p></div> : (
          <>
            <div className="score-row">
              <div className={`score-ring score-${band(report.score)}`} aria-label={`Performance score ${report.score}`}>
                <strong>{report.score ?? "—"}</strong><small>/ 100</small>
              </div>
              <div className="score-text">
                <strong>{band(report.score) === "good" ? "Good" : band(report.score) === "average" ? "Needs improvement" : "Poor"} {strategy} performance</strong>
                <small>Tested {new Date(report.createdAt).toLocaleString()} · 90–100 good · 50–89 needs improvement · 0–49 poor</small>
                {history.length > 1 && <small className="score-history">Recent: {history.map((item, index) => <span key={index} className={`score-chip score-${band(item.score)}`}>{item.score}</span>)}</small>}
              </div>
            </div>
            <h4 className="metric-heading">Lab test (this run)</h4>
            <div className="metric-grid">
              {LAB_ORDER.filter((key) => report.metrics[key]).map((key) => (
                <div className={`metric metric-${metricBand(report.metrics[key].score)}`} key={key}>
                  <small>{report.metrics[key].label}</small><strong>{key === "ttfb" && report.metrics[key].value !== null ? `${Math.round(report.metrics[key].value!)} ms` : report.metrics[key].display ?? "—"}</strong>
                </div>
              ))}
            </div>
            <h4 className="metric-heading">Real visitors (Chrome users, last 28 days{report.field?.scope === "origin" ? ", whole site" : ""})</h4>
            {report.field ? (
              <div className="metric-grid">
                {FIELD_ORDER.filter((key) => report.field!.metrics[key]).map((key) => (
                  <div className={`metric metric-${fieldBand(report.field!.metrics[key].category)}`} key={key}>
                    <small>{report.field!.metrics[key].label}</small><strong>{formatField(key, report.field!.metrics[key].p75)}</strong>
                  </div>
                ))}
              </div>
            ) : <p className="muted-meta">Google has too little real-visitor data for this site, so Interaction to Next Paint (INP) and the other field metrics are not available. Total Blocking Time above is the lab stand-in for INP.</p>}
          </>
        )}
      </section>

      {report && !report.error && (
        <section className="tab-section">
          <div className="tab-section-head">
            <div>
              <h3>Why the score is {band(report.score) === "good" ? "not 100" : "low"}</h3>
              <p className="lead">Biggest savings first. Files are traced to the plugin or theme that loads them.</p>
            </div>
            {pluginReady && recommended.length > 0 && (
              <button className="button primary" disabled={locked} onClick={() => post("fix-all", { action: "fix", changes: recommended.map((measure) => ({ measure, state: "on" })) }, fixDialog(recommended))}>
                {busy === "fix-all" ? "Approving…" : `Apply recommended fixes (${recommended.length})`}
              </button>
            )}
          </div>
          {!pluginReady && <div className="callout callout-warn"><p>One-click speed fixes need AI Website Doctor 0.8.0 or later on the site{data.pluginVersion ? ` (it has ${data.pluginVersion})` : ""}. The diagnosis below still applies.</p></div>}
          {report.opportunities.length === 0 ? <p className="empty-note">No significant problems found in this test.</p> : (
            <div className="opportunity-list">
              {report.opportunities.map((item) => {
                const measure = item.fix ? measures.get(item.fix) : undefined;
                return (
                  <article className="opportunity" key={item.id}>
                    <div className="opportunity-head">
                      <div><strong>{item.title}</strong>{(item.displayValue || item.savingsMs || item.savingsBytes) && <small>{[item.displayValue ?? (kb(item.savingsBytes) ? `Est savings of ${kb(item.savingsBytes)}` : null), item.savingsMs && item.savingsMs >= 100 && !/\bms\b|\bs$/.test(item.displayValue ?? "") ? `about ${(item.savingsMs / 1000).toFixed(1)} s faster` : null].filter(Boolean).join(" · ")}</small>}</div>
                      {measure && (measure.enabled
                        ? <span className={`pill pill-${measure.verified === false ? "warn" : "on"}`}>{measure.verified === false ? "Fix on, not effective" : "Fix applied"}</span>
                        : pluginReady && <button className="button secondary" disabled={locked} onClick={() => post(`fix:${measure.id}`, { action: "fix", changes: [{ measure: measure.id, state: "on" }] }, fixDialog([measure.id]))}>{busy === `fix:${measure.id}` ? "Approving…" : `Fix: ${measure.title}`}</button>)}
                    </div>
                    <p>{item.why}</p>
                    {item.sources.length > 0 && <div className="source-chips">{item.sources.map((source) => <span key={source.name} className={`source-chip source-${source.kind}`}>{source.name}{source.bytes ? ` · ${kb(source.bytes)}` : source.ms ? ` · ${Math.round(source.ms)} ms` : ""}</span>)}</div>}
                    {measure?.enabled && measure.verified === false && measure.detail && <p className="muted-meta">{measure.detail}</p>}
                    {item.manual && <p className="muted-meta">{measure ? "Also: " : "How to fix: "}{item.manual}</p>}
                  </article>
                );
              })}
            </div>
          )}
        </section>
      )}

      <section className="tab-section">
        <div className="tab-section-head">
          <div>
            <h3>Speed fixes on this site</h3>
            <p className="lead">{data.server ? `Server: ${data.server}. ` : ""}{data.cachePlugins.length ? `Cache plugin: ${data.cachePlugins.join(", ")}.` : "No cache plugin is active."} Each fix is reversible.</p>
          </div>
          {pluginReady && allOff.length > 0 && (
            <button className="button primary" disabled={locked} onClick={() => post("all-on", { action: "fix", changes: allOff.map((measure) => ({ measure, state: "on" })) }, fixDialog(allOff))}>
              {busy === "all-on" ? "Approving…" : `Turn on all speed fixes (${allOff.length})`}
            </button>
          )}
        </div>
        {data.run && (
          <div className={`callout ${runActive ? "" : data.run.status === "verified" ? "callout-ok" : "callout-warn"}`}>
            <p><strong>{data.run.title}</strong>: {runActive ? "running on the site…" : data.run.status === "verified" ? "done and verified." : `finished with problems.`} {data.run.results?.filter((result) => result.status !== "applied").map((result) => result.message).join(" ")}</p>
            {!runActive && data.run.status === "verified" && <p className="muted-meta">Run the PageSpeed test again to see the effect (scores vary by a few points between runs).</p>}
          </div>
        )}
        <div className="measure-list">
          {data.measures.map((measure) => (
            <div className="measure-row" key={measure.id}>
              <div className="measure-text">
                <div className="measure-title"><strong>{measure.title}</strong><span className={`pill pill-${!measure.enabled ? "off" : measure.verified === false ? "warn" : "on"}`}>{!measure.enabled ? "Off" : measure.verified === false ? "Not effective here" : measure.verified ? "On · verified" : "On"}</span></div>
                <p>{measure.description}</p>
                {measure.enabled && measure.detail && <small>{measure.detail}</small>}
              </div>
              <button className={`button measure-toggle ${measure.enabled ? "is-on" : ""}`} disabled={locked || !pluginReady}
                onClick={() => post(`measure:${measure.id}`, { action: "fix", changes: [{ measure: measure.id, state: measure.enabled ? "off" : "on" }] }, measure.enabled ? { title: `Turn off ${measure.title}?`, body: "The site goes back to how it was before this fix.", confirmLabel: "Turn off", danger: true } : fixDialog([measure.id]))}>
                {busy === `measure:${measure.id}` ? "Approving…" : measure.enabled ? "Turn off" : "Turn on"}
              </button>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
