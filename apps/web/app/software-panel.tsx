"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export type UploadTarget = { websiteId: string; kind: "plugin" | "theme"; target: string; name: string; installedVersion: string; fixedIn?: string | null; issueId?: string | null };
type Scan = { status: string; name: string | null; version: string | null; files: number; phpFiles: number; blockers: string[]; warnings: string[]; malware: Array<{ file: string; signatures: string[]; strong: boolean }>; vulnerabilities: Array<{ title: string; fixedIn: string | null }> };
type Package = { id: string; kind: string; target: string; name: string | null; version: string | null; fileName: string; size: number; status: string; scan: Scan | null; createdAt: string };

const mb = (bytes: number) => `${(bytes / 1_048_576).toFixed(1)} MB`;

/** Upload a plugin/theme zip, see the scan, and install it on the site. */
export function PackageUploadDialog({ target, onClose, onDone }: { target: UploadTarget | null; onClose: () => void; onDone: (message: string) => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [stage, setStage] = useState<"choose" | "uploading" | "scanned" | "installing">("choose");
  const [progress, setProgress] = useState(0);
  const [pkg, setPkg] = useState<Package | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (target) {
      setFile(null); setStage("choose"); setProgress(0); setPkg(null); setError("");
      if (!dialog.current?.open) dialog.current?.showModal();
    } else if (dialog.current?.open) dialog.current.close();
  }, [target]);

  async function upload() {
    if (!target || !file) return;
    setError("");
    setStage("uploading");
    try {
      const bytes = await file.arrayBuffer();
      const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))).map((byte) => byte.toString(16).padStart(2, "0")).join("");
      const created = await fetch(`/api/sites/${target.websiteId}/packages`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ kind: target.kind, target: target.target, fileName: file.name, size: file.size, sha256: digest }) });
      const start = await created.json();
      if (!created.ok) throw new Error(start.error ?? "The upload could not start.");
      for (let index = 0; index < start.chunkCount; index += 1) {
        const piece = bytes.slice(index * start.chunkBytes, Math.min(file.size, (index + 1) * start.chunkBytes));
        let sent = false;
        for (let attempt = 0; attempt < 3 && !sent; attempt += 1) {
          const response = await fetch(`/api/packages/${start.packageId}/chunks/${index}`, { method: "PUT", headers: { "content-type": "application/octet-stream" }, body: piece });
          if (response.ok) sent = true;
          else if (attempt === 2) throw new Error((await response.json().catch(() => ({}))).error ?? `Piece ${index + 1} failed to upload.`);
        }
        setProgress(Math.round(((index + 1) / start.chunkCount) * 100));
      }
      const finalized = await fetch(`/api/packages/${start.packageId}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "finalize" }) });
      const result = await finalized.json();
      if (!finalized.ok) throw new Error(result.error ?? "The package could not be checked.");
      setPkg(result.package);
      setStage("scanned");
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "The upload failed.");
      setStage("choose");
    }
  }

  async function install() {
    if (!target || !pkg) return;
    setStage("installing");
    try {
      const response = await fetch(`/api/packages/${pkg.id}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "install", issueId: target.issueId ?? null }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "The install could not be approved.");
      onDone(`Approved: ${pkg.name ?? target.name} ${pkg.version} is being installed on the site. The current version is kept and put back automatically if anything fails.`);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "The install could not be approved.");
      setStage("scanned");
    }
  }

  const scan = pkg?.scan;
  return (
    <dialog ref={dialog} className="confirm-dialog upload-dialog" onClose={onClose} onCancel={(event) => { if (stage === "uploading" || stage === "installing") event.preventDefault(); }}>
      {target && (
        <div className="upload-dialog-body">
          <h2>Install a new version of {target.name}</h2>
          <p>Installed: {target.kind} {target.name} {target.installedVersion || ""}{target.fixedIn ? ` · the vulnerability is fixed in ${target.fixedIn} or later` : ""}.</p>
          {stage === "choose" && (
            <>
              <ol className="step-list numbered">
                <li><span>Download the installable zip from the vendor&apos;s account area (for example CodeCanyon → Downloads → &quot;Installable WordPress file only&quot;).</span></li>
                <li><span>Choose it below. It is checked before anything changes: same folder and main file, version, malware patterns, and known vulnerabilities.</span></li>
              </ol>
              <input type="file" accept=".zip,application/zip" onChange={(event) => setFile(event.target.files?.[0] ?? null)} aria-label="Package zip file" />
              {file && <p className="muted-meta">{file.name} · {mb(file.size)}</p>}
            </>
          )}
          {stage === "uploading" && <div className="upload-progress" role="status"><div className="upload-bar"><span style={{ width: `${progress}%` }} /></div><small>{progress < 100 ? `Uploading… ${progress}%` : "Checking and scanning the package…"}</small></div>}
          {(stage === "scanned" || stage === "installing") && scan && (
            <div className={`callout ${scan.status === "ready" ? "callout-ok" : "callout-warn"}`}>
              <p><strong>{scan.status === "ready" ? `Passed: ${scan.name ?? target.name} ${scan.version}` : "Not safe to install"}</strong> · {scan.files} files, {scan.phpFiles} PHP files scanned.</p>
              {scan.blockers.length > 0 && <ul>{scan.blockers.map((item) => <li key={item}>{item}</li>)}</ul>}
              {scan.warnings.length > 0 && <><p className="muted-meta">Please read:</p><ul>{scan.warnings.map((item) => <li key={item}>{item}</li>)}</ul></>}
            </div>
          )}
          {error && <div className="callout callout-warn"><p>{error}</p></div>}
          <div className="confirm-actions">
            <button className="button ghost" disabled={stage === "uploading" || stage === "installing"} onClick={() => dialog.current?.close()}>{stage === "scanned" ? "Close" : "Cancel"}</button>
            {stage === "choose" && <button className="button primary" disabled={!file} onClick={upload}>Upload and scan</button>}
            {(stage === "scanned" || stage === "installing") && scan?.status === "ready" && <button className="button primary" disabled={stage === "installing"} onClick={install}>{stage === "installing" ? "Approving…" : "Install on the site"}</button>}
          </div>
        </div>
      )}
    </dialog>
  );
}

type Software = { kind: "plugin" | "theme"; target: string; name: string; version: string; active: boolean; source: string; newVersion: string | null };
type IssueLike = { id: string; fingerprint: string; title: string; severity: string; status: string; evidence?: unknown };

/** Every plugin and theme on the site, what needs attention, and uploads for premium software. */
export function SoftwarePanel({ websiteId, diagnostics, issues, onUpload, onFix }: { websiteId: string; diagnostics: unknown; issues: IssueLike[]; onUpload: (target: UploadTarget) => void; onFix: (issueId: string) => void }) {
  const [packages, setPackages] = useState<Package[]>([]);
  const [filter, setFilter] = useState<"attention" | "all">("attention");
  const data = (diagnostics ?? {}) as { plugins?: Array<Record<string, unknown>>; themes?: Array<Record<string, unknown>> };
  const software: Software[] = [
    ...(data.plugins ?? []).filter((plugin) => typeof plugin.file === "string" && String(plugin.file).includes("/") && !String(plugin.file).startsWith("ai-website-doctor/")).map((plugin) => ({ kind: "plugin" as const, target: String(plugin.file), name: String(plugin.name ?? plugin.file), version: String(plugin.version ?? ""), active: Boolean(plugin.active), source: String(plugin.source ?? "other"), newVersion: typeof plugin.newVersion === "string" ? plugin.newVersion : null })),
    ...(data.themes ?? []).filter((theme) => typeof theme.stylesheet === "string").map((theme) => ({ kind: "theme" as const, target: String(theme.stylesheet), name: String(theme.name ?? theme.stylesheet), version: String(theme.version ?? ""), active: Boolean(theme.active || theme.parentOfActive), source: String(theme.source ?? "other"), newVersion: typeof theme.newVersion === "string" ? theme.newVersion : null })),
  ];
  const load = useCallback(async () => {
    try {
      const response = await fetch(`/api/sites/${websiteId}/packages`, { cache: "no-store" });
      const body = await response.json();
      if (response.ok) setPackages(body.packages);
    } catch { /* list stays empty */ }
  }, [websiteId]);
  useEffect(() => { void load(); }, [load]);

  const vulnFor = (item: Software) => issues.filter((issue) => issue.status !== "resolved" && issue.fingerprint.startsWith(`vuln:${item.kind}-${item.kind === "plugin" ? item.target.split("/")[0] : item.target}:`));
  const rows = software.map((item) => ({ item, vulns: vulnFor(item) })).sort((a, b) => b.vulns.length - a.vulns.length || Number(Boolean(b.item.newVersion)) - Number(Boolean(a.item.newVersion)) || a.item.name.localeCompare(b.item.name));
  const needsAttention = rows.filter((row) => row.vulns.length || row.item.newVersion);
  const visible = filter === "attention" ? needsAttention : rows;
  const fixedIn = (vulns: IssueLike[]) => vulns.map((issue) => (issue.evidence as { fixedIn?: string } | undefined)?.fixedIn).filter((value): value is string => typeof value === "string").sort().at(-1) ?? null;

  return (
    <div className="detail-content tab-stack">
      <section className="tab-section">
        <div className="tab-section-head">
          <div>
            <h3>Plugins &amp; themes</h3>
            <p className="lead">{software.length} installed. WordPress.org software updates with one click from Issues. Premium software (from CodeCanyon, ThemeForest or a vendor) is updated by uploading the vendor&apos;s zip here: it is scanned first and the current version is kept for rollback.</p>
          </div>
          <div className="segmented" role="tablist" aria-label="Show">
            <button role="tab" aria-selected={filter === "attention"} className={filter === "attention" ? "active" : ""} onClick={() => setFilter("attention")}>Needs attention ({needsAttention.length})</button>
            <button role="tab" aria-selected={filter === "all"} className={filter === "all" ? "active" : ""} onClick={() => setFilter("all")}>All ({rows.length})</button>
          </div>
        </div>
        {software.length === 0 ? <p className="empty-note">The WordPress plugin has not reported any software yet.</p> : visible.length === 0 ? <p className="empty-note">Everything is up to date and no known vulnerabilities match.</p> : (
          <div className="software-list">
            {visible.map(({ item, vulns }) => {
              const premium = item.source !== "wordpress.org";
              const fixed = fixedIn(vulns);
              return (
                <article className="software-row" key={`${item.kind}:${item.target}`}>
                  <div className="software-main">
                    <strong>{item.name}</strong>
                    <small>{item.kind === "theme" ? "Theme" : "Plugin"} · {item.version || "no version"}{item.active ? " · active" : " · inactive"} · {premium ? "premium / other source" : "WordPress.org"}{item.newVersion ? ` · update ${item.newVersion} available` : ""}</small>
                    {vulns.length > 0 && <div className="software-vulns">{vulns.slice(0, 3).map((issue) => <span key={issue.id} className={`severity severity-${issue.severity}`} title={issue.title}>{issue.severity}</span>)}<small>{vulns.length} known vulnerabilit{vulns.length === 1 ? "y" : "ies"}{fixed ? ` · fixed in ${fixed}` : " · no fixed version yet"}</small></div>}
                  </div>
                  <div className="software-actions">
                    {vulns.length > 0 && !premium && <button className="button secondary" onClick={() => onFix(vulns[0].id)}>Fix</button>}
                    {vulns.length > 0 && premium && !fixed && <button className="button secondary" onClick={() => onFix(vulns[0].id)}>Remove until fixed</button>}
                    {(premium || vulns.length > 0) && <button className={`button ${premium && (vulns.length || item.newVersion) ? "primary" : "ghost"}`} onClick={() => onUpload({ websiteId, kind: item.kind, target: item.target, name: item.name, installedVersion: item.version, fixedIn: fixed, issueId: vulns[0]?.id ?? null })}>Upload new version</button>}
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </section>
      {packages.length > 0 && (
        <section className="tab-section">
          <div className="tab-section-head"><div><h3>Uploaded packages</h3><p className="lead">Kept for 14 days after installing.</p></div><button className="button ghost" onClick={load}>Refresh</button></div>
          <ul className="package-list">
            {packages.map((pkg) => (
              <li key={pkg.id}>
                <span className={`pill pill-${pkg.status === "installed" || pkg.status === "ready" ? "on" : pkg.status === "blocked" || pkg.status === "failed" ? "warn" : "off"}`}>{({ uploading: "Upload incomplete", ready: "Passed scan", blocked: "Blocked by scan", installing: "Installing", installed: "Installed", failed: "Install failed", expired: "Expired" } as Record<string, string>)[pkg.status] ?? pkg.status}</span>
                <div><strong>{pkg.name ?? pkg.target} {pkg.version ?? ""}</strong><small>{pkg.fileName} · {mb(pkg.size)} · {new Date(pkg.createdAt).toLocaleString()}</small></div>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
