import { createHash } from "node:crypto";

type DiagnosticIssue = { fingerprint?: unknown; severity?: unknown };

export function verifyBrowserConflictRepair(input: {
  issueFingerprint: string;
  issueEvidence: unknown;
  scan: { status?: unknown; crawlIncomplete?: unknown; findings?: unknown };
}): { status: "passed" | "failed" | "inconclusive"; reason: string; regressions: string[] } {
  if (!input.issueFingerprint.startsWith("wp:staging-conflict:")) {
    return { status: "inconclusive", reason: "This issue is not a staging-isolated browser conflict.", regressions: [] };
  }
  const evidence = input.issueEvidence && typeof input.issueEvidence === "object" && !Array.isArray(input.issueEvidence)
    ? input.issueEvidence as Record<string, unknown>
    : {};
  const report = evidence.conflictTesting && typeof evidence.conflictTesting === "object" && !Array.isArray(evidence.conflictTesting)
    ? evidence.conflictTesting as Record<string, unknown>
    : {};
  if (report.environment !== "disposable_staging" || report.status !== "completed" || report.liveDeactivationPerformed !== false) {
    return { status: "inconclusive", reason: "The issue has no validated disposable-staging evidence.", regressions: [] };
  }
  const rawFindingId = input.issueFingerprint.slice("wp:".length);
  const test = (Array.isArray(report.findings) ? report.findings : []).find((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) return false;
    const finding = item as Record<string, unknown>;
    const components = Array.isArray(finding.components) ? finding.components.filter((part): part is string => typeof part === "string") : [];
    const fingerprint = `staging-conflict:${createHash("sha256").update(components.join("|")).digest("hex").slice(0, 32)}`;
    return fingerprint === rawFindingId && finding.result === "conflict";
  }) as Record<string, unknown> | undefined;
  const baseline = readBrowserFindingSet(test?.baselineFindings);
  const stagedProbe = readBrowserFindingSet(test?.probeFindings);
  const resolvedByStaging = [...baseline].filter((fingerprint) => !stagedProbe.has(fingerprint));
  if (!test || resolvedByStaging.length === 0) {
    return { status: "inconclusive", reason: "The staging result did not record browser findings resolved by the proposed component change.", regressions: [] };
  }
  if (!Array.isArray(input.scan.findings) || !["passed", "issues_found", "partial"].includes(String(input.scan.status))) {
    return { status: "inconclusive", reason: "The central post-repair browser scan is unavailable or malformed.", regressions: [] };
  }
  if (input.scan.status === "partial" || input.scan.crawlIncomplete === true) {
    return { status: "inconclusive", reason: "The central post-repair browser scan was incomplete.", regressions: [] };
  }
  const afterFindings = input.scan.findings.flatMap((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) return [];
    const finding = item as Record<string, unknown>;
    return typeof finding.fingerprint === "string" ? [{ fingerprint: finding.fingerprint, severity: finding.severity }] : [];
  });
  const remaining = resolvedByStaging.filter((fingerprint) => afterFindings.some((finding) => finding.fingerprint === fingerprint));
  if (remaining.length > 0) {
    return { status: "failed", reason: "The central browser retest still reports findings that the staging repair was expected to remove.", regressions: remaining };
  }
  const baselineHigh = new Set(readBrowserFindingSet(test.baselineFindings, ["high", "critical"]));
  const regressions = afterFindings.flatMap((finding) =>
    (finding.severity === "high" || finding.severity === "critical") && !baselineHigh.has(finding.fingerprint)
      ? [finding.fingerprint]
      : []);
  if (regressions.length) {
    return { status: "failed", reason: "The central browser retest found new high-severity regressions.", regressions };
  }
  return { status: "passed", reason: "The central browser retest cleared the staged findings and found no new high-severity regression.", regressions: [] };
}

export function verifyBrowserLayoutRepair(input: {
  issueFingerprint: string;
  scan: { status?: unknown; crawlIncomplete?: unknown; findings?: unknown };
}): { status: "passed" | "failed" | "inconclusive"; reason: string; regressions: string[] } {
  if (!input.issueFingerprint.startsWith("browser:horizontal-overflow:")) {
    return { status: "inconclusive", reason: "This is not a supported responsive layout finding.", regressions: [] };
  }
  if (!Array.isArray(input.scan.findings) || !["passed", "issues_found"].includes(String(input.scan.status))
    || input.scan.crawlIncomplete === true) {
    return { status: "inconclusive", reason: "The post-repair browser scan was unavailable or incomplete.", regressions: [] };
  }
  const stillOverflows = input.scan.findings.some((raw) => raw && typeof raw === "object" && !Array.isArray(raw)
    && (raw as Record<string, unknown>).fingerprint === input.issueFingerprint);
  return stillOverflows
    ? { status: "failed", reason: "The horizontal-overflow finding remains after the staging rescan.", regressions: [input.issueFingerprint] }
    : { status: "passed", reason: "The complete staging browser rescan no longer reports the original horizontal-overflow finding.", regressions: [] };
}

export function verifyBrowserLinkRepair(input: {
  issueFingerprint: string;
  issueEvidence: unknown;
  scan: { status?: unknown; findings?: unknown; pages?: unknown };
  siteAvailability?: { available?: unknown; statusCode?: unknown } | null;
  destinationAvailability?: { available?: unknown; statusCode?: unknown; finalUrl?: unknown } | null;
}): { status: "passed" | "failed" | "inconclusive"; reason: string; regressions: string[] } {
  const isRedirectRepair = input.issueFingerprint.startsWith("browser:link-redirect:");
  const isBrokenLinkRepair = input.issueFingerprint.startsWith("browser:broken-link:");
  if (!isRedirectRepair && !isBrokenLinkRepair) {
    return { status: "inconclusive", reason: "This is not a supported browser link finding.", regressions: [] };
  }
  const evidence = input.issueEvidence && typeof input.issueEvidence === "object" && !Array.isArray(input.issueEvidence)
    ? input.issueEvidence as Record<string, unknown>
    : {};
  const browser = evidence.browser && typeof evidence.browser === "object" && !Array.isArray(evidence.browser)
    ? evidence.browser as Record<string, unknown>
    : {};
  const finding = browser.finding && typeof browser.finding === "object" && !Array.isArray(browser.finding)
    ? browser.finding as Record<string, unknown>
    : {};
  const replacementValue = isRedirectRepair ? finding.replacementUrl : input.issueEvidence && typeof input.issueEvidence === "object"
    && !Array.isArray(input.issueEvidence) && typeof (input.issueEvidence as Record<string, unknown>).requestedReplacementUrl === "string"
    ? (input.issueEvidence as Record<string, unknown>).requestedReplacementUrl
    : null;
  if (typeof finding.sourcePage !== "string" || typeof replacementValue !== "string") {
    return { status: "inconclusive", reason: "The original source page or selected replacement URL is missing.", regressions: [] };
  }
  const successfulHttpCheck = (check: { available?: unknown; statusCode?: unknown } | null | undefined) =>
    check?.available === true && typeof check.statusCode === "number" && check.statusCode >= 200 && check.statusCode < 300;
  if (!input.siteAvailability || typeof input.siteAvailability.available !== "boolean"
    || typeof input.siteAvailability.statusCode !== "number") {
    return { status: "inconclusive", reason: "Independent site availability could not be confirmed after the link change.", regressions: [] };
  }
  if (!successfulHttpCheck(input.siteAvailability)) {
    return { status: "failed", reason: `The site availability check failed after the link change${typeof input.siteAvailability.statusCode === "number" ? ` (HTTP ${input.siteAvailability.statusCode})` : ""}.`, regressions: [] };
  }
  if (!input.destinationAvailability || typeof input.destinationAvailability.available !== "boolean"
    || typeof input.destinationAvailability.statusCode !== "number" || typeof input.destinationAvailability.finalUrl !== "string") {
    return { status: "inconclusive", reason: "Independent availability of the selected replacement URL could not be confirmed.", regressions: [] };
  }
  if (!successfulHttpCheck(input.destinationAvailability)) {
    return { status: "failed", reason: `The selected replacement URL did not respond successfully${typeof input.destinationAvailability.statusCode === "number" ? ` (HTTP ${input.destinationAvailability.statusCode})` : ""}.`, regressions: [] };
  }
  const replacementUrl = replacementValue;
  const canonical = (value: string) => {
    try {
      const url = new URL(value);
      url.hash = "";
      if (url.pathname !== "/") url.pathname = url.pathname.replace(/\/+$/, "") || "/";
      return `${url.origin}${url.pathname}${url.search}`;
    } catch { return ""; }
  };
  if (canonical(input.destinationAvailability.finalUrl) !== canonical(replacementUrl)) {
    return { status: "failed", reason: "The selected replacement URL redirected to a different final URL during independent verification.", regressions: [] };
  }
  if (!Array.isArray(input.scan.findings) || !Array.isArray(input.scan.pages)
    || !["passed", "issues_found", "partial"].includes(String(input.scan.status))) {
    return { status: "inconclusive", reason: "The central post-repair browser scan is unavailable or malformed.", regressions: [] };
  }
  if (input.scan.status === "partial") {
    return { status: "inconclusive", reason: "The central post-repair browser scan was partial, so the destination could not be verified reliably.", regressions: [] };
  }
  const sourceKey = canonical(finding.sourcePage);
  const sourcePage = input.scan.pages.find((raw) => raw && typeof raw === "object" && !Array.isArray(raw)
    && canonical(String((raw as Record<string, unknown>).url ?? "")) === sourceKey) as Record<string, unknown> | undefined;
  if (!sourcePage) return { status: "inconclusive", reason: "The source page was not included in the post-repair scan.", regressions: [] };
  if (typeof sourcePage.statusCode !== "number" || sourcePage.statusCode < 200 || sourcePage.statusCode >= 400) {
    return { status: "failed", reason: "The source page is not reachable after the link change.", regressions: [] };
  }
  if (sourcePage.complete !== true) return { status: "inconclusive", reason: "The source page scan was incomplete, so the changed link was not fully checked.", regressions: [] };
  const originalRedirectRemains = input.scan.findings.some((raw) => raw && typeof raw === "object" && !Array.isArray(raw)
    && (raw as Record<string, unknown>).fingerprint === input.issueFingerprint);
  if (originalRedirectRemains) return { status: "failed", reason: isRedirectRepair ? "The original link still uses the permanent redirect." : "The original broken link remains on the source page.", regressions: [input.issueFingerprint] };
  const destinationMissing = input.scan.findings.some((raw) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
    const item = raw as Record<string, unknown>;
    if (typeof item.fingerprint !== "string" || !item.fingerprint.startsWith("browser:broken-link:")) return false;
    const itemEvidence = item.evidence && typeof item.evidence === "object" && !Array.isArray(item.evidence)
      ? item.evidence as Record<string, unknown>
      : {};
    return canonical(String(itemEvidence.pageUrl ?? "")) === sourceKey
      && canonical(String(itemEvidence.link ?? "")) === canonical(replacementUrl);
  });
  if (destinationMissing) return { status: "failed", reason: "The selected destination is now reported missing from the source page.", regressions: [] };
  const destinationRedirects = input.scan.findings.some((raw) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
    const item = raw as Record<string, unknown>;
    if (typeof item.fingerprint !== "string" || !item.fingerprint.startsWith("browser:link-redirect:")) return false;
    const itemEvidence = item.evidence && typeof item.evidence === "object" && !Array.isArray(item.evidence)
      ? item.evidence as Record<string, unknown>
      : {};
    return canonical(String(itemEvidence.pageUrl ?? "")) === sourceKey
      && canonical(String(itemEvidence.link ?? "")) === canonical(replacementUrl);
  });
  if (destinationRedirects) return { status: "failed", reason: "The selected destination still redirects; the content update did not remove the redirect hop.", regressions: [] };
  return { status: "passed", reason: "The central browser rescan confirms the exact source page and link are corrected; independent checks confirm the site and selected destination are reachable without an unexpected redirect.", regressions: [] };
}

function readBrowserFindingSet(value: unknown, severities?: string[]): Set<string> {
  if (!Array.isArray(value)) return new Set();
  return new Set(value.flatMap((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) return [];
    const finding = item as Record<string, unknown>;
    return typeof finding.fingerprint === "string" && (!severities || severities.includes(String(finding.severity)))
      ? [finding.fingerprint]
      : [];
  }));
}

function readIssues(evidence: unknown): DiagnosticIssue[] | null {
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) return null;
  const issues = (evidence as Record<string, unknown>).issues;
  if (!Array.isArray(issues) || issues.some((issue) => !issue || typeof issue !== "object" || Array.isArray(issue))) {
    return null;
  }
  return issues as DiagnosticIssue[];
}

export function verifyRepairEvidence(input: {
  issueFingerprint: string | null;
  baselineEvidence: unknown;
  afterEvidence: unknown;
}): { status: "passed" | "failed" | "inconclusive"; reason: string; regressions: string[] } {
  if (!input.issueFingerprint?.startsWith("wp:")) {
    return { status: "inconclusive", reason: "No comparable WordPress issue fingerprint is attached to this repair.", regressions: [] };
  }
  const afterIssues = readIssues(input.afterEvidence);
  if (!afterIssues) {
    return { status: "inconclusive", reason: "Post-repair WordPress diagnostics are missing or invalid.", regressions: [] };
  }
  const fingerprint = input.issueFingerprint.slice(3);
  if (afterIssues.some((issue) => issue.fingerprint === fingerprint)) {
    return { status: "failed", reason: "The original diagnostic finding is still present after the repair.", regressions: [] };
  }

  const baselineIssues = readIssues(input.baselineEvidence);
  if (!baselineIssues) {
    return { status: "inconclusive", reason: "Pre-repair WordPress diagnostics are missing or invalid.", regressions: [] };
  }
  if (!baselineIssues.some((issue) => issue.fingerprint === fingerprint)) {
    return { status: "inconclusive", reason: "The original finding was not present in the pre-repair diagnostic baseline.", regressions: [] };
  }
  const baselineHigh = new Set(
    baselineIssues
      .filter((issue) => issue.severity === "high" || issue.severity === "critical")
      .flatMap((issue) => typeof issue.fingerprint === "string" ? [issue.fingerprint] : []),
  );
  const regressions = afterIssues
    .filter((issue) => (issue.severity === "high" || issue.severity === "critical")
      && typeof issue.fingerprint === "string"
      && !baselineHigh.has(issue.fingerprint))
    .map((issue) => issue.fingerprint as string);
  if (regressions.length > 0) {
    return {
      status: "failed",
      reason: "Post-repair diagnostics found new high-severity issues.",
      regressions,
    };
  }
  return { status: "passed", reason: "The original finding is absent and no new high-severity findings were detected.", regressions: [] };
}

export function verifyFatalPluginContainment(input: {
  issueFingerprint: string | null;
  pluginFile: string;
  startedAt: string;
  baselineEvidence: unknown;
  afterEvidence: unknown;
}): { status: "passed" | "failed" | "inconclusive"; reason: string; regressions: string[] } {
  if (!input.issueFingerprint?.startsWith("wp:php-fatal:") || !input.pluginFile || !Number.isFinite(Date.parse(input.startedAt))) {
    return { status: "inconclusive", reason: "The PHP fatal repair is missing exact operation or timing evidence.", regressions: [] };
  }
  const before = input.baselineEvidence && typeof input.baselineEvidence === "object" && !Array.isArray(input.baselineEvidence)
    ? input.baselineEvidence as Record<string, unknown>
    : {};
  const after = input.afterEvidence && typeof input.afterEvidence === "object" && !Array.isArray(input.afterEvidence)
    ? input.afterEvidence as Record<string, unknown>
    : {};
  const beforePlugins = Array.isArray(before.plugins) ? before.plugins : [];
  const afterPlugins = Array.isArray(after.plugins) ? after.plugins : [];
  const targetWasActive = beforePlugins.some((raw) => raw && typeof raw === "object" && !Array.isArray(raw)
    && (raw as Record<string, unknown>).file === input.pluginFile && (raw as Record<string, unknown>).active === true);
  const targetIsActive = afterPlugins.some((raw) => raw && typeof raw === "object" && !Array.isArray(raw)
    && (raw as Record<string, unknown>).file === input.pluginFile && (raw as Record<string, unknown>).active === true);
  if (!targetWasActive || targetIsActive) {
    return { status: "failed", reason: "The exact implicated plugin was not confirmed inactive.", regressions: [] };
  }
  const fatalId = input.issueFingerprint.slice("wp:php-fatal:".length);
  const repeated = (Array.isArray(after.fatalErrors) ? after.fatalErrors : []).some((raw) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
    const fatal = raw as Record<string, unknown>;
    return fatal.id === fatalId && typeof fatal.observedAt === "string" && Date.parse(fatal.observedAt) >= Date.parse(input.startedAt);
  });
  if (repeated) return { status: "failed", reason: "The same PHP fatal event was observed again after the repair began.", regressions: [] };
  const beforeIssues = readIssues(input.baselineEvidence);
  const afterIssues = readIssues(input.afterEvidence);
  if (!beforeIssues || !afterIssues) return { status: "inconclusive", reason: "Comparable post-repair WordPress findings are unavailable.", regressions: [] };
  const baselineHigh = new Set(beforeIssues.filter((issue) => issue.severity === "high" || issue.severity === "critical")
    .flatMap((issue) => typeof issue.fingerprint === "string" ? [issue.fingerprint] : []));
  const regressions = afterIssues.filter((issue) => (issue.severity === "high" || issue.severity === "critical")
    && typeof issue.fingerprint === "string" && !baselineHigh.has(issue.fingerprint))
    .map((issue) => issue.fingerprint as string);
  return regressions.length
    ? { status: "failed", reason: "Post-repair diagnostics found new high-severity issues.", regressions }
    : { status: "passed", reason: "The implicated plugin is inactive, the same fatal has not recurred, and no new high-severity findings were detected. This is temporary containment, not a code fix.", regressions: [] };
}

export function verifyRecoveryState(input: {
  beforeEvidence: unknown;
  afterEvidence: unknown;
  operations?: unknown;
}): { status: "passed" | "failed" | "inconclusive"; reason: string } {
  const before = input.beforeEvidence && typeof input.beforeEvidence === "object" && !Array.isArray(input.beforeEvidence)
    ? input.beforeEvidence as Record<string, unknown>
    : null;
  const after = input.afterEvidence && typeof input.afterEvidence === "object" && !Array.isArray(input.afterEvidence)
    ? input.afterEvidence as Record<string, unknown>
    : null;
  if (Array.isArray(input.operations) && input.operations.length > 0) {
    if (!before || !after) return { status: "inconclusive", reason: "Recovery-state diagnostics are incomplete." };
    const beforeSite = before.site && typeof before.site === "object" && !Array.isArray(before.site) ? before.site as Record<string, unknown> : {};
    const afterSite = after.site && typeof after.site === "object" && !Array.isArray(after.site) ? after.site as Record<string, unknown> : {};
    const beforeTheme = beforeSite.activeTheme && typeof beforeSite.activeTheme === "object" ? (beforeSite.activeTheme as Record<string, unknown>).stylesheet : null;
    const afterTheme = afterSite.activeTheme && typeof afterSite.activeTheme === "object" ? (afterSite.activeTheme as Record<string, unknown>).stylesheet : null;
    const beforePlugins = new Map((Array.isArray(before.plugins) ? before.plugins : []).flatMap((raw) => raw && typeof raw === "object" && !Array.isArray(raw)
      && typeof (raw as Record<string, unknown>).file === "string" ? [[String((raw as Record<string, unknown>).file), (raw as Record<string, unknown>).active === true] as const] : []));
    const afterPlugins = new Map((Array.isArray(after.plugins) ? after.plugins : []).flatMap((raw) => raw && typeof raw === "object" && !Array.isArray(raw)
      && typeof (raw as Record<string, unknown>).file === "string" ? [[String((raw as Record<string, unknown>).file), (raw as Record<string, unknown>).active === true] as const] : []));
    const beforeSettings = before.settings && typeof before.settings === "object" && !Array.isArray(before.settings) ? before.settings as Record<string, unknown> : {};
    const afterSettings = after.settings && typeof after.settings === "object" && !Array.isArray(after.settings) ? after.settings as Record<string, unknown> : {};
    const pageHashes = (value: Record<string, unknown>) => new Map((Array.isArray(value.editablePages) ? value.editablePages : []).flatMap((raw) => raw && typeof raw === "object" && !Array.isArray(raw)
      && Number.isSafeInteger((raw as Record<string, unknown>).id) && typeof (raw as Record<string, unknown>).contentSha256 === "string"
      ? [[Number((raw as Record<string, unknown>).id), String((raw as Record<string, unknown>).contentSha256)] as const] : []));
    const beforePageHashes = pageHashes(before);
    const afterPageHashes = pageHashes(after);
    for (const raw of input.operations) {
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { status: "inconclusive", reason: "The undo record does not identify each exact operation target." };
      const operation = raw as Record<string, unknown>;
      const params = operation.parameters && typeof operation.parameters === "object" && !Array.isArray(operation.parameters) ? operation.parameters as Record<string, unknown> : {};
      if (operation.operation === "disable_plugin" && typeof params.plugin === "string") {
        if (!beforePlugins.has(params.plugin) || !afterPlugins.has(params.plugin)) return { status: "inconclusive", reason: "The target plugin is missing from recovery diagnostics." };
        if (beforePlugins.get(params.plugin) !== afterPlugins.get(params.plugin)) return { status: "failed", reason: "The exact plugin activation state was not restored." };
      } else if (operation.operation === "switch_theme") {
        if (typeof beforeTheme !== "string" || typeof afterTheme !== "string") return { status: "inconclusive", reason: "Theme recovery diagnostics are unavailable." };
        if (beforeTheme !== afterTheme) return { status: "failed", reason: "The exact active theme was not restored." };
      } else if (operation.operation === "update_setting" && typeof params.option === "string") {
        if (!(params.option in beforeSettings) || !(params.option in afterSettings)) return { status: "inconclusive", reason: "The target setting is missing from recovery diagnostics." };
        if (beforeSettings[params.option] !== afterSettings[params.option]) return { status: "failed", reason: "The exact setting value was not restored." };
      } else if (operation.operation === "replace_post_link" && typeof params.postId === "string") {
        const postId = Number(params.postId);
        if (!beforePageHashes.has(postId) || !afterPageHashes.has(postId)) return { status: "inconclusive", reason: "The target post content hash is missing from recovery diagnostics." };
        if (beforePageHashes.get(postId) !== afterPageHashes.get(postId)) return { status: "failed", reason: "The exact post content was not restored." };
      } else if (operation.operation === "add_scoped_css_rule") {
        const beforeCssHash = beforeSite.customCssSha256;
        const afterCssHash = afterSite.customCssSha256;
        if (typeof beforeTheme !== "string" || typeof afterTheme !== "string"
          || typeof beforeCssHash !== "string" || typeof afterCssHash !== "string") {
          return { status: "inconclusive", reason: "Theme and custom CSS recovery diagnostics are unavailable." };
        }
        if (beforeTheme !== afterTheme) return { status: "failed", reason: "The active theme changed during CSS rollback." };
        if (beforeCssHash !== afterCssHash) return { status: "failed", reason: "The exact custom CSS state was not restored." };
      } else return { status: "inconclusive", reason: "The undo record contains an unsupported operation." };
    }
    return { status: "passed", reason: "Every operation-specific target matches its pre-change state." };
  }
  const beforeSite = before?.site && typeof before.site === "object" && !Array.isArray(before.site)
    ? before.site as Record<string, unknown>
    : null;
  const afterSite = after?.site && typeof after.site === "object" && !Array.isArray(after.site)
    ? after.site as Record<string, unknown>
    : null;
  const beforeTheme = beforeSite?.activeTheme && typeof beforeSite.activeTheme === "object"
    ? (beforeSite.activeTheme as Record<string, unknown>).stylesheet
    : null;
  const afterTheme = afterSite?.activeTheme && typeof afterSite.activeTheme === "object"
    ? (afterSite.activeTheme as Record<string, unknown>).stylesheet
    : null;
  const beforePlugins = Array.isArray(before?.plugins) ? before.plugins : null;
  const afterPlugins = Array.isArray(after?.plugins) ? after.plugins : null;
  const beforeSettings = before?.settings && typeof before.settings === "object" && !Array.isArray(before.settings)
    ? before.settings as Record<string, unknown>
    : null;
  const afterSettings = after?.settings && typeof after.settings === "object" && !Array.isArray(after.settings)
    ? after.settings as Record<string, unknown>
    : null;
  if (!before || !after || typeof beforeTheme !== "string" || typeof afterTheme !== "string" || !beforePlugins || !afterPlugins
    || typeof beforeSettings?.blogname !== "string" || typeof afterSettings?.blogname !== "string"
    || typeof beforeSettings.blogdescription !== "string" || typeof afterSettings.blogdescription !== "string") {
    return { status: "inconclusive", reason: "Recovery-state diagnostics are incomplete." };
  }
  const activeFiles = (plugins: unknown[]) => plugins.flatMap((plugin) => {
    if (!plugin || typeof plugin !== "object" || Array.isArray(plugin)) return [];
    const item = plugin as Record<string, unknown>;
    return item.active === true && typeof item.file === "string" ? [item.file] : [];
  }).sort();
  if (beforeTheme !== afterTheme
    || JSON.stringify(activeFiles(beforePlugins)) !== JSON.stringify(activeFiles(afterPlugins))
    || beforeSettings.blogname !== afterSettings.blogname
    || beforeSettings.blogdescription !== afterSettings.blogdescription) {
    return { status: "failed", reason: "Restored theme, active-plugin, or supported setting state does not match the pre-repair snapshot." };
  }
  const beforePages = Array.isArray(before.editablePages) ? before.editablePages : null;
  const afterPages = Array.isArray(after.editablePages) ? after.editablePages : null;
  if (beforePages?.some((page) => page && typeof page === "object" && !Array.isArray(page)
    && typeof (page as Record<string, unknown>).contentSha256 === "string")) {
    if (!afterPages) return { status: "inconclusive", reason: "Restored public post content hashes are unavailable." };
    const contentHashes = (pages: unknown[]) => new Map(pages.flatMap((page) => {
      if (!page || typeof page !== "object" || Array.isArray(page)) return [];
      const item = page as Record<string, unknown>;
      return Number.isSafeInteger(item.id) && typeof item.contentSha256 === "string" ? [[Number(item.id), item.contentSha256] as const] : [];
    }));
    const beforeContent = contentHashes(beforePages);
    const afterContent = contentHashes(afterPages);
    if (beforeContent.size !== afterContent.size || [...beforeContent].some(([id, hash]) => afterContent.get(id) !== hash)) {
      return { status: "failed", reason: "Restored published post content does not match the pre-repair diagnostic snapshot." };
    }
  }
  return { status: "passed", reason: "Restored theme, active-plugin, and supported setting state match the pre-repair snapshot." };
}
