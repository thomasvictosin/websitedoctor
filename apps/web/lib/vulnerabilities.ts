import type { Prisma } from "@prisma/client";
import { compareVersions } from "./cleanup-plan.ts";
import { db } from "./db.ts";
import { anyWordfenceKey } from "./integrations.ts";

/**
 * Known-vulnerability matching for installed plugins and WordPress core,
 * from the Wordfence Intelligence vulnerability feed (v3; free API key pasted
 * in Settings or WORDFENCE_INTELLIGENCE_API_KEY). A daily job downloads the scanner feed,
 * keeps only the entries for software installed on registered sites, and
 * stores that compact index. Each plugin sync is matched against the index,
 * so a site's findings change as soon as a plugin is updated.
 */

const FEED_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner";
const CLOSED_KEY = "wporg_closed_plugins";
const INDEX_KEY = "vulnerability_index";
type Json = Record<string, unknown>;
const record = (value: unknown): Json => value && typeof value === "object" && !Array.isArray(value) ? value as Json : {};

export type VersionRange = { from: string; fromInclusive: boolean; to: string; toInclusive: boolean };
export type IndexedVulnerability = { id: string; title: string; type: "plugin" | "theme" | "core"; slug: string; ranges: VersionRange[]; patchedVersions: string[]; cvss: number | null; rating: string | null; cve: string | null; reference: string | null; informational?: boolean };
export type VulnerabilityIndex = { fetchedAt: string; source: "wordfence"; entries: number; bySlug: Record<string, IndexedVulnerability[]> };

/** Reduce the feed to vulnerabilities for the given software keys ("plugin:<slug>", "core:wordpress"). */
export function parseFeed(feed: unknown, wanted: Set<string>): { bySlug: Record<string, IndexedVulnerability[]>; total: number } {
  const bySlug: Record<string, IndexedVulnerability[]> = {};
  let total = 0;
  for (const [id, raw] of Object.entries(record(feed))) {
    const entry = record(raw);
    if (!Array.isArray(entry.software)) continue;
    total += 1;
    for (const software of entry.software.map(record)) {
      const type = software.type === "core" ? "core" : software.type === "theme" ? "theme" : software.type === "plugin" ? "plugin" : null;
      const slug = type === "core" ? "wordpress" : typeof software.slug === "string" ? software.slug : "";
      if (!type || !slug || !wanted.has(`${type}:${slug}`)) continue;
      const ranges = Object.values(record(software.affected_versions)).map(record).map((range) => ({
        from: String(range.from_version ?? "*"), fromInclusive: range.from_inclusive !== false,
        to: String(range.to_version ?? "*"), toInclusive: range.to_inclusive !== false,
      }));
      if (!ranges.length) continue;
      const cvss = record(entry.cvss);
      const cve = Array.isArray(entry.cve) ? entry.cve.find((item) => typeof item === "string") : typeof entry.cve === "string" ? entry.cve : null;
      const references = Array.isArray(entry.references) ? entry.references.filter((item): item is string => typeof item === "string") : [];
      (bySlug[`${type}:${slug}`] ??= []).push({
        id: String(entry.id ?? id).slice(0, 80), title: String(entry.title ?? "Known vulnerability").slice(0, 300), type, slug,
        ranges, patchedVersions: Array.isArray(software.patched_versions) ? software.patched_versions.filter((item): item is string => typeof item === "string").slice(0, 10) : [],
        cvss: typeof cvss.score === "number" ? cvss.score : typeof cvss.score === "string" ? Number(cvss.score) || null : null,
        rating: typeof cvss.rating === "string" ? cvss.rating : null,
        cve: (cve as string | null) ?? null,
        reference: references[0] ?? null,
        informational: entry.informational === true,
      });
    }
  }
  return { bySlug, total };
}

export function versionInRange(version: string, range: VersionRange) {
  const lower = range.from === "*" || (range.fromInclusive ? compareVersions(version, range.from) >= 0 : compareVersions(version, range.from) > 0);
  const upper = range.to === "*" || (range.toInclusive ? compareVersions(version, range.to) <= 0 : compareVersions(version, range.to) < 0);
  return lower && upper;
}

type Severity = "critical" | "high" | "medium" | "low";
const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/**
 * The scanner feed carries no CVSS score, so the severity is estimated from
 * the standardized Wordfence title: who can exploit it and what it allows.
 * A real CVSS score or rating, when present, always wins.
 */
export function severityFor(vulnerability: Pick<IndexedVulnerability, "title" | "cvss" | "rating" | "informational">): { severity: Severity; estimated: boolean } {
  const rating = (vulnerability.rating ?? "").toLowerCase();
  const score = vulnerability.cvss ?? 0;
  if (rating === "critical" || score >= 9) return { severity: "critical", estimated: false };
  if (rating === "high" || score >= 7) return { severity: "high", estimated: false };
  if (rating === "medium" || score >= 4) return { severity: "medium", estimated: false };
  if (rating === "low" || rating === "none" || score > 0) return { severity: "low", estimated: false };
  if (vulnerability.informational) return { severity: "low", estimated: true };
  const title = vulnerability.title.toLowerCase();
  // Who can exploit it: anyone on the internet, a visitor tricking a logged-in admin (CSRF), any logged-in user, or only privileged users.
  const csrf = /cross-site request forgery|csrf/.test(title);
  const level = /administrator\+|admin\+|super admin|editor\+|shop manager\+/.test(title) ? "privileged" : /unauthenticated/.test(title) ? "anyone" : csrf ? "tricked" : "user";
  const takeover = /remote code execution|code execution|code injection|arbitrary file upload|privilege escalation|authentication bypass|account takeover|arbitrary options? update|arbitrary user (creation|password)|command injection/.test(title);
  const serious = /sql injection|object injection|arbitrary file (deletion|read|download)|local file inclusion|remote file inclusion|path traversal|directory traversal|server-side request forgery|ssrf/.test(title);
  const moderate = csrf || /cross-site scripting|xss|open redirect|missing authori[sz]ation|insecure direct object|information (exposure|disclosure)|sensitive information|full path disclosure|content injection|html injection|denial of service/.test(title);
  if (level === "privileged") return { severity: takeover || serious ? "medium" : "low", estimated: true };
  if (takeover) return { severity: level === "anyone" ? "critical" : "high", estimated: true };
  if (serious) return { severity: level === "user" ? "medium" : "high", estimated: true };
  if (moderate) return { severity: "medium", estimated: true };
  return { severity: "low", estimated: true };
}

export type VulnerabilityFinding = { fingerprint: string; title: string; description: string; severity: "critical" | "high" | "medium" | "low"; evidence: Json };

/** Findings for one site's installed plugins and core version. */
export function matchVulnerabilities(index: Pick<VulnerabilityIndex, "bySlug">, diagnostics: unknown): VulnerabilityFinding[] {
  const data = record(diagnostics);
  const plugins = Array.isArray(data.plugins) ? data.plugins.map(record) : [];
  const findings: VulnerabilityFinding[] = [];
  const installed: Array<{ key: string; name: string; version: string; file: string | null; newVersion: string | null; source: string | null }> = plugins
    .filter((plugin) => typeof plugin.file === "string" && plugin.file.includes("/"))
    .map((plugin) => ({ key: `plugin:${String(plugin.file).split("/")[0]}`, name: String(plugin.name ?? plugin.file), version: String(plugin.version ?? ""), file: String(plugin.file), newVersion: typeof plugin.newVersion === "string" ? plugin.newVersion : null, source: typeof plugin.source === "string" ? plugin.source : null }));
  for (const theme of Array.isArray(data.themes) ? data.themes.map(record) : []) {
    if (typeof theme.stylesheet !== "string") continue;
    installed.push({ key: `theme:${theme.stylesheet}`, name: `${String(theme.name ?? theme.stylesheet)} theme`, version: String(theme.version ?? ""), file: null, newVersion: typeof theme.newVersion === "string" ? theme.newVersion : null, source: typeof theme.source === "string" ? theme.source : null });
  }
  const wpVersion = typeof record(data.site).wpVersion === "string" ? String(record(data.site).wpVersion) : "";
  if (wpVersion) installed.push({ key: "core:wordpress", name: "WordPress", version: wpVersion, file: null, newVersion: null, source: "wordpress.org" });
  for (const item of installed) {
    if (!item.version) continue;
    // One issue per installed plugin/theme/core version, listing every known vulnerability it has.
    const matched = (index.bySlug[item.key] ?? [])
      .filter((vulnerability) => vulnerability.ranges.some((range) => versionInRange(item.version, range)))
      .filter((vulnerability, position, all) => all.findIndex((other) => other.id === vulnerability.id) === position)
      .map((vulnerability) => {
        const fixedIn = vulnerability.patchedVersions.filter((version) => compareVersions(version, item.version) > 0).sort(compareVersions)[0] ?? null;
        return { ...vulnerability, fixedIn, ...severityFor(vulnerability) };
      })
      .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.title.localeCompare(b.title));
    if (!matched.length) continue;
    const worst = matched[0];
    const unfixed = matched.filter((vulnerability) => !vulnerability.fixedIn);
    // The version that fixes all of them (null when at least one has no fix yet).
    const fixedIn = unfixed.length ? null : matched.map((vulnerability) => vulnerability.fixedIn as string).sort(compareVersions).at(-1) ?? null;
    const partialFix = unfixed.length && unfixed.length < matched.length ? matched.filter((vulnerability) => vulnerability.fixedIn).map((vulnerability) => vulnerability.fixedIn as string).sort(compareVersions).at(-1) ?? null : null;
    const updateFixes = Boolean(fixedIn && item.newVersion && compareVersions(item.newVersion, fixedIn) >= 0);
    const count = matched.length;
    const lines = matched.slice(0, 15).map((vulnerability) => `• ${vulnerability.title}${vulnerability.cve ? ` (${vulnerability.cve})` : ""} — ${vulnerability.severity}${vulnerability.estimated ? " (estimated)" : vulnerability.cvss ? `, CVSS ${vulnerability.cvss}` : ""}; ${vulnerability.fixedIn ? `fixed in ${vulnerability.fixedIn}` : "no fix released yet"}.`);
    const advice = fixedIn
      ? `Version ${fixedIn} or later fixes ${count === 1 ? "it" : `all ${count}`}.${updateFixes ? ` The available update (${item.newVersion}) includes the fix.` : item.source === "wordpress.org" ? " Sync diagnostics so WordPress offers that update." : " Get it from the vendor and upload it here."}`
      : partialFix
        ? `Version ${partialFix} fixes ${count - unfixed.length} of them; ${unfixed.length} ha${unfixed.length === 1 ? "s" : "ve"} no fix yet, so consider removing it until the vendor releases one.`
        : `No fixed version is published yet: deactivate and remove it until the vendor releases a fix.`;
    findings.push({
      fingerprint: `vuln:${item.key.replace(":", "-")}:known`.slice(0, 160),
      title: (count === 1 ? `Known vulnerability in ${item.name} ${item.version}: ${worst.title}` : `${item.name} ${item.version} has ${count} known vulnerabilities`).slice(0, 200),
      description: `${advice}\n${lines.join("\n")}${count > lines.length ? `\n…and ${count - lines.length} more.` : ""}`.slice(0, 2000),
      severity: worst.severity,
      evidence: {
        vulnerability: { ...worst },
        vulnerabilities: matched.map((vulnerability) => ({ ...vulnerability })),
        count,
        severityEstimated: worst.estimated,
        installed: { name: item.name, version: item.version, file: item.file, availableUpdate: item.newVersion, source: item.source },
        fixedIn, partialFix, unfixedCount: unfixed.length, updateFixes,
      },
    });
  }
  return findings;
}

export async function loadVulnerabilityIndex(): Promise<VulnerabilityIndex | null> {
  const setting = await db.systemSetting.findFirst({ where: { organizationId: null, scope: "global", scopeId: "system", key: INDEX_KEY }, select: { value: true } });
  const value = setting?.value as VulnerabilityIndex | undefined;
  return value?.bySlug ? value : null;
}

/** Download the feed and rebuild the compact index for software installed on registered sites. */
export async function refreshVulnerabilityIndex(fetcher: typeof fetch = fetch) {
  const apiKey = await anyWordfenceKey();
  if (!apiKey) return { refreshed: false as const, reason: "No Wordfence Intelligence key is set (Settings → Integrations)." };
  const agents = await db.wordPressAgent.findMany({ where: { revokedAt: null }, select: { diagnostics: true } });
  const wanted = new Set<string>(["core:wordpress"]);
  for (const agent of agents) {
    for (const plugin of Array.isArray(record(agent.diagnostics).plugins) ? (record(agent.diagnostics).plugins as unknown[]).map(record) : []) {
      if (typeof plugin.file === "string" && plugin.file.includes("/")) wanted.add(`plugin:${plugin.file.split("/")[0]}`);
    }
    for (const theme of Array.isArray(record(agent.diagnostics).themes) ? (record(agent.diagnostics).themes as unknown[]).map(record) : []) {
      if (typeof theme.stylesheet === "string") wanted.add(`theme:${theme.stylesheet}`);
    }
  }
  const response = await fetcher(FEED_URL, { headers: { authorization: `Bearer ${apiKey}`, accept: "application/json" }, signal: AbortSignal.timeout(45_000) });
  if (!response.ok) {
    const reason = `The Wordfence Intelligence feed returned HTTP ${response.status}${response.status === 401 || response.status === 403 ? " (check the API key)" : response.status === 429 ? " (rate limited; it is retried tomorrow)" : ""}.`;
    await saveRefreshError(reason);
    return { refreshed: false as const, reason };
  }
  const parsed = parseFeed(await response.json(), wanted);
  if (parsed.total === 0) return { refreshed: false as const, reason: "The vulnerability feed format was not recognized; nothing was changed." };
  const index: VulnerabilityIndex = { fetchedAt: new Date().toISOString(), source: "wordfence", entries: parsed.total, bySlug: parsed.bySlug };
  await putGlobalSetting(INDEX_KEY, index);
  return { refreshed: true as const, feedEntries: parsed.total, matchedSoftware: Object.keys(parsed.bySlug).length };
}

type ClosedPlugin = { slug: string; name: string; closedDate: string | null; reason: string; reasonText: string; checkedAt: string };
type ClosedIndex = { checked: Record<string, { closed: ClosedPlugin | null; checkedAt: string }> };

async function globalSetting<T>(key: string): Promise<{ id: string | null; value: T | null }> {
  const row = await db.systemSetting.findFirst({ where: { organizationId: null, scope: "global", scopeId: "system", key }, select: { id: true, value: true } });
  return { id: row?.id ?? null, value: (row?.value as T | undefined) ?? null };
}

async function putGlobalSetting(key: string, value: unknown) {
  const { id } = await globalSetting(key);
  if (id) await db.systemSetting.update({ where: { id }, data: { value: value as Prisma.InputJsonValue } });
  else await db.systemSetting.create({ data: { organizationId: null, scope: "global", scopeId: "system", key, value: value as Prisma.InputJsonValue } });
}

async function saveRefreshError(reason: string) {
  await putGlobalSetting("vulnerability_refresh_error", { reason, at: new Date().toISOString() });
}

/**
 * WordPress.org closes plugins for security issues and guideline violations;
 * a closed plugin gets no more updates. This needs no API key. Each slug is
 * looked up at most once a week (premium plugins answer "not found").
 */
export async function refreshClosedPlugins(slugs: string[], fetcher: typeof fetch = fetch, budgetMs = 20_000) {
  const { value } = await globalSetting<ClosedIndex>(CLOSED_KEY);
  const index: ClosedIndex = { checked: { ...(value?.checked ?? {}) } };
  const weekAgo = Date.now() - 7 * 24 * 60 * 60_000;
  const due = [...new Set(slugs)].filter((slug) => /^[a-z0-9][a-z0-9-]{0,99}$/.test(slug) && slug !== "ai-website-doctor" && !(Date.parse(index.checked[slug]?.checkedAt ?? "") > weekAgo));
  const deadline = Date.now() + budgetMs;
  let looked = 0;
  for (let offset = 0; offset < due.length && Date.now() < deadline; offset += 8) {
    await Promise.all(due.slice(offset, offset + 8).map(async (slug) => {
      try {
        const response = await fetcher(`https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bslug%5D=${encodeURIComponent(slug)}&request%5Bfields%5D%5Bsections%5D=0`, { signal: AbortSignal.timeout(8_000) });
        const body = record(await response.json());
        const checkedAt = new Date().toISOString();
        index.checked[slug] = body.closed === true
          ? { checkedAt, closed: { slug, name: String(body.name ?? slug).replace(/^Author:\s*/, "").slice(0, 200), closedDate: typeof body.closed_date === "string" ? body.closed_date : null, reason: String(body.reason ?? "unknown"), reasonText: String(body.reason_text ?? body.reason ?? "Unknown").slice(0, 100), checkedAt } }
          : { checkedAt, closed: null };
        looked += 1;
      } catch {
        // Unreachable this time; checked again on the next run.
      }
    }));
  }
  await putGlobalSetting(CLOSED_KEY, index);
  return { looked, closed: Object.values(index.checked).filter((entry) => entry.closed).length };
}

export function matchClosedPlugins(index: ClosedIndex | null, diagnostics: unknown): VulnerabilityFinding[] {
  if (!index) return [];
  const plugins = Array.isArray(record(diagnostics).plugins) ? (record(diagnostics).plugins as unknown[]).map(record) : [];
  const findings: VulnerabilityFinding[] = [];
  for (const plugin of plugins) {
    if (typeof plugin.file !== "string" || !plugin.file.includes("/")) continue;
    const slug = plugin.file.split("/")[0];
    const closed = index.checked[slug]?.closed;
    if (!closed) continue;
    const security = /security/i.test(closed.reason);
    findings.push({
      fingerprint: `vuln:plugin-${slug}:wporg-closed`,
      title: `${String(plugin.name ?? slug)} was closed on WordPress.org${security ? " for a security issue" : ""}`.slice(0, 200),
      description: `WordPress.org closed this plugin${closed.closedDate ? ` on ${closed.closedDate}` : ""} (reason: ${closed.reasonText}). It no longer receives updates${security ? ", and the reason given is an unfixed security issue" : ""}. Replace it with a maintained alternative, or remove it if it is not needed.`,
      severity: security ? "high" : "medium",
      evidence: { vulnerability: { id: "wporg-closed", title: `Closed on WordPress.org: ${closed.reasonText}`, type: "plugin", slug, ranges: [], patchedVersions: [], cvss: null, rating: null, cve: null, reference: `https://wordpress.org/plugins/${slug}/` }, installed: { name: String(plugin.name ?? slug), version: String(plugin.version ?? ""), file: plugin.file, availableUpdate: null, source: typeof plugin.source === "string" ? plugin.source : null }, fixedIn: null, updateFixes: false, closed },
    });
  }
  return findings;
}

/** What the Settings and Issues pages show about the vulnerability database. */
export async function vulnerabilityStatus() {
  const [index, error, closed, key] = await Promise.all([loadVulnerabilityIndex(), globalSetting<{ reason: string; at: string }>("vulnerability_refresh_error"), globalSetting<ClosedIndex>(CLOSED_KEY), anyWordfenceKey()]);
  const lastError = error.value && (!index || Date.parse(error.value.at) > Date.parse(index.fetchedAt)) ? error.value : null;
  return {
    keyConfigured: Boolean(key),
    feedFetchedAt: index?.fetchedAt ?? null,
    feedEntries: index?.entries ?? 0,
    matchedSoftware: index ? Object.keys(index.bySlug).length : 0,
    lastError,
    closedPluginsCheckedAt: closed.value ? Object.values(closed.value.checked).map((entry) => entry.checkedAt).sort().at(-1) ?? null : null,
  };
}

/** Upsert a site's vulnerability findings and resolve the ones no longer matching. */
export async function storeVulnerabilityFindings(websiteId: string, diagnostics: unknown, index?: VulnerabilityIndex | null) {
  const current = index === undefined ? await loadVulnerabilityIndex() : index;
  const closed = (await globalSetting<ClosedIndex>(CLOSED_KEY)).value;
  if (!current && !closed) return { checked: false };
  const findings = [...(current ? matchVulnerabilities(current, diagnostics) : []), ...matchClosedPlugins(closed, diagnostics)];
  const now = new Date();
  for (const finding of findings) {
    const evidence = { ...finding.evidence, feedFetchedAt: current?.fetchedAt ?? null } as Prisma.InputJsonValue;
    await db.issue.upsert({
      where: { websiteId_fingerprint: { websiteId, fingerprint: finding.fingerprint } },
      create: { websiteId, fingerprint: finding.fingerprint, title: finding.title, description: finding.description, severity: finding.severity, source: "vulnerability_feed", evidence },
      update: { title: finding.title, description: finding.description, severity: finding.severity, status: "open", resolvedAt: null, lastSeenAt: now, evidence },
    });
  }
  const active = findings.map((finding) => finding.fingerprint);
  // Before grouping, each vulnerability record was its own issue; the grouped issue replaces them.
  if (current) {
    await db.issue.deleteMany({ where: { websiteId, source: "vulnerability_feed", NOT: [{ fingerprint: { endsWith: ":known" } }, { fingerprint: { endsWith: ":wporg-closed" } }] } });
  }
  // Without the Wordfence index, only closed-plugin findings can be judged; keep feed findings as they are.
  await db.issue.updateMany({
    where: { websiteId, source: "vulnerability_feed", status: { in: ["open", "acknowledged"] }, fingerprint: { ...(current ? {} : { endsWith: ":wporg-closed" }), ...(active.length ? { notIn: active } : {}) } },
    data: { status: "resolved", resolvedAt: now, lastSeenAt: now },
  });
  return { checked: true, findings: findings.length };
}

/** Every installed plugin slug across connected sites. */
export async function installedPluginSlugs() {
  const agents = await db.wordPressAgent.findMany({ where: { revokedAt: null }, select: { diagnostics: true } });
  const slugs = new Set<string>();
  for (const agent of agents) {
    for (const plugin of Array.isArray(record(agent.diagnostics).plugins) ? (record(agent.diagnostics).plugins as unknown[]).map(record) : []) {
      if (typeof plugin.file === "string" && plugin.file.includes("/")) slugs.add(plugin.file.split("/")[0]);
    }
  }
  return [...slugs];
}

/** Plugin file for a "vuln:plugin-<slug>:<id>" fingerprint. */
export function pluginSlugForVulnerability(fingerprint: string) {
  const match = /^vuln:plugin-([a-z0-9-]+):/.exec(fingerprint);
  return match ? match[1] : null;
}

/** Refresh the vulnerability index and WordPress.org closed-plugin list, then re-match every connected site. */
export async function refreshAllVulnerabilities() {
  const refresh = await refreshVulnerabilityIndex();
  const closed = await refreshClosedPlugins(await installedPluginSlugs());
  const index = await loadVulnerabilityIndex();
  let sites = 0;
  let findings = 0;
  for (const agent of await db.wordPressAgent.findMany({ where: { revokedAt: null }, select: { websiteId: true, diagnostics: true } })) {
    const result = await storeVulnerabilityFindings(agent.websiteId, agent.diagnostics, index);
    sites += 1;
    findings += "findings" in result ? result.findings ?? 0 : 0;
  }
  return { refresh, closed, indexFetchedAt: index?.fetchedAt ?? null, sites, findings };
}

