import type { Prisma } from "@prisma/client";
import { compareVersions } from "./cleanup-plan.ts";
import { db } from "./db.ts";

/**
 * Known-vulnerability matching for installed plugins and WordPress core,
 * from the Wordfence Intelligence vulnerability feed (free API key:
 * WORDFENCE_INTELLIGENCE_API_KEY). A daily job downloads the scanner feed,
 * keeps only the entries for software installed on registered sites, and
 * stores that compact index. Each plugin sync is matched against the index,
 * so a site's findings change as soon as a plugin is updated.
 */

const FEED_URL = "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/scanner";
const INDEX_KEY = "vulnerability_index";
type Json = Record<string, unknown>;
const record = (value: unknown): Json => value && typeof value === "object" && !Array.isArray(value) ? value as Json : {};

export type VersionRange = { from: string; fromInclusive: boolean; to: string; toInclusive: boolean };
export type IndexedVulnerability = { id: string; title: string; type: "plugin" | "theme" | "core"; slug: string; ranges: VersionRange[]; patchedVersions: string[]; cvss: number | null; rating: string | null; cve: string | null; reference: string | null };
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

function severityFor(vulnerability: IndexedVulnerability): "critical" | "high" | "medium" | "low" {
  const rating = (vulnerability.rating ?? "").toLowerCase();
  if (rating === "critical" || (vulnerability.cvss ?? 0) >= 9) return "critical";
  if (rating === "high" || (vulnerability.cvss ?? 0) >= 7) return "high";
  if (rating === "medium" || (vulnerability.cvss ?? 0) >= 4) return "medium";
  return "low";
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
    for (const vulnerability of index.bySlug[item.key] ?? []) {
      if (!vulnerability.ranges.some((range) => versionInRange(item.version, range))) continue;
      const fixedIn = vulnerability.patchedVersions.filter((version) => compareVersions(version, item.version) > 0).sort(compareVersions)[0] ?? null;
      const updateFixes = Boolean(fixedIn && item.newVersion && compareVersions(item.newVersion, fixedIn) >= 0);
      findings.push({
        fingerprint: `vuln:${item.key.replace(":", "-")}:${vulnerability.id}`.slice(0, 160),
        title: `Known vulnerability in ${item.name} ${item.version}: ${vulnerability.title}`.slice(0, 200),
        description: `${vulnerability.title}${vulnerability.cve ? ` (${vulnerability.cve})` : ""}${vulnerability.cvss ? `, CVSS ${vulnerability.cvss}` : ""}. ${fixedIn
          ? `Fixed in version ${fixedIn}.${updateFixes ? ` The available update (${item.newVersion}) includes the fix.` : item.source === "wordpress.org" ? " Sync diagnostics so WordPress offers that update." : " Update it from the vendor."}`
          : "No fixed version is published yet: deactivate and remove it until the vendor releases a fix."}`.slice(0, 2000),
        severity: severityFor(vulnerability),
        evidence: { vulnerability: { ...vulnerability }, installed: { name: item.name, version: item.version, file: item.file, availableUpdate: item.newVersion, source: item.source }, fixedIn, updateFixes },
      });
    }
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
  const apiKey = process.env.WORDFENCE_INTELLIGENCE_API_KEY;
  if (!apiKey) return { refreshed: false as const, reason: "WORDFENCE_INTELLIGENCE_API_KEY is not configured." };
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
  if (!response.ok) return { refreshed: false as const, reason: `The Wordfence Intelligence feed returned HTTP ${response.status}${response.status === 401 ? " (check the API key)" : ""}.` };
  const parsed = parseFeed(await response.json(), wanted);
  if (parsed.total === 0) return { refreshed: false as const, reason: "The vulnerability feed format was not recognized; nothing was changed." };
  const index: VulnerabilityIndex = { fetchedAt: new Date().toISOString(), source: "wordfence", entries: parsed.total, bySlug: parsed.bySlug };
  const existing = await db.systemSetting.findFirst({ where: { organizationId: null, scope: "global", scopeId: "system", key: INDEX_KEY }, select: { id: true } });
  if (existing) await db.systemSetting.update({ where: { id: existing.id }, data: { value: index as unknown as Prisma.InputJsonValue } });
  else await db.systemSetting.create({ data: { organizationId: null, scope: "global", scopeId: "system", key: INDEX_KEY, value: index as unknown as Prisma.InputJsonValue } });
  return { refreshed: true as const, feedEntries: parsed.total, matchedSoftware: Object.keys(parsed.bySlug).length };
}

/** Upsert a site's vulnerability findings and resolve the ones no longer matching. */
export async function storeVulnerabilityFindings(websiteId: string, diagnostics: unknown, index?: VulnerabilityIndex | null) {
  const current = index === undefined ? await loadVulnerabilityIndex() : index;
  if (!current) return { checked: false };
  const findings = matchVulnerabilities(current, diagnostics);
  const now = new Date();
  for (const finding of findings) {
    await db.issue.upsert({
      where: { websiteId_fingerprint: { websiteId, fingerprint: finding.fingerprint } },
      create: { websiteId, fingerprint: finding.fingerprint, title: finding.title, description: finding.description, severity: finding.severity, source: "vulnerability_feed", evidence: { ...finding.evidence, feedFetchedAt: current.fetchedAt } as Prisma.InputJsonValue },
      update: { title: finding.title, description: finding.description, severity: finding.severity, status: "open", resolvedAt: null, lastSeenAt: now, evidence: { ...finding.evidence, feedFetchedAt: current.fetchedAt } as Prisma.InputJsonValue },
    });
  }
  const active = findings.map((finding) => finding.fingerprint);
  await db.issue.updateMany({
    where: { websiteId, source: "vulnerability_feed", status: { in: ["open", "acknowledged"] }, ...(active.length ? { fingerprint: { notIn: active } } : {}) },
    data: { status: "resolved", resolvedAt: now, lastSeenAt: now },
  });
  return { checked: true, findings: findings.length };
}

/** Plugin file for a "vuln:plugin-<slug>:<id>" fingerprint. */
export function pluginSlugForVulnerability(fingerprint: string) {
  const match = /^vuln:plugin-([a-z0-9-]+):/.exec(fingerprint);
  return match ? match[1] : null;
}
