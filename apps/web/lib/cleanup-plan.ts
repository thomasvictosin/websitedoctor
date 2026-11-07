import { createHash } from "node:crypto";
import { z } from "zod";

/**
 * Compromise cleanup playbook: turns the plugin's integrity report and the
 * central security probe into an ordered list of allowlisted operations that
 * the WordPress plugin (0.3.0+) executes after one approval.
 *
 * Every file step is bound to the SHA-256 the plugin reported, and every core
 * restore to the MD5 that WordPress.org publishes for the installed version,
 * so an approval covers exactly the content that was reviewed. The plugin
 * repeats all of these checks before changing anything.
 */

export const CLEANUP_OPERATIONS = [
  "quarantine_file",
  "restore_core_file",
  "remove_htaccess_rules",
  "quarantine_plugin",
  "demote_user",
  "rotate_salts",
  "purge_page_cache",
  "purge_quarantine",
  "update_plugin",
  "reinstall_plugin",
  "install_plugin",
  "set_hardening",
  "restore_run",
] as const;
export type CleanupOperation = typeof CLEANUP_OPERATIONS[number];
export const MIN_CLEANUP_PLUGIN_VERSION = "0.3.0";
export const MAX_CLEANUP_STEPS = 120;
const INTEGRITY_MAX_AGE_MS = 30 * 60_000;
/** File-management plugins are a frequent entry point; removal is offered, never preselected. */
const RISKY_PLUGIN_SLUGS = ["wp-file-manager", "file-manager-advanced", "filester", "file-manager", "wp-file-manager-pro"];

const sha256 = /^[a-f0-9]{64}$/;
const relativePath = (value: string) => value.length > 0 && value.length <= 300 && !value.startsWith("/") && !value.includes("\\")
  && !/(^|\/)\.\.?(\/|$)/.test(value) && /^[A-Za-z0-9._@+\- /]+$/.test(value);

const pluginVersion = /^[0-9A-Za-z.+-]{1,40}$/;
const wordpressOrgPluginFile = (file: string) => /^[a-z0-9][a-z0-9-]{0,99}\/[A-Za-z0-9._-]+\.php$/.test(file) && !file.startsWith("ai-website-doctor/");

export function isAllowedCleanupStep(step: { operation?: unknown; parameters?: unknown }): boolean {
  if (!step || typeof step.operation !== "string" || !step.parameters || typeof step.parameters !== "object" || Array.isArray(step.parameters)) return false;
  const params = step.parameters as Record<string, unknown>;
  if (Object.values(params).some((value) => typeof value !== "string" || value.length > 500)) return false;
  const keys = Object.keys(params).sort().join(",");
  const p = params as Record<string, string>;
  switch (step.operation) {
    case "quarantine_file": return keys === "expectedSha256,path" && relativePath(p.path) && sha256.test(p.expectedSha256);
    case "restore_core_file": return keys === "expectedCurrentSha256,officialMd5,path" && relativePath(p.path) && !p.path.startsWith("wp-content/")
      && /^[a-f0-9]{32}$/.test(p.officialMd5) && (p.expectedCurrentSha256 === "missing" || sha256.test(p.expectedCurrentSha256));
    case "remove_htaccess_rules": return keys === "expectedSha256,lines" && sha256.test(p.expectedSha256) && /^[1-9]\d{0,5}(,[1-9]\d{0,5}){0,9}$/.test(p.lines);
    case "quarantine_plugin": return keys === "expectedVersion,plugin" && /^(?!\/)(?!.*(?:^|\/)\.\.?\/)[a-z0-9._/-]+\.php$/i.test(p.plugin) && !p.plugin.startsWith("ai-website-doctor/") && p.expectedVersion.length <= 40;
    case "demote_user": return keys === "expectedRole,login" && p.expectedRole === "administrator" && /^[A-Za-z0-9._@ -]{1,60}$/.test(p.login);
    case "rotate_salts":
    case "purge_page_cache": return keys === "";
    case "purge_quarantine": return keys === "runId" && /^[a-z0-9-]{8,64}$/.test(p.runId);
    case "update_plugin": return keys === "expectedVersion,plugin,targetVersion" && wordpressOrgPluginFile(p.plugin) && pluginVersion.test(p.expectedVersion) && pluginVersion.test(p.targetVersion);
    case "reinstall_plugin": return keys === "expectedVersion,plugin" && wordpressOrgPluginFile(p.plugin) && pluginVersion.test(p.expectedVersion);
    case "restore_run": return keys === "runId" && /^[a-z0-9-]{8,64}$/.test(p.runId);
    case "set_hardening": return keys === "measure,state" && ["block_php_uploads", "protect_sensitive_files", "disable_file_editor", "disable_xmlrpc", "block_user_enumeration", "security_headers", "verified_crawlers"].includes(p.measure) && ["on", "off"].includes(p.state);
    case "install_plugin": return keys === "activate,slug,version" && /^[a-z0-9][a-z0-9-]{0,99}$/.test(p.slug) && p.slug !== "ai-website-doctor" && pluginVersion.test(p.version) && ["yes", "no"].includes(p.activate);
    default: return false;
  }
}

export const cleanupStepSchema = z.object({
  description: z.string().trim().min(1).max(500),
  operation: z.enum(CLEANUP_OPERATIONS),
  parameters: z.record(z.string(), z.string().max(500)),
}).strict().refine(isAllowedCleanupStep, "Cleanup step parameters are not allowed.");
export type CleanupStep = z.infer<typeof cleanupStepSchema>;

export type CleanupOptionalItem = { id: string; description: string; step: CleanupStep };
export type CleanupPlan = {
  generatedAt: string;
  summary: string;
  steps: CleanupStep[];
  optional: CleanupOptionalItem[];
  manual: string[];
  warnings: string[];
  blockers: string[];
  evidence: { integrityScannedAt: string | null; integrityStatus: string | null; pluginVersion: string | null; openSecurityFindings: string[] };
  planDigest: string;
};

type Json = Record<string, unknown>;
const record = (value: unknown): Json => value && typeof value === "object" && !Array.isArray(value) ? value as Json : {};
const strings = (value: unknown): string[] => Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical((value as Json)[key])]));
  return value;
}

export function cleanupStepsDigest(steps: CleanupStep[]) {
  return createHash("sha256").update(JSON.stringify(canonical(steps.map(({ operation, parameters }) => ({ operation, parameters }))))).digest("hex");
}

function planDigest(steps: CleanupStep[], optional: CleanupOptionalItem[]) {
  return createHash("sha256").update(JSON.stringify(canonical({
    steps: steps.map(({ operation, parameters }) => ({ operation, parameters })),
    optional: optional.map(({ id, step }) => ({ id, operation: step.operation, parameters: step.parameters })),
  }))).digest("hex");
}

export function compareVersions(a: string, b: string) {
  const left = a.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const right = b.split(".").map((part) => Number.parseInt(part, 10) || 0);
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    if ((left[index] ?? 0) !== (right[index] ?? 0)) return (left[index] ?? 0) - (right[index] ?? 0);
  }
  return 0;
}

/** Mirrors the plugin's quarantine rules so the plan never proposes a step the plugin will refuse. */
function quarantinable(path: string, officialChecksums: Record<string, string> | null) {
  if (officialChecksums?.[path]) return false;
  if (["wp-config.php", ".htaccess", "wp-settings.php", "wp-load.php", "index.php"].includes(path)) return false;
  if (path.startsWith("wp-content/plugins/") || path.startsWith("wp-content/themes/")) return false;
  if (!path.includes("/")) return true;
  const executable = /\.(?:php\d?|phtml|pht|phar|phps|inc)$/i.test(path);
  if ((path.startsWith("wp-admin/") || path.startsWith("wp-includes/")) && executable) return true;
  if (path.startsWith("wp-content/uploads/") && executable) return true;
  if (path.startsWith("wp-content/mu-plugins/")) return true;
  return path.startsWith("wp-content/") && path.split("/").length === 2 && executable;
}

export function buildCleanupPlan(input: {
  diagnostics: unknown;
  openIssues: Array<{ fingerprint: string; severity: string; title: string }>;
  officialChecksums: Record<string, string> | null;
  now?: Date;
}): CleanupPlan {
  const now = input.now ?? new Date();
  const diagnostics = record(input.diagnostics);
  const site = record(diagnostics.site);
  const integrity = Object.keys(record(diagnostics.integrity)).length ? record(diagnostics.integrity) : null;
  const core = record(integrity?.core);
  const hashes = record(integrity?.fileHashes) as Record<string, unknown>;
  const pluginVersion = typeof site.pluginVersion === "string" ? site.pluginVersion : null;
  const securityIssues = input.openIssues.filter((issue) => /^(?:wp:)?(?:security|integrity):/.test(issue.fingerprint));
  const openFingerprints = new Set(securityIssues.map((issue) => issue.fingerprint));
  const blockers: string[] = [];
  const warnings: string[] = [];
  const manual: string[] = [];

  if (!Object.keys(diagnostics).length) blockers.push("The WordPress plugin has not synced diagnostics yet.");
  else if (!integrity) blockers.push("The plugin has not sent an integrity scan. Install AI Website Doctor 0.3.0 or later on the site, then select Collect and sync diagnostics.");
  if (!pluginVersion || compareVersions(pluginVersion, MIN_CLEANUP_PLUGIN_VERSION) < 0) {
    blockers.push(`Cleanup needs AI Website Doctor ${MIN_CLEANUP_PLUGIN_VERSION} or later on the site (it reports ${pluginVersion ?? "an older version"}). Upload the new plugin ZIP and choose "Replace current with uploaded".`);
  }
  const scannedAt = typeof integrity?.scannedAt === "string" ? integrity.scannedAt : null;
  if (integrity && (!scannedAt || now.getTime() - Date.parse(scannedAt) > INTEGRITY_MAX_AGE_MS)) {
    blockers.push("The integrity scan is more than 30 minutes old. In the plugin, select Collect and sync diagnostics so the cleanup is built from current file contents.");
  }

  const hashOf = (path: string) => typeof hashes[path] === "string" && sha256.test(hashes[path] as string) ? hashes[path] as string : null;
  const quarantine = new Map<string, string>();
  const addQuarantine = (path: string, reason: string) => {
    if (quarantine.has(path)) return;
    if (!quarantinable(path, input.officialChecksums)) return;
    if (!hashOf(path)) { manual.push(`${path}: ${reason}, but the scan has no content digest for it; remove it manually or rescan.`); return; }
    quarantine.set(path, reason);
  };
  const suspicious = Array.isArray(integrity?.suspiciousFiles) ? integrity!.suspiciousFiles.map(record) : [];
  for (const file of suspicious) {
    const path = typeof file.path === "string" ? file.path : "";
    const signatures = strings(file.signatures).join(", ");
    if (!path) continue;
    if (path.startsWith("wp-content/themes/") || path.startsWith("wp-content/plugins/")) {
      manual.push(`${path} matched malware patterns (${signatures}). Reinstall that theme or plugin from its official source instead of editing the file.`);
      continue;
    }
    if (!input.officialChecksums?.[path]) addQuarantine(path, `matched malware patterns (${signatures})`);
  }
  for (const path of strings(core.unknownPhp)) addQuarantine(path, "is not part of WordPress but sits in a core directory");
  for (const path of strings(integrity?.uploadsPhp)) addQuarantine(path, "is executable code in the uploads directory");
  const spamSitemaps = openFingerprints.has("security:robots-sitemaps") || openFingerprints.has("security:sitemap-spam") || openFingerprints.has("wp:integrity:robots-file");
  const robots = record(integrity?.robotsFile);
  if (robots.present === true && (Number(robots.sitemapEntries) >= 5 || spamSitemaps)) addQuarantine("robots.txt", "is a physical robots.txt advertising injected sitemaps");
  if (spamSitemaps) {
    for (const path of strings(integrity?.rootUnknownFiles)) {
      if (/^sitemap[-_]?[\w-]*\.xml(?:\.gz)?$/i.test(path)) addQuarantine(path, "is a physical sitemap file the spam injection advertises");
    }
  }

  const steps: CleanupStep[] = [];
  for (const [path, reason] of quarantine) {
    steps.push({ description: `Quarantine ${path}: it ${reason}.`, operation: "quarantine_file", parameters: { path, expectedSha256: hashOf(path)! } });
  }
  const modified = strings(core.modified);
  if (modified.length && !input.officialChecksums) manual.push("WordPress.org checksums for this version could not be fetched, so modified core files cannot be restored automatically. Reinstall WordPress core from Dashboard → Updates → Re-install.");
  for (const path of modified) {
    const official = input.officialChecksums?.[path];
    const current = hashOf(path);
    if (!official || !current || path.startsWith("wp-content/")) {
      if (input.officialChecksums) manual.push(`${path} differs from the official release but cannot be restored automatically; reinstall WordPress core.`);
      continue;
    }
    steps.push({ description: `Restore ${path} from the official WordPress ${String(core.version || "")} release.`.replace("  ", " "), operation: "restore_core_file", parameters: { path, officialMd5: official, expectedCurrentSha256: current } });
  }
  const htaccess = record(integrity?.htaccess);
  const htaccessLines = Array.isArray(htaccess.suspiciousLines) ? htaccess.suspiciousLines.map(record) : [];
  if (htaccessLines.length && typeof htaccess.sha256 === "string" && sha256.test(htaccess.sha256)) {
    steps.push({
      description: `Remove ${htaccessLines.length} injected .htaccess rule(s) (${[...new Set(htaccessLines.map((line) => String(line.reason)))].join(", ")}); the WordPress block and other rules are kept.`,
      operation: "remove_htaccess_rules",
      parameters: { expectedSha256: htaccess.sha256, lines: htaccessLines.map((line) => String(line.line)).join(",") },
    });
  }

  const plugins = Array.isArray(diagnostics.plugins) ? diagnostics.plugins.map(record) : [];
  // WordPress.org plugins whose code differs from the official checksums are reinstalled.
  const pluginIntegrity = Array.isArray(integrity?.pluginIntegrity) ? integrity!.pluginIntegrity.map(record) : [];
  for (const result of pluginIntegrity) {
    if (result.status !== "modified" || typeof result.plugin !== "string" || typeof result.version !== "string") continue;
    const step = { description: `Reinstall ${result.plugin.split("/")[0]} ${result.version} from WordPress.org: ${[...strings(result.modified), ...strings(result.addedPhp).map((path) => `${path} (added)`)].slice(0, 3).join(", ")} differ from the official release.`, operation: "reinstall_plugin" as const, parameters: { plugin: result.plugin, expectedVersion: result.version } };
    if (isAllowedCleanupStep(step)) steps.push(step);
  }
  const optional: CleanupOptionalItem[] = [];
  for (const plugin of plugins) {
    const file = typeof plugin.file === "string" ? plugin.file : "";
    if (!RISKY_PLUGIN_SLUGS.includes(file.split("/")[0])) continue;
    optional.push({
      id: `plugin:${file}`,
      description: `Remove ${String(plugin.name)} ${String(plugin.version)}: file-manager plugins are a common way attackers get in. It is deactivated and moved to the quarantine.`,
      step: { description: `Deactivate and quarantine the ${String(plugin.name)} plugin.`, operation: "quarantine_plugin", parameters: { plugin: file, expectedVersion: String(plugin.version ?? "") } },
    });
  }
  const recentAdmins = Array.isArray(record(integrity?.admins).recent) ? (record(integrity?.admins).recent as unknown[]).map(record) : [];
  for (const admin of recentAdmins) {
    const login = typeof admin.login === "string" ? admin.login : "";
    if (!/^[A-Za-z0-9._@ -]{1,60}$/.test(login)) continue;
    optional.push({
      id: `admin:${login}`,
      description: `Demote administrator "${login}" (created ${String(admin.registeredAt).slice(0, 10)}): only tick this if nobody on your team created it.`,
      step: { description: `Demote the recently created administrator "${login}" to subscriber, reset its password and sign it out.`, operation: "demote_user", parameters: { login, expectedRole: "administrator" } },
    });
  }

  const compromised = steps.length > 0 || securityIssues.some((issue) => issue.severity === "critical" || issue.severity === "high");
  if (compromised && steps.length + optional.length > 0) {
    steps.push({ description: "Replace the eight WordPress secret keys and salts in wp-config.php, so stolen login cookies stop working. Everyone, including you, will need to sign in again.", operation: "rotate_salts", parameters: {} });
  }
  if (steps.length) steps.push({ description: "Purge the page cache so visitors and search engines stop receiving cached spam pages.", operation: "purge_page_cache", parameters: {} });
  // Leave room for optional items; keep the closing salt rotation and cache purge.
  const stepLimit = MAX_CLEANUP_STEPS - optional.length;
  if (steps.length > stepLimit) {
    const closing = steps.filter((step) => step.operation === "rotate_salts" || step.operation === "purge_page_cache");
    const body = steps.filter((step) => !closing.includes(step)).slice(0, stepLimit - closing.length);
    warnings.push(`The cleanup has more than ${stepLimit} steps; the first ${body.length} file changes run now and a fresh plan will contain the rest.`);
    steps.splice(0, steps.length, ...body, ...closing);
  }

  if (compromised && !steps.some((step) => step.operation !== "rotate_salts" && step.operation !== "purge_page_cache")) {
    manual.push("The outside check shows the site is compromised, but the integrity scan found no file this cleanup can fix. The injected code is probably inside a plugin or theme: reinstall every plugin and theme from its official source.");
  }
  if (compromised) {
    manual.push("Reinstall premium plugins and your theme from their vendors and delete what you do not use: only WordPress.org plugins can be checked against official checksums.");
    manual.push("Change the passwords of every WordPress administrator, your hosting account, SFTP and the database.");
    manual.push("In Google Search Console, review Security issues, resubmit your real sitemap and request removal of the spam URLs.");
    warnings.push("These changes are made on your live site. Every changed or removed file is kept in a private quarantine and the run can be restored from the plugin until you purge it.");
    warnings.push("After the cleanup the app checks the site again from outside. If the spam comes back, something not covered here (for example a hidden scheduled task or a backdoor in a plugin) is reinstalling it.");
  }

  const actionable = steps.filter((step) => step.operation !== "purge_page_cache").length;
  const summary = !compromised
    ? "No compromise evidence was found; nothing needs cleaning."
    : `${actionable} change(s) will be made after one approval: ${[
      quarantine.size ? `${quarantine.size} file(s) quarantined` : "",
      steps.filter((step) => step.operation === "restore_core_file").length ? `${steps.filter((step) => step.operation === "restore_core_file").length} core file(s) restored` : "",
      steps.some((step) => step.operation === "remove_htaccess_rules") ? ".htaccess cleaned" : "",
      steps.some((step) => step.operation === "rotate_salts") ? "salts rotated" : "",
    ].filter(Boolean).join(", ")}, then the page cache is purged and the site is re-checked from outside.`;

  return {
    generatedAt: now.toISOString(),
    summary,
    steps,
    optional,
    manual: [...new Set(manual)].slice(0, 40),
    warnings,
    blockers,
    evidence: { integrityScannedAt: scannedAt, integrityStatus: typeof integrity?.status === "string" ? integrity.status : null, pluginVersion, openSecurityFindings: securityIssues.map((issue) => issue.title) },
    planDigest: planDigest(steps, optional),
  };
}

/** The steps that will run: the plan's steps plus ticked optional items, in safe order. */
export function selectCleanupSteps(plan: CleanupPlan, include: string[]): CleanupStep[] {
  const unknown = include.filter((id) => !plan.optional.some((item) => item.id === id));
  if (unknown.length) throw new Error(`Unknown optional cleanup item: ${unknown[0]}`);
  const chosen = plan.optional.filter((item) => include.includes(item.id)).map((item) => item.step);
  // Optional removals run before salt rotation and the cache purge.
  const tail = plan.steps.filter((step) => step.operation === "rotate_salts" || step.operation === "purge_page_cache");
  const head = plan.steps.filter((step) => step.operation !== "rotate_salts" && step.operation !== "purge_page_cache");
  const steps = [...head, ...chosen, ...tail];
  if (!tail.some((step) => step.operation === "purge_page_cache") && steps.length) steps.push({ description: "Purge the page cache.", operation: "purge_page_cache", parameters: {} });
  return steps.slice(0, MAX_CLEANUP_STEPS);
}

/** Official per-file MD5 checksums from WordPress.org, or null when unavailable. */
export async function fetchOfficialChecksums(version: string, locale: string, fetcher: typeof fetch = fetch): Promise<Record<string, string> | null> {
  if (!/^\d+\.\d+(?:\.\d+)?(?:-[A-Za-z0-9.]+)?$/.test(version)) return null;
  for (const candidate of [...new Set([/^[a-z]{2,3}(?:_[A-Z]{2})?(?:_[a-z]+)?$/.test(locale) ? locale : "en_US", "en_US"])]) {
    try {
      const response = await fetcher(`https://api.wordpress.org/core/checksums/1.0/?version=${encodeURIComponent(version)}&locale=${encodeURIComponent(candidate)}`, { signal: AbortSignal.timeout(10_000) });
      if (!response.ok) continue;
      const body = await response.json() as { checksums?: unknown };
      const checksums = record(body.checksums);
      const entries = Object.entries(checksums).filter((entry): entry is [string, string] => typeof entry[1] === "string" && /^[a-f0-9]{32}$/.test(entry[1]));
      if (entries.length > 100) return Object.fromEntries(entries);
    } catch {
      // Try the next locale; the plan reports when checksums are unavailable.
    }
  }
  return null;
}

/** Plugin file for a "wp:plugin-update:<hash>" fingerprint (the plugin hashes the file path). */
export function pluginForUpdateFingerprint(fingerprint: string, plugins: Array<Record<string, unknown>>) {
  const hash = fingerprint.replace(/^wp:plugin-update:/, "");
  return plugins.find((plugin) => typeof plugin.file === "string" && createHash("sha256").update(plugin.file).digest("hex").slice(0, 20) === hash) ?? null;
}

export type FixPlan = { steps: CleanupStep[]; title: string; skipped: string[] };

/** Update steps for WordPress.org plugins with an available update (optionally only the listed files). */
export function pluginUpdateSteps(diagnostics: unknown, only?: string[]): FixPlan {
  const plugins = Array.isArray(record(diagnostics).plugins) ? (record(diagnostics).plugins as unknown[]).map(record) : [];
  const steps: CleanupStep[] = [];
  const skipped: string[] = [];
  for (const plugin of plugins) {
    const file = typeof plugin.file === "string" ? plugin.file : "";
    if (!plugin.updateAvailable || (only && !only.includes(file))) continue;
    const name = String(plugin.name ?? file);
    if (plugin.source !== "wordpress.org") { skipped.push(`${name}: not hosted on WordPress.org (premium or custom); update it from its vendor.`); continue; }
    if (typeof plugin.newVersion !== "string") { skipped.push(`${name}: the target version is unknown; sync diagnostics again.`); continue; }
    const step = { description: `Update ${name} ${String(plugin.version)} → ${plugin.newVersion} from WordPress.org.`, operation: "update_plugin" as const, parameters: { plugin: file, expectedVersion: String(plugin.version ?? ""), targetVersion: plugin.newVersion } };
    if (isAllowedCleanupStep(step)) steps.push(step); else skipped.push(`${name}: its files are not in a standard plugin directory.`);
  }
  return { steps, title: steps.length === 1 ? steps[0].description.replace(/ from WordPress\.org\.$/, "") : `Update ${steps.length} plugins`, skipped };
}

/** The one-click fix for an issue, or null when the finding has no automatic fix. */
export function fixPlanForIssue(fingerprint: string, diagnostics: unknown): FixPlan | null {
  const plugins = Array.isArray(record(diagnostics).plugins) ? (record(diagnostics).plugins as unknown[]).map(record) : [];
  if (fingerprint.startsWith("wp:plugin-update:")) {
    const plugin = pluginForUpdateFingerprint(fingerprint, plugins);
    if (!plugin || typeof plugin.file !== "string") return { steps: [], title: "Update plugin", skipped: ["The plugin is no longer in the latest diagnostics; sync again."] };
    return pluginUpdateSteps(diagnostics, [plugin.file]);
  }
  const vulnerable = /^vuln:plugin-([a-z0-9-]+):/.exec(fingerprint);
  if (vulnerable) {
    const plugin = plugins.find((item) => typeof item.file === "string" && item.file.split("/")[0] === vulnerable[1]);
    if (!plugin || typeof plugin.file !== "string") return { steps: [], title: "Fix vulnerable plugin", skipped: ["The plugin is no longer installed."] };
    const evidence = (record(diagnostics).__issueEvidence ?? {}) as Record<string, unknown>;
    const fixedIn = typeof evidence.fixedIn === "string" ? evidence.fixedIn : null;
    if (fixedIn && typeof plugin.newVersion === "string" && compareVersions(plugin.newVersion, fixedIn) >= 0) return pluginUpdateSteps(diagnostics, [plugin.file]);
    if (fixedIn) return { steps: [], title: "Update vulnerable plugin", skipped: [plugin.source === "wordpress.org" ? `WordPress has not offered version ${fixedIn} yet; sync diagnostics again.` : `Update ${String(plugin.name)} to ${fixedIn} from its vendor.`] };
    const step = { description: `Deactivate and quarantine ${String(plugin.name)} ${String(plugin.version)}: it has a known vulnerability with no fixed version yet.`, operation: "quarantine_plugin" as const, parameters: { plugin: plugin.file, expectedVersion: String(plugin.version ?? "") } };
    return isAllowedCleanupStep(step) ? { steps: [step], title: `Remove vulnerable ${String(plugin.name)}`, skipped: [] } : { steps: [], title: "Remove vulnerable plugin", skipped: ["The plugin cannot be removed automatically."] };
  }
  if (fingerprint.startsWith("wp:integrity:plugin-modified:")) {
    const slug = fingerprint.replace(/^wp:integrity:plugin-modified:/, "");
    const integrity = record(record(diagnostics).integrity);
    const result = (Array.isArray(integrity.pluginIntegrity) ? integrity.pluginIntegrity.map(record) : [])
      .find((item) => typeof item.plugin === "string" && item.plugin.split("/")[0] === slug && item.status === "modified");
    if (!result) return { steps: [], title: "Reinstall plugin", skipped: ["The latest integrity scan no longer reports this plugin as modified."] };
    const step = { description: `Reinstall ${slug} ${String(result.version)} from WordPress.org.`, operation: "reinstall_plugin" as const, parameters: { plugin: String(result.plugin), expectedVersion: String(result.version) } };
    return isAllowedCleanupStep(step) ? { steps: [step], title: step.description.replace(/ from WordPress\.org\.$/, ""), skipped: [] } : { steps: [], title: "Reinstall plugin", skipped: ["The plugin is not in a standard directory."] };
  }
  return null;
}
