import https from "node:https";
import { pinnedLookup, resolvePublicAddresses } from "./monitor.ts";

/**
 * Switch a site's PHP version through the owner's cPanel account (UAPI
 * LangPHP, the API behind cPanel's MultiPHP Manager).
 *
 * The sequence is: check compatibility from the plugin's report, record the
 * current version, sample the site from outside, switch, read the version
 * back from cPanel, sample the site again, and switch back automatically when
 * a page that worked before now fails. The paired plugin's next sync then
 * confirms which PHP WordPress really runs on: hosts that use CloudLinux's
 * PHP Selector or a hand-written .htaccess handler can override MultiPHP.
 *
 * Requests go only to public addresses (DNS pinned per request), with normal
 * TLS certificate checks, so a token cannot be sent to a spoofed server.
 */

export const CPANEL_PORTS = [2083, 443] as const;
/** The AI Website Doctor plugin's own minimum ("Requires PHP" in its header). */
export const PLUGIN_MIN_PHP = "7.2";
/**
 * Oldest WordPress release that supports each PHP version (WordPress's PHP
 * compatibility table; "beta support" counts as supported).
 */
export const WORDPRESS_FOR_PHP: Record<string, string> = {
  "7.2": "4.9",
  "7.3": "5.0",
  "7.4": "5.3",
  "8.0": "5.6",
  "8.1": "5.9",
  "8.2": "6.1",
  "8.3": "6.4",
  "8.4": "6.7",
  "8.5": "6.9",
};

export class CpanelError extends Error {
  readonly status: number;
  constructor(message: string, status: number = 400) {
    super(message);
    this.status = status;
  }
}

export type CpanelTarget = { hostname: string; port: number; username: string; token: string };
export type CpanelTransport = (url: URL, headers: Record<string, string>) => Promise<{ status: number; body: string }>;
export type CpanelCall = (module: string, func: string, params?: Record<string, string>) => Promise<unknown>;

/** cPanel's version id ("ea-php81") as a PHP release ("8.1"); null for anything else. */
export function phpLabel(id: string | null | undefined): string | null {
  const match = /^ea-php(\d)(\d{1,2})$/.exec(String(id ?? "").trim());
  return match ? `${match[1]}.${Number(match[2])}` : null;
}

/** "8.1" or "ea-php81" as cPanel's version id. */
export function phpId(value: string): string | null {
  const trimmed = value.trim().toLowerCase();
  if (phpLabel(trimmed)) return trimmed;
  const match = /^(\d)\.(\d{1,2})$/.exec(trimmed);
  return match ? `ea-php${match[1]}${match[2]}` : null;
}

/** Numeric version comparison: compareVersions("8.10", "8.9") > 0. */
export function compareVersions(a: string, b: string): number {
  const left = a.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const right = b.split(".").map((part) => Number.parseInt(part, 10) || 0);
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

function tlsHint(code: string, hostname: string) {
  return `The cPanel server's TLS certificate is not valid for ${hostname} (${code}). Use the server hostname shown under Server Information in cPanel (port 2083), or cpanel.<your domain> on port 443.`;
}

async function defaultTransport(url: URL, headers: Record<string, string>): Promise<{ status: number; body: string }> {
  const addresses = await resolvePublicAddresses(url.hostname);
  return new Promise((resolve, reject) => {
    const request = https.request(url, { method: "GET", headers, timeout: 20_000, lookup: pinnedLookup(addresses) }, (response) => {
      const chunks: Buffer[] = [];
      let size = 0;
      response.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > 2 * 1024 * 1024) {
          response.destroy();
          reject(new Error("The cPanel response was too large."));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      response.on("error", reject);
    });
    request.on("timeout", () => request.destroy(new Error("cPanel did not answer within 20 seconds.")));
    request.on("error", reject);
    request.end();
  });
}

function connectionMessage(error: unknown, target: CpanelTarget) {
  const code = error && typeof error === "object" && "code" in error ? String((error as { code?: unknown }).code ?? "") : "";
  if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ALTNAME/.test(code)) return tlsHint(code, target.hostname);
  if (code === "ECONNREFUSED" || code === "ETIMEDOUT" || code === "EHOSTUNREACH" || code === "ENOTFOUND") {
    return `Could not reach cPanel at ${target.hostname}:${target.port} (${code}). Check the hostname and port; cPanel normally listens on 2083.`;
  }
  return `Could not reach cPanel at ${target.hostname}:${target.port}: ${error instanceof Error ? error.message : "unknown error"}`;
}

export function cpanelClient(target: CpanelTarget, transport: CpanelTransport = defaultTransport): CpanelCall {
  if (!/^[a-z][a-z0-9_-]{0,31}$/i.test(target.username)) throw new CpanelError("Enter the cPanel account username (letters and digits).");
  if (!/^[A-Za-z0-9]{16,128}$/.test(target.token)) throw new CpanelError("That does not look like a cPanel API token (create one under Security → Manage API Tokens).");
  if (!(CPANEL_PORTS as readonly number[]).includes(target.port)) throw new CpanelError("cPanel connections use port 2083, or 443 for a cpanel.<domain> proxy.");
  return async (module, func, params = {}) => {
    const url = new URL(`https://${target.hostname}:${target.port}/execute/${module}/${func}`);
    for (const [name, value] of Object.entries(params)) url.searchParams.set(name, value);
    let response: { status: number; body: string };
    try {
      response = await transport(url, { authorization: `cpanel ${target.username}:${target.token}`, accept: "application/json" });
    } catch (error) {
      throw new CpanelError(connectionMessage(error, target), 502);
    }
    if (response.status === 401 || response.status === 403) throw new CpanelError("cPanel rejected the username or API token.", 400);
    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(response.body) as Record<string, unknown>;
    } catch {
      throw new CpanelError(`cPanel did not return an API response (HTTP ${response.status}). Check the hostname and port, and that the username and token belong to the same account.`, 502);
    }
    // /execute/ answers flat; some proxies wrap the same object in "result".
    const result = payload.result && typeof payload.result === "object" && "status" in (payload.result as object)
      ? payload.result as Record<string, unknown>
      : payload;
    if (Number(result.status) !== 1) {
      const errors = (Array.isArray(result.errors) ? result.errors : []).map(String).filter(Boolean).join("; ");
      const featureOff = /feature|multiphp|not have access|permission/i.test(errors);
      throw new CpanelError(
        featureOff
          ? `cPanel refused the request: ${errors} The host must enable MultiPHP Manager for this account.`
          : `cPanel reported an error: ${errors || `${module}::${func} failed.`}`,
        featureOff ? 403 : 400,
      );
    }
    return result.data;
  };
}

export type VhostPhp = { vhost: string; id: string; label: string | null; documentRoot: string | null; inherited: boolean; phpFpm: boolean };
export type PhpOption = { id: string; label: string };
export type PhpState = { installed: PhpOption[]; systemDefault: string | null; vhosts: VhostPhp[] };

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

export function parseVhosts(data: unknown): VhostPhp[] {
  // An array of vhosts; a single object when the request named one vhost.
  const entries = Array.isArray(data) ? data : data && typeof data === "object" ? [data] : [];
  return entries.map((item) => {
    const entry = record(item);
    // Documented as an array, returned by some versions as an object: { domain } or { system_default: 1 }.
    const sources = Array.isArray(entry.phpversion_source) ? entry.phpversion_source.map(record) : [record(entry.phpversion_source)];
    return {
      vhost: String(entry.vhost ?? "").toLowerCase(),
      id: String(entry.version ?? ""),
      label: phpLabel(String(entry.version ?? "")),
      documentRoot: typeof entry.documentroot === "string" ? entry.documentroot : null,
      inherited: sources.some((source) => Number(source.system_default) === 1),
      phpFpm: Number(entry.php_fpm) === 1,
    };
  }).filter((entry) => entry.vhost && entry.id);
}

export async function readPhpState(call: CpanelCall): Promise<PhpState> {
  const [installed, vhosts, systemDefault] = await Promise.all([
    call("LangPHP", "php_get_installed_versions"),
    call("LangPHP", "php_get_vhost_versions"),
    call("LangPHP", "php_get_system_default_version").catch(() => null),
  ]);
  const versions = Array.isArray(record(installed).versions) ? record(installed).versions as unknown[] : [];
  return {
    installed: versions.map(String).flatMap((id) => {
      const label = phpLabel(id);
      return label ? [{ id, label }] : [];
    }).sort((a, b) => compareVersions(a.label, b.label)),
    systemDefault: phpLabel(String(record(systemDefault).version ?? "")) ? String(record(systemDefault).version) : null,
    vhosts: parseVhosts(vhosts),
  };
}

/** The account's virtual host serving the registered site (www. is an alias of the bare domain). */
export function matchVhost(vhosts: VhostPhp[], siteUrl: string): VhostPhp | null {
  const host = new URL(siteUrl).hostname.toLowerCase().replace(/\.$/, "");
  const candidates = [host, host.replace(/^www\./, "")];
  for (const candidate of candidates) {
    const found = vhosts.find((entry) => entry.vhost === candidate);
    if (found) return found;
  }
  return null;
}

export async function discoverCpanelSite(target: CpanelTarget, siteUrl: string, transport?: CpanelTransport) {
  const call = cpanelClient(target, transport);
  const state = await readPhpState(call);
  const vhost = matchVhost(state.vhosts, siteUrl);
  if (!vhost) {
    const found = state.vhosts.map((entry) => entry.vhost).slice(0, 10).join(", ");
    throw new CpanelError(`This cPanel account has no domain matching ${new URL(siteUrl).hostname}${found ? ` (it has: ${found})` : ""}. Connect the account that hosts this website.`, 404);
  }
  return { vhost, installed: state.installed };
}

export type PluginReport = {
  collectedAt?: string;
  site?: { wpVersion?: string; phpVersion?: string };
  plugins?: Array<{ name?: string; active?: boolean; updateAvailable?: boolean; source?: string; requiresPhp?: string }>;
  themes?: Array<{ name?: string; active?: boolean; parentOfActive?: boolean; requiresPhp?: string }>;
} | null;

/** What stands in the way of moving the site to `target` ("8.2"). Blockers stop the switch; warnings are shown before confirming. */
export function checkPhpCompatibility(input: { current: string | null; target: string; installed: string[]; report: PluginReport; now?: Date }) {
  const blockers: string[] = [];
  const warnings: string[] = [];
  const { current, target, report } = input;
  if (!input.installed.includes(target)) blockers.push(`PHP ${target} is not installed on this server.`);
  if (current === target) blockers.push(`The site already runs PHP ${target}.`);
  if (compareVersions(target, PLUGIN_MIN_PHP) < 0) blockers.push(`PHP ${target} is older than ${PLUGIN_MIN_PHP}, the minimum for the AI Website Doctor plugin; the plugin would stop working and the change could not be confirmed.`);

  const wpVersion = report?.site?.wpVersion;
  const neededWordPress = WORDPRESS_FOR_PHP[target];
  if (wpVersion && neededWordPress && compareVersions(wpVersion, neededWordPress) < 0) {
    blockers.push(`WordPress ${wpVersion} does not support PHP ${target}. Update WordPress to ${neededWordPress} or newer first.`);
  } else if (!neededWordPress) {
    warnings.push(`WordPress's support for PHP ${target} is not known to this app yet; check wordpress.org before switching.`);
  }

  const upgrade = current ? compareVersions(target, current) > 0 : true;
  const activePlugins = (report?.plugins ?? []).filter((plugin) => plugin.active);
  const activeThemes = (report?.themes ?? []).filter((theme) => theme.active || theme.parentOfActive);
  for (const item of [...activePlugins.map((plugin) => ({ kind: "plugin", ...plugin })), ...activeThemes.map((theme) => ({ kind: "theme", ...theme }))]) {
    if (item.requiresPhp && compareVersions(target, item.requiresPhp) < 0) {
      blockers.push(`The ${item.kind} ${item.name ?? "(unnamed)"} requires PHP ${item.requiresPhp} or newer.`);
    }
  }

  if (!report) {
    warnings.push("The WordPress plugin has not reported yet, so plugin and theme compatibility cannot be checked and the new version cannot be confirmed from inside WordPress. The outside check after switching still runs.");
  } else {
    const collected = report.collectedAt ? Date.parse(report.collectedAt) : Number.NaN;
    const ageMinutes = Number.isFinite(collected) ? ((input.now ?? new Date()).getTime() - collected) / 60_000 : null;
    if (ageMinutes === null || ageMinutes > 60) warnings.push("The plugin's last report is more than an hour old; the compatibility check may miss recent changes.");
    if (upgrade) {
      const outdated = activePlugins.filter((plugin) => plugin.updateAvailable).map((plugin) => plugin.name ?? "(unnamed)");
      if (outdated.length) warnings.push(`Update these plugins first; old plugin versions are the most common cause of errors after a PHP upgrade: ${outdated.slice(0, 6).join(", ")}${outdated.length > 6 ? ` and ${outdated.length - 6} more` : ""}.`);
      const unchecked = activePlugins.filter((plugin) => plugin.source === "other").length;
      if (unchecked) warnings.push(`${unchecked} active premium or custom plugin(s) are not on WordPress.org; make sure their vendors support PHP ${target}.`);
    }
  }
  if (current && upgrade && current.split(".")[0] !== target.split(".")[0]) {
    warnings.push(`PHP ${target.split(".")[0]} removed features that older code relies on. The site is checked from outside and switched back automatically if it breaks, but also test forms, checkout and the admin after switching.`);
  }
  if (!upgrade && current) warnings.push(`PHP ${target} is older than the current ${current}; older PHP releases may no longer get security fixes.`);
  return { blockers, warnings };
}

export const HEALTH_PATHS = ["/", "/wp-login.php", "/wp-json/", "/wp-admin/admin-ajax.php"] as const;
const FATAL_MARKERS = /There has been a critical error on (?:this|your) website|<b>(?:Fatal|Parse) error<\/b>|PHP (?:Fatal|Parse) error|Fatal error: (?:Uncaught|Allowed memory|Cannot redeclare|Call to undefined)|Parse error: syntax error/i;

export type HealthSample = { path: string; statusCode: number | null; bytes: number; fatal: boolean; poweredBy: string | null; error: string | null };
export type PageFetcher = (url: string) => Promise<{ statusCode: number; text: string; headers?: Record<string, unknown> }>;

export async function sampleSiteHealth(siteUrl: string, fetchPage: PageFetcher): Promise<HealthSample[]> {
  // Relative to the site URL, so a WordPress installed in a subdirectory is checked there.
  const base = new URL(siteUrl);
  if (!base.pathname.endsWith("/")) base.pathname = `${base.pathname}/`;
  base.search = "";
  base.hash = "";
  return Promise.all(HEALTH_PATHS.map(async (path) => {
    const url = new URL(path.slice(1), base);
    // Bypass page caches on the home page, which would otherwise hide a broken PHP.
    if (path === "/") url.searchParams.set("awd-php-check", Math.random().toString(36).slice(2, 10));
    try {
      const page = await fetchPage(url.toString());
      const poweredBy = page.headers?.["x-powered-by"];
      return {
        path,
        statusCode: page.statusCode,
        bytes: Buffer.byteLength(page.text),
        fatal: FATAL_MARKERS.test(page.text),
        poweredBy: typeof poweredBy === "string" && /^PHP\/[\d.]+/i.test(poweredBy) ? poweredBy.slice(0, 40) : null,
        error: null,
      };
    } catch (error) {
      return { path, statusCode: null, bytes: 0, fatal: false, poweredBy: null, error: error instanceof Error ? error.message.slice(0, 200) : "request failed" };
    }
  }));
}

function healthy(sample: HealthSample | undefined) {
  return Boolean(sample && !sample.error && sample.statusCode !== null && sample.statusCode < 500);
}

/** Problems in `after` compared with `before`. The home page must work afterwards; other pages must keep working if they did. */
export function compareSiteHealth(before: HealthSample[], after: HealthSample[]): string[] {
  const problems: string[] = [];
  for (const sample of after) {
    const baseline = before.find((entry) => entry.path === sample.path);
    const describe = sample.error ? sample.error : `HTTP ${sample.statusCode}`;
    if (sample.path === "/" || healthy(baseline)) {
      if (!healthy(sample)) problems.push(`${sample.path} now fails (${describe}).`);
      else if (sample.fatal && !baseline?.fatal) problems.push(`${sample.path} now shows a PHP error.`);
      else if (sample.path === "/" && (baseline?.bytes ?? 0) >= 512 && sample.bytes < 100) problems.push("The home page is now blank.");
    }
  }
  return problems;
}

export type PhpSwitchStep = { step: string; ok: boolean; detail: string };
export type PhpSwitchResult = {
  status: "verified" | "rolled_back" | "rollback_failed" | "failed" | "blocked";
  message: string;
  vhost: string;
  from: PhpOption | null;
  to: PhpOption;
  steps: PhpSwitchStep[];
  baseline: HealthSample[];
  after: HealthSample[];
  startedAt: string;
  finishedAt: string;
};

async function readVhost(call: CpanelCall, vhost: string) {
  const entry = parseVhosts(await call("LangPHP", "php_get_vhost_versions")).find((item) => item.vhost === vhost);
  if (!entry) throw new CpanelError(`cPanel no longer lists ${vhost} on this account.`, 404);
  return entry;
}

/** Switch, verify from outside, and switch back when the site breaks. */
export async function switchPhpVersion(input: {
  call: CpanelCall;
  vhost: string;
  siteUrl: string;
  targetId: string;
  expectedCurrentId?: string | null;
  fetchPage: PageFetcher;
  sleep?: (ms: number) => Promise<void>;
  attempts?: number;
  intervalMs?: number;
  settleMs?: number;
  now?: () => Date;
}): Promise<PhpSwitchResult> {
  const sleep = input.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const now = input.now ?? (() => new Date());
  const attempts = input.attempts ?? 4;
  const intervalMs = input.intervalMs ?? 5_000;
  const settleMs = input.settleMs ?? 3_000;
  const startedAt = now().toISOString();
  const to = { id: input.targetId, label: phpLabel(input.targetId) ?? input.targetId };
  const steps: PhpSwitchStep[] = [];
  const finish = (status: PhpSwitchResult["status"], message: string, from: PhpOption | null, baseline: HealthSample[] = [], after: HealthSample[] = []): PhpSwitchResult => ({
    status, message, vhost: input.vhost, from, to, steps, baseline, after, startedAt, finishedAt: now().toISOString(),
  });

  const current = await readVhost(input.call, input.vhost);
  const from = { id: current.id, label: current.label ?? current.id };
  steps.push({ step: "Read current version", ok: true, detail: `${input.vhost} runs PHP ${from.label}${current.inherited ? " (the server default)" : ""}.` });
  if (input.expectedCurrentId && current.id !== input.expectedCurrentId) {
    return finish("blocked", `The PHP version changed to ${from.label} since it was reviewed; review again before switching.`, from);
  }
  if (current.id === input.targetId) return finish("blocked", `The site already runs PHP ${to.label}.`, from);

  const baseline = await sampleSiteHealth(input.siteUrl, input.fetchPage);
  const home = baseline.find((sample) => sample.path === "/");
  if (home?.error) {
    steps.push({ step: "Check the site before switching", ok: false, detail: home.error });
    return finish("blocked", `The home page cannot be checked from outside (${home.error}), so a broken switch could not be detected. Nothing was changed.`, from, baseline);
  }
  steps.push({ step: "Check the site before switching", ok: true, detail: baseline.map((sample) => `${sample.path} ${sample.error ? "unreachable" : sample.statusCode}`).join(", ") });

  try {
    await input.call("LangPHP", "php_set_vhost_versions", { version: input.targetId, vhost: input.vhost });
    steps.push({ step: `Switch to PHP ${to.label}`, ok: true, detail: "cPanel accepted the change." });
  } catch (error) {
    const applied = await readVhost(input.call, input.vhost).then((entry) => entry.id === input.targetId).catch(() => false);
    steps.push({ step: `Switch to PHP ${to.label}`, ok: false, detail: error instanceof Error ? error.message : "cPanel refused the change." });
    if (!applied) return finish("failed", `cPanel did not switch the version: ${error instanceof Error ? error.message : "unknown error"} Nothing was changed.`, from, baseline);
  }

  await sleep(settleMs);
  let after: HealthSample[] = [];
  let problems: string[] = ["The site was not checked."];
  let readBack = "";
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const entry = await readVhost(input.call, input.vhost).catch(() => null);
    readBack = entry?.id ?? "unknown";
    after = await sampleSiteHealth(input.siteUrl, input.fetchPage);
    problems = compareSiteHealth(baseline, after);
    if (readBack !== input.targetId) problems = [`cPanel still reports ${phpLabel(readBack) ?? readBack}.`, ...problems];
    if (!problems.length) break;
    if (attempt < attempts) await sleep(intervalMs);
  }
  if (!problems.length) {
    steps.push({ step: "Verify the site from outside", ok: true, detail: after.map((sample) => `${sample.path} ${sample.statusCode}`).join(", ") });
    return finish("verified", `The site now runs on PHP ${to.label} and answered normally from outside. The WordPress plugin confirms the version on its next sync.`, from, baseline, after);
  }
  steps.push({ step: "Verify the site from outside", ok: false, detail: problems.join(" ") });

  try {
    await input.call("LangPHP", "php_set_vhost_versions", { version: from.id, vhost: input.vhost });
    await sleep(settleMs);
    const restored = await readVhost(input.call, input.vhost);
    if (restored.id !== from.id) throw new Error(`cPanel reports ${restored.label ?? restored.id} after switching back.`);
    const recovered = await sampleSiteHealth(input.siteUrl, input.fetchPage);
    const remaining = compareSiteHealth(baseline, recovered);
    steps.push({ step: `Switch back to PHP ${from.label}`, ok: true, detail: remaining.length ? `Switched back, but: ${remaining.join(" ")}` : "Switched back; the site answers as before." });
    return finish("rolled_back", `PHP ${to.label} broke the site (${problems.join(" ")}), so it was switched back to PHP ${from.label}.${current.inherited ? " It is now set explicitly rather than following the server default." : ""}`, from, baseline, after);
  } catch (error) {
    const detail = error instanceof Error ? error.message : "unknown error";
    steps.push({ step: `Switch back to PHP ${from.label}`, ok: false, detail });
    return finish("rollback_failed", `PHP ${to.label} broke the site (${problems.join(" ")}) and switching back failed (${detail}). Switch ${input.vhost} back to PHP ${from.label} now in cPanel → MultiPHP Manager.`, from, baseline, after);
  }
}

/** Whether the plugin's report after the switch shows the new PHP version. */
export function pluginConfirmation(change: { status: string; to: PhpOption; finishedAt: string } | null, report: PluginReport, now: Date = new Date()) {
  if (!change || change.status !== "verified") return null;
  if (!report?.site?.phpVersion) return { state: "unavailable" as const, detail: "The WordPress plugin is not connected, so the version WordPress runs on cannot be confirmed from inside." };
  const collected = report.collectedAt ? Date.parse(report.collectedAt) : Number.NaN;
  if (!Number.isFinite(collected) || collected <= Date.parse(change.finishedAt)) {
    const minutes = Math.round((now.getTime() - Date.parse(change.finishedAt)) / 60_000);
    return { state: "waiting" as const, detail: minutes > 30 ? `The plugin has not reported for ${minutes} minutes; WP-Cron runs on site traffic.` : "Waiting for the plugin's next report (usually within 5 minutes)." };
  }
  const running = report.site.phpVersion;
  if (running === change.to.label || running.startsWith(`${change.to.label}.`)) return { state: "confirmed" as const, detail: `WordPress reports PHP ${running}.` };
  return { state: "mismatch" as const, detail: `cPanel is set to PHP ${change.to.label}, but WordPress still reports PHP ${running}. The host may choose PHP elsewhere (CloudLinux "Select PHP Version", or an AddHandler line in .htaccess); change it there too.` };
}
