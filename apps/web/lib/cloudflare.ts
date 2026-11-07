import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";
import type { Prisma } from "@prisma/client";
import { db } from "./db.ts";

/**
 * Edge protection through the owner's Cloudflare account (free plan works).
 * Cloudflare sits in front of the server, so these rules drop attack traffic
 * before it reaches WordPress or any file dropped on the server.
 *
 * The app adds only rules whose description starts with "AWD:" and leaves
 * every other rule in the zone untouched. Rules that judge crawler identity
 * apply only to login/admin/API paths, so the app's outside cloaking check
 * (which impersonates Googlebot from a data center) keeps working. Bot Fight
 * Mode is optional because it challenges that check too and cannot be
 * bypassed on the free plan.
 *
 * The API token is stored encrypted (AES-256-GCM, key derived from
 * SESSION_SECRET) and never returned by the API.
 */

const API = "https://api.cloudflare.com/client/v4";
const SETTING_KEY = "cloudflare";
const RULE_PREFIX = "AWD:";
type Fetcher = typeof fetch;
type Json = Record<string, unknown>;

export class CloudflareError extends Error {
  readonly status: number;
  constructor(message: string, status: number = 400) {
    super(message);
    this.status = status;
  }
}

function key(): Buffer {
  const secret = process.env.SESSION_SECRET;
  if (!secret || Buffer.byteLength(secret) < 32) throw new CloudflareError("SESSION_SECRET must be at least 32 bytes before a Cloudflare token can be stored.", 503);
  return createHmac("sha256", secret).update("ai-website-doctor:cloudflare-api-token:v1").digest();
}

export function encryptToken(token: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(), iv);
  const data = Buffer.concat([cipher.update(token, "utf8"), cipher.final()]);
  return `${iv.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}.${data.toString("base64url")}`;
}

export function decryptToken(payload: string) {
  const [iv, tag, data, extra] = payload.split(".");
  if (!iv || !tag || !data || extra !== undefined) throw new CloudflareError("The stored Cloudflare token is malformed; connect again.", 409);
  const decipher = createDecipheriv("aes-256-gcm", key(), Buffer.from(iv, "base64url"));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(data, "base64url")), decipher.final()]).toString("utf8");
}

async function cf(token: string, method: string, path: string, body?: unknown, fetcher: Fetcher = fetch): Promise<{ status: number; result: unknown }> {
  const response = await fetcher(`${API}${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });
  const payload = await response.json().catch(() => ({})) as { success?: boolean; result?: unknown; errors?: Array<{ message?: string; code?: number }> };
  if (!response.ok || payload.success === false) {
    const message = payload.errors?.map((error) => error.message).filter(Boolean).join("; ") || `Cloudflare returned HTTP ${response.status}.`;
    throw new CloudflareError(response.status === 403 ? `The Cloudflare token is missing a permission (${message}). See the required permissions.` : message, response.status === 404 ? 404 : 400);
  }
  return { status: response.status, result: payload.result };
}

export const REQUIRED_PERMISSIONS = ["Zone → Zone → Read", "Zone → Zone Settings → Edit", "Zone → Zone WAF → Edit", "Zone → Bot Management → Edit (only for the optional Bot Fight Mode)"];

/** Rule expressions. Pure, so they can be unit tested. */
export function awdCustomRules(options: { blockXmlrpc: boolean }) {
  const path = "http.request.uri.path";
  const lowerPath = `lower(${path})`;
  const sensitive = ["/wp-config.php", "/wp-config-sample.php", "/readme.html", "/license.txt", "/.env", "/.git/config", "/.htaccess", "/debug.log", "/wp-content/debug.log", ...(options.blockXmlrpc ? ["/xmlrpc.php"] : [])];
  const executableInUploads = `(starts_with(${lowerPath}, "/wp-content/uploads/") and (ends_with(${lowerPath}, ".php") or ends_with(${lowerPath}, ".phtml") or ends_with(${lowerPath}, ".phar") or ends_with(${lowerPath}, ".php5") or ends_with(${lowerPath}, ".php7")))`;
  const sensitivePaths = `(${lowerPath} in {${sensitive.map((item) => `"${item}"`).join(" ")}})`;
  const protectedArea = `(${path} in {"/wp-login.php" "/xmlrpc.php"} or starts_with(${path}, "/wp-admin") or starts_with(${path}, "/wp-json"))`;
  const claimsCrawler = `(lower(http.user_agent) contains "googlebot" or lower(http.user_agent) contains "bingbot" or lower(http.user_agent) contains "yandex" or lower(http.user_agent) contains "baiduspider")`;
  const attackTools = `(lower(http.user_agent) contains "sqlmap" or lower(http.user_agent) contains "nikto" or lower(http.user_agent) contains "wpscan" or lower(http.user_agent) contains "masscan" or lower(http.user_agent) contains "zgrab" or lower(http.user_agent) contains "nuclei")`;
  return [
    {
      description: `${RULE_PREFIX} block PHP in uploads, sensitive files, fake crawlers on login/admin and attack tools`,
      action: "block",
      enabled: true,
      expression: `${executableInUploads} or ${sensitivePaths} or (${claimsCrawler} and not cf.client.bot and ${protectedArea}) or ${attackTools}`,
    },
    {
      description: `${RULE_PREFIX} challenge login page visitors that are not verified bots`,
      action: "managed_challenge",
      enabled: true,
      expression: `(${path} eq "/wp-login.php" and not cf.client.bot)`,
    },
  ];
}

export function awdRateLimitRule() {
  return {
    description: `${RULE_PREFIX} limit login attempts`,
    action: "block",
    enabled: true,
    expression: `(http.request.uri.path eq "/wp-login.php" and http.request.method eq "POST")`,
    ratelimit: { characteristics: ["cf.colo.id", "ip.src"], period: 10, requests_per_period: 5, mitigation_timeout: 10 },
  };
}

/** Merge our rules into a phase entrypoint, keeping every rule we did not create. */
export function mergeRules(existing: unknown[], ours: Json[]) {
  const kept = existing.filter((rule) => !String((rule as Json)?.description ?? "").startsWith(RULE_PREFIX)).map((rule) => {
    const { id: _id, version: _version, last_updated: _updated, ref: _ref, ...rest } = rule as Json;
    return rest;
  });
  return [...kept, ...ours];
}

async function readEntrypoint(token: string, zoneId: string, phase: string, fetcher: Fetcher) {
  try {
    const { result } = await cf(token, "GET", `/zones/${zoneId}/rulesets/phases/${phase}/entrypoint`, undefined, fetcher);
    return Array.isArray((result as Json)?.rules) ? (result as Json).rules as unknown[] : [];
  } catch (error) {
    if (error instanceof CloudflareError && error.status === 404) return [];
    throw error;
  }
}

async function writeEntrypoint(token: string, zoneId: string, phase: string, rules: unknown[], fetcher: Fetcher) {
  await cf(token, "PUT", `/zones/${zoneId}/rulesets/phases/${phase}/entrypoint`, { rules }, fetcher);
}

type StoredConnection = { encryptedToken: string; zoneId: string; zoneName: string; connectedAt: string; connectedBy: string | null; applied?: Json };

async function readConnection(websiteId: string): Promise<StoredConnection | null> {
  const setting = await db.systemSetting.findFirst({ where: { scope: "site", scopeId: websiteId, key: SETTING_KEY }, select: { value: true } });
  const value = setting?.value as StoredConnection | undefined;
  return value?.encryptedToken && value.zoneId ? value : null;
}

async function writeConnection(websiteId: string, organizationId: string, value: StoredConnection | null) {
  if (!value) {
    await db.systemSetting.deleteMany({ where: { organizationId, scope: "site", scopeId: websiteId, key: SETTING_KEY } });
    return;
  }
  await db.systemSetting.upsert({
    where: { organizationId_scope_scopeId_key: { organizationId, scope: "site", scopeId: websiteId, key: SETTING_KEY } },
    create: { organizationId, scope: "site", scopeId: websiteId, key: SETTING_KEY, value: value as unknown as Prisma.InputJsonValue, isSecret: true },
    update: { value: value as unknown as Prisma.InputJsonValue, isSecret: true },
  });
}

/** Candidate zone names for a host: www.shop.example.co.uk -> shop.example.co.uk, example.co.uk, co.uk */
export function zoneCandidates(hostname: string) {
  const parts = hostname.toLowerCase().replace(/\.$/, "").split(".");
  const names: string[] = [];
  for (let index = 0; index < parts.length - 1; index += 1) names.push(parts.slice(index).join("."));
  return names;
}

export async function connectCloudflare(input: { websiteId: string; organizationId: string; siteUrl: string; token: string; userId: string | null }, fetcher: Fetcher = fetch) {
  const token = input.token.trim();
  if (!/^[A-Za-z0-9_-]{30,200}$/.test(token)) throw new CloudflareError("That does not look like a Cloudflare API token.");
  const verify = await cf(token, "GET", "/user/tokens/verify", undefined, fetcher);
  if ((verify.result as Json)?.status !== "active") throw new CloudflareError("The Cloudflare token is not active.");
  const hostname = new URL(input.siteUrl).hostname;
  let zone: Json | null = null;
  for (const name of zoneCandidates(hostname)) {
    const { result } = await cf(token, "GET", `/zones?name=${encodeURIComponent(name)}`, undefined, fetcher);
    if (Array.isArray(result) && result[0]) { zone = result[0] as Json; break; }
  }
  if (!zone) throw new CloudflareError(`No Cloudflare zone for ${hostname} is visible to this token. Add the site to Cloudflare first, or give the token access to that zone.`, 404);
  await writeConnection(input.websiteId, input.organizationId, { encryptedToken: encryptToken(token), zoneId: String(zone.id), zoneName: String(zone.name), connectedAt: new Date().toISOString(), connectedBy: input.userId });
  await db.auditLog.create({ data: { action: "cloudflare_connected", actorType: "admin", actorId: input.userId ?? "unknown", actorUserId: input.userId, organizationId: input.organizationId, resourceType: "website", resourceId: input.websiteId, details: { zoneName: String(zone.name) } } });
  return { zoneName: String(zone.name), status: String(zone.status) };
}

export async function disconnectCloudflare(websiteId: string, organizationId: string, userId: string | null) {
  await writeConnection(websiteId, organizationId, null);
  await db.auditLog.create({ data: { action: "cloudflare_disconnected", actorType: "admin", actorId: userId ?? "unknown", actorUserId: userId, organizationId, resourceType: "website", resourceId: websiteId } });
}

/** Whether the site's public traffic actually passes through Cloudflare. */
async function proxiedThroughCloudflare(siteUrl: string, fetcher: Fetcher) {
  try {
    const response = await fetcher(siteUrl, { method: "HEAD", redirect: "manual", signal: AbortSignal.timeout(10_000) });
    return Boolean(response.headers.get("cf-ray")) || /cloudflare/i.test(response.headers.get("server") ?? "");
  } catch { return false; }
}

export async function cloudflareStatus(websiteId: string, siteUrl: string, fetcher: Fetcher = fetch) {
  const connection = await readConnection(websiteId);
  if (!connection) return { connected: false as const, requiredPermissions: REQUIRED_PERMISSIONS };
  const token = decryptToken(connection.encryptedToken);
  const [zone, security, customRules, rateRules, botManagement, proxied] = await Promise.all([
    cf(token, "GET", `/zones/${connection.zoneId}`, undefined, fetcher).then((value) => value.result as Json).catch(() => null),
    cf(token, "GET", `/zones/${connection.zoneId}/settings/security_level`, undefined, fetcher).then((value) => (value.result as Json)?.value).catch(() => null),
    readEntrypoint(token, connection.zoneId, "http_request_firewall_custom", fetcher).catch(() => null),
    readEntrypoint(token, connection.zoneId, "http_ratelimit", fetcher).catch(() => null),
    cf(token, "GET", `/zones/${connection.zoneId}/bot_management`, undefined, fetcher).then((value) => (value.result as Json)?.fight_mode).catch(() => null),
    proxiedThroughCloudflare(siteUrl, fetcher),
  ]);
  const ours = (rules: unknown[] | null) => (rules ?? []).filter((rule) => String((rule as Json)?.description ?? "").startsWith(RULE_PREFIX)).length;
  return {
    connected: true as const,
    zoneName: connection.zoneName,
    zoneStatus: zone ? String(zone.status) : "unknown",
    plan: zone ? String(record(zone.plan).name ?? "") : "",
    proxied,
    securityLevel: security,
    awdFirewallRules: ours(customRules),
    otherFirewallRules: (customRules ?? []).length - ours(customRules),
    awdRateLimitRules: ours(rateRules),
    botFightMode: botManagement,
    applied: connection.applied ?? null,
    requiredPermissions: REQUIRED_PERMISSIONS,
  };
}

function record(value: unknown): Json { return value && typeof value === "object" && !Array.isArray(value) ? value as Json : {}; }

/** Apply (or remove) the app's edge protection, then verify it from outside. */
export async function applyCloudflareProtection(input: { websiteId: string; organizationId: string; siteUrl: string; botFightMode: boolean; blockXmlrpc: boolean; remove?: boolean; userId: string | null }, fetcher: Fetcher = fetch) {
  const connection = await readConnection(input.websiteId);
  if (!connection) throw new CloudflareError("Connect Cloudflare first.", 409);
  const token = decryptToken(connection.encryptedToken);
  const zoneId = connection.zoneId;
  const steps: Array<{ step: string; ok: boolean; detail: string }> = [];
  const run = async (step: string, action: () => Promise<unknown>) => {
    try { await action(); steps.push({ step, ok: true, detail: "done" }); } catch (error) { steps.push({ step, ok: false, detail: error instanceof Error ? error.message : "failed" }); }
  };
  if (!input.remove) {
    await run("Security level: medium", () => cf(token, "PATCH", `/zones/${zoneId}/settings/security_level`, { value: "medium" }, fetcher));
    await run("Always use HTTPS", () => cf(token, "PATCH", `/zones/${zoneId}/settings/always_use_https`, { value: "on" }, fetcher));
    await run("Minimum TLS 1.2", () => cf(token, "PATCH", `/zones/${zoneId}/settings/min_tls_version`, { value: "1.2" }, fetcher));
    await run("Browser integrity check", () => cf(token, "PATCH", `/zones/${zoneId}/settings/browser_check`, { value: "on" }, fetcher));
  }
  await run(input.remove ? "Remove firewall rules" : "Firewall rules", async () => {
    const existing = await readEntrypoint(token, zoneId, "http_request_firewall_custom", fetcher);
    await writeEntrypoint(token, zoneId, "http_request_firewall_custom", mergeRules(existing, input.remove ? [] : awdCustomRules({ blockXmlrpc: input.blockXmlrpc })), fetcher);
  });
  await run(input.remove ? "Remove login rate limit" : "Login rate limit", async () => {
    const existing = await readEntrypoint(token, zoneId, "http_ratelimit", fetcher);
    await writeEntrypoint(token, zoneId, "http_ratelimit", mergeRules(existing, input.remove ? [] : [awdRateLimitRule()]), fetcher);
  });
  if (input.botFightMode || input.remove) {
    await run(`Bot Fight Mode ${input.remove ? "off" : "on"}`, () => cf(token, "PUT", `/zones/${zoneId}/bot_management`, { fight_mode: !input.remove }, fetcher));
  }
  // Verify from outside: a request for PHP in uploads must be blocked by Cloudflare itself.
  let verified: boolean | null = null;
  let verification = "";
  if (!input.remove && steps.find((step) => step.step === "Firewall rules")?.ok) {
    try {
      const probe = await fetcher(new URL(`/wp-content/uploads/awd-edge-check-${Date.now()}.php`, input.siteUrl), { redirect: "manual", signal: AbortSignal.timeout(10_000) });
      const fromCloudflare = Boolean(probe.headers.get("cf-ray"));
      verified = probe.status === 403 && fromCloudflare;
      verification = !fromCloudflare
        ? "Traffic is not passing through Cloudflare yet: point the domain's nameservers to Cloudflare and make sure the DNS records are proxied (orange cloud)."
        : verified ? "Confirmed: Cloudflare blocks PHP requests under uploads before they reach the server." : `Cloudflare answered HTTP ${probe.status}; the rule may take a minute to propagate.`;
    } catch (error) {
      verification = `The verification request failed: ${error instanceof Error ? error.message : "unknown error"}`;
    }
  }
  const applied = input.remove ? null : { at: new Date().toISOString(), botFightMode: input.botFightMode, blockXmlrpc: input.blockXmlrpc, verified, verification };
  await writeConnection(input.websiteId, input.organizationId, { ...connection, applied: applied ?? undefined });
  await db.auditLog.create({ data: { action: input.remove ? "cloudflare_protection_removed" : "cloudflare_protection_applied", actorType: "admin", actorId: input.userId ?? "unknown", actorUserId: input.userId, organizationId: input.organizationId, resourceType: "website", resourceId: input.websiteId, details: { steps, verified } as Prisma.InputJsonValue } });
  return { steps, verified, verification };
}
