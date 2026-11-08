import { connect, type PeerCertificate } from "node:tls";
import type { Prisma } from "@prisma/client";
import { db } from "./db.ts";
import { sendEmail } from "./email.ts";
import { getIntegrations } from "./integrations.ts";
import { resolvePublicAddresses } from "./monitor.ts";

/**
 * Renewal dates for each website: the SSL/TLS certificate (read from the
 * live HTTPS handshake), the domain registration (from the registry's public
 * RDAP service) and the hosting plan (entered by the owner; no host
 * publishes it). Expiring and expired items become issues, and reminders go
 * out 30 days before, 10 days before, and on the day something expires.
 */

export const RENEWAL_KINDS = ["ssl", "domain", "hosting"] as const;
export type RenewalKind = typeof RENEWAL_KINDS[number];
const DAY = 24 * 60 * 60_000;
const STAGES = [{ id: "expired", days: 0 }, { id: "10", days: 10 }, { id: "30", days: 30 }] as const;
const STAGE_RANK: Record<string, number> = { "30": 1, "10": 2, expired: 3 };
const LABEL: Record<RenewalKind, string> = { ssl: "SSL certificate", domain: "Domain name", hosting: "Hosting" };

export type SslResult = { available: boolean; expiresAt: Date | null; validFrom: Date | null; issuer: string | null; trusted: boolean; coversHost: boolean; error: string | null };

/** Read the certificate the site presents (any certificate, so an expired or self-signed one is still reported). */
export async function checkSsl(hostname: string, timeoutMs = 10_000): Promise<SslResult> {
  let address: string;
  try {
    [{ address }] = await resolvePublicAddresses(hostname);
  } catch (error) {
    return { available: false, expiresAt: null, validFrom: null, issuer: null, trusted: false, coversHost: false, error: error instanceof Error ? error.message : "DNS lookup failed." };
  }
  return new Promise((resolve) => {
    const socket = connect({ host: address, port: 443, servername: hostname, rejectUnauthorized: false, timeout: timeoutMs });
    const finish = (result: SslResult) => { socket.destroy(); resolve(result); };
    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate() as PeerCertificate;
      if (!cert || !cert.valid_to) return finish({ available: false, expiresAt: null, validFrom: null, issuer: null, trusted: false, coversHost: false, error: "The server answered on port 443 without a certificate." });
      const authError = socket.authorizationError ? String(socket.authorizationError) : null;
      finish({
        available: true,
        expiresAt: new Date(cert.valid_to),
        validFrom: cert.valid_from ? new Date(cert.valid_from) : null,
        issuer: String(cert.issuer?.O ?? cert.issuer?.CN ?? "") || null,
        trusted: socket.authorized,
        coversHost: !/ALTNAME|HOSTNAME/i.test(authError ?? ""),
        error: authError,
      });
    });
    socket.once("timeout", () => finish({ available: false, expiresAt: null, validFrom: null, issuer: null, trusted: false, coversHost: false, error: "No answer on port 443 (HTTPS) within 10 seconds." }));
    socket.once("error", (error: NodeJS.ErrnoException) => finish({ available: false, expiresAt: null, validFrom: null, issuer: null, trusted: false, coversHost: false, error: error.code === "ECONNREFUSED" ? "The server refuses HTTPS connections (port 443 closed)." : `HTTPS handshake failed: ${error.message}` }));
  });
}

export type DomainResult = { domain: string | null; expiresAt: Date | null; registrar: string | null; error: string | null };
let bootstrapCache: { at: number; services: Array<[string[], string[]]> } | null = null;

async function rdapBaseFor(tld: string, fetcher: typeof fetch) {
  if (!bootstrapCache || Date.now() - bootstrapCache.at > DAY) {
    const response = await fetcher("https://data.iana.org/rdap/dns.json", { signal: AbortSignal.timeout(10_000) });
    const body = await response.json() as { services?: Array<[string[], string[]]> };
    bootstrapCache = { at: Date.now(), services: body.services ?? [] };
  }
  const service = bootstrapCache.services.find(([tlds]) => tlds.includes(tld));
  return service?.[1].find((url) => url.startsWith("https://")) ?? service?.[1][0] ?? null;
}

/** Domain expiry from RDAP; tries the shortest registrable name first (example.co.uk before www.example.co.uk). */
export async function checkDomain(hostname: string, fetcher: typeof fetch = fetch): Promise<DomainResult> {
  const labels = hostname.toLowerCase().replace(/\.$/, "").split(".");
  if (labels.length < 2) return { domain: null, expiresAt: null, registrar: null, error: "Not a registered domain name." };
  const tld = labels.at(-1)!;
  let base: string | null;
  try {
    base = await rdapBaseFor(tld, fetcher);
  } catch {
    return { domain: null, expiresAt: null, registrar: null, error: "The registry directory (IANA RDAP) could not be reached." };
  }
  if (!base) return { domain: null, expiresAt: null, registrar: null, error: `The .${tld} registry does not publish expiry dates (no RDAP service). Enter the date manually.` };
  for (let take = 2; take <= Math.min(labels.length, 4); take += 1) {
    const domain = labels.slice(-take).join(".");
    try {
      const response = await fetcher(`${base.replace(/\/?$/, "/")}domain/${encodeURIComponent(domain)}`, { headers: { accept: "application/rdap+json" }, signal: AbortSignal.timeout(10_000), redirect: "follow" });
      if (response.status === 404) continue;
      if (!response.ok) return { domain, expiresAt: null, registrar: null, error: `The registry answered HTTP ${response.status}.` };
      const body = await response.json() as { events?: Array<{ eventAction?: string; eventDate?: string }>; entities?: Array<{ roles?: string[]; vcardArray?: [string, Array<[string, unknown, string, unknown]>] }> };
      const expiration = body.events?.find((event) => event.eventAction === "expiration")?.eventDate;
      const registrarEntity = body.entities?.find((entity) => entity.roles?.includes("registrar"));
      const registrar = registrarEntity?.vcardArray?.[1]?.find((entry) => entry[0] === "fn")?.[3];
      return { domain, expiresAt: expiration ? new Date(expiration) : null, registrar: typeof registrar === "string" ? registrar.slice(0, 120) : null, error: expiration ? null : "The registry does not publish this domain's expiry date. Enter it manually." };
    } catch {
      return { domain, expiresAt: null, registrar: null, error: "The registry could not be reached; it is retried tomorrow." };
    }
  }
  return { domain: null, expiresAt: null, registrar: null, error: "The registry has no record of this domain." };
}

export function renewalStatus(expiresAt: Date | null, now = Date.now()) {
  if (!expiresAt) return { status: "unknown" as const, daysLeft: null };
  const daysLeft = Math.floor((expiresAt.getTime() - now) / DAY);
  if (expiresAt.getTime() <= now) return { status: "expired" as const, daysLeft };
  if (daysLeft <= 30) return { status: "expiring" as const, daysLeft };
  return { status: "ok" as const, daysLeft };
}

/** The reminder stage reached for an expiry date (null before 30 days out). */
export function reminderStage(expiresAt: Date | null, now = Date.now()) {
  if (!expiresAt) return null;
  const days = (expiresAt.getTime() - now) / DAY;
  return STAGES.find((stage) => stage.id === "expired" ? days <= 0 : days <= stage.days)?.id ?? null;
}

/** Whether a reminder is due: a new stage for this expiry date, or a new expiry date that already reached a stage. */
export function reminderDue(row: { remindedStage: string | null; remindedFor: Date | null }, expiresAt: Date | null, now = Date.now()) {
  const stage = reminderStage(expiresAt, now);
  if (!stage || !expiresAt) return null;
  const sameDate = row.remindedFor && Math.abs(row.remindedFor.getTime() - expiresAt.getTime()) < DAY;
  if (sameDate && (STAGE_RANK[row.remindedStage ?? ""] ?? 0) >= STAGE_RANK[stage]) return null;
  return stage;
}

type Row = { kind: string; status: string; expiresAt: Date | null; provider: string | null; error: string | null; remindedStage: string | null; remindedFor: Date | null; details: unknown };

function issueFor(kind: RenewalKind, row: Row) {
  const label = LABEL[kind];
  const { daysLeft } = renewalStatus(row.expiresAt);
  const when = row.expiresAt ? row.expiresAt.toISOString().slice(0, 10) : "";
  if (kind === "ssl" && row.status === "missing") return { severity: "high", title: "SSL certificate not available", description: `${row.error ?? "The site does not serve HTTPS."} Visitors see "Not secure", browsers block forms, and search ranking suffers. Ask your host to issue a free Let's Encrypt certificate, or turn on Cloudflare's proxy.` };
  if (kind === "ssl" && row.status === "invalid") return { severity: "high", title: "SSL certificate is not trusted", description: `Browsers reject the certificate: ${row.error ?? "untrusted"}. Reissue it for this domain from your hosting panel.` };
  if (row.status === "expired") return { severity: "critical", title: `${label} expired`, description: `The ${label.toLowerCase()} expired on ${when}.${kind === "ssl" ? " Visitors now see a security warning." : kind === "domain" ? " The site can go offline and the domain can be lost after the grace period." : " The host can suspend the site at any time."} Renew it now${row.provider ? ` with ${row.provider}` : ""}.` };
  if (row.status === "expiring" && daysLeft !== null) return { severity: daysLeft <= 10 ? "high" : "medium", title: `${label} expires in ${daysLeft} day${daysLeft === 1 ? "" : "s"}`, description: `The ${label.toLowerCase()} expires on ${when}.${kind === "ssl" ? " Certificates from Let's Encrypt and most hosts renew automatically; if this date does not move within a week, renew it from your hosting panel." : ` Renew it${row.provider ? ` with ${row.provider}` : ""} or make sure auto-renew is on.`}` };
  return null;
}

async function syncIssue(websiteId: string, kind: RenewalKind, row: Row) {
  const fingerprint = `renewal:${kind}`;
  const issue = issueFor(kind, row);
  const now = new Date();
  if (issue) {
    await db.issue.upsert({
      where: { websiteId_fingerprint: { websiteId, fingerprint } },
      create: { websiteId, fingerprint, source: "renewal_monitor", ...issue, evidence: { kind, expiresAt: row.expiresAt?.toISOString() ?? null, provider: row.provider, details: row.details ?? null } as Prisma.InputJsonValue },
      update: { ...issue, status: "open", resolvedAt: null, lastSeenAt: now, evidence: { kind, expiresAt: row.expiresAt?.toISOString() ?? null, provider: row.provider, details: row.details ?? null } as Prisma.InputJsonValue },
    });
  } else {
    await db.issue.updateMany({ where: { websiteId, fingerprint, status: { in: ["open", "acknowledged"] } }, data: { status: "resolved", resolvedAt: now, lastSeenAt: now } });
  }
}

async function remind(website: { id: string; name: string; url: string; organizationId: string }, kind: RenewalKind, row: Row & { id: string }) {
  const stage = reminderDue(row, row.expiresAt);
  if (!stage || !row.expiresAt) return null;
  const when = row.expiresAt.toISOString().slice(0, 10);
  const subject = stage === "expired" ? `${website.name}: ${LABEL[kind]} has expired` : `${website.name}: ${LABEL[kind]} expires in ${stage} days (${when})`;
  const text = `${LABEL[kind]} for ${website.url}\nExpiry date: ${when}${row.provider ? `\nProvider: ${row.provider}` : ""}\n\n${issueFor(kind, row)?.description ?? ""}\n\nYou get reminders 30 days before, 10 days before, and on the day it expires.`;
  const { reminderEmails } = await getIntegrations(website.organizationId);
  const owners = reminderEmails.length ? reminderEmails : (await db.organizationMember.findMany({ where: { organizationId: website.organizationId, role: { in: ["owner", "admin"] }, user: { disabledAt: null } }, select: { user: { select: { email: true } } } })).map((member) => member.user.email);
  const emailed = await sendEmail(website.organizationId, { to: owners, subject, text });
  // Without an email provider, the site's own plugin emails its administrator (category "renewal:").
  await db.notification.create({ data: { organizationId: website.organizationId, category: `${emailed.sent ? "renewal_sent" : "renewal"}:${website.id}`, title: subject.slice(0, 200), body: text.slice(0, 4000) } });
  await db.siteRenewal.update({ where: { id: row.id }, data: { remindedStage: stage, remindedFor: row.expiresAt } });
  return { stage, emailed: emailed.sent };
}

/** Check SSL and domain, apply manual dates, update issues and send due reminders. */
export async function refreshRenewals(websiteId: string, options: { fetcher?: typeof fetch; ssl?: typeof checkSsl; domain?: typeof checkDomain } = {}) {
  const website = await db.website.findUnique({ where: { id: websiteId }, select: { id: true, name: true, url: true, organizationId: true } });
  if (!website) return null;
  const hostname = new URL(website.url).hostname;
  const [ssl, domain, existing] = await Promise.all([
    (options.ssl ?? checkSsl)(hostname),
    (options.domain ?? checkDomain)(hostname, options.fetcher),
    db.siteRenewal.findMany({ where: { websiteId } }),
  ]);
  const byKind = new Map(existing.map((row) => [row.kind, row]));
  const now = new Date();
  const results: Record<string, unknown> = {};
  for (const kind of RENEWAL_KINDS) {
    const current = byKind.get(kind);
    let detected: Date | null = null;
    let provider: string | null = null;
    let error: string | null = null;
    let status: string;
    let details: Record<string, unknown> = {};
    if (kind === "ssl") {
      detected = ssl.expiresAt;
      provider = ssl.issuer;
      error = ssl.error;
      details = { trusted: ssl.trusted, validFrom: ssl.validFrom?.toISOString() ?? null, coversHost: ssl.coversHost };
      const expiry = renewalStatus(detected);
      status = !ssl.available ? "missing" : expiry.status === "expired" ? "expired" : !ssl.trusted ? "invalid" : expiry.status;
    } else if (kind === "domain") {
      detected = domain.expiresAt;
      provider = domain.registrar;
      error = domain.error;
      details = { domain: domain.domain };
      status = "unknown";
    } else {
      status = "unknown";
    }
    const expiresAt = (kind !== "ssl" ? current?.manualExpiresAt : null) ?? detected;
    if (kind !== "ssl") status = expiresAt ? renewalStatus(expiresAt).status : kind === "hosting" ? "not_set" : "unknown";
    const effectiveProvider = current?.manualProvider ?? provider;
    const data = { status, expiresAt, detectedExpiry: detected, provider: effectiveProvider, error: kind === "hosting" ? null : error, details: details as Prisma.InputJsonValue, checkedAt: now };
    const row = current
      ? await db.siteRenewal.update({ where: { id: current.id }, data })
      : await db.siteRenewal.create({ data: { websiteId, kind, ...data } });
    await syncIssue(websiteId, kind, row);
    const reminder = await remind(website, kind, row);
    results[kind] = { status, expiresAt: expiresAt?.toISOString() ?? null, reminder };
  }
  return results;
}

/** Owner-entered dates (hosting always; domain when the registry does not publish one). */
export async function saveManualRenewal(websiteId: string, kind: "domain" | "hosting", input: { expiresAt: Date | null; provider: string | null; notes: string | null }) {
  const current = await db.siteRenewal.findUnique({ where: { websiteId_kind: { websiteId, kind } } });
  const expiresAt = input.expiresAt ?? current?.detectedExpiry ?? null;
  const status = expiresAt ? renewalStatus(expiresAt).status : kind === "hosting" ? "not_set" : "unknown";
  const data = { manualExpiresAt: input.expiresAt, manualProvider: input.provider, notes: input.notes, expiresAt, status, provider: input.provider ?? current?.provider ?? null };
  const row = current
    ? await db.siteRenewal.update({ where: { id: current.id }, data })
    : await db.siteRenewal.create({ data: { websiteId, kind, ...data } });
  await syncIssue(websiteId, kind, row);
  const website = await db.website.findUnique({ where: { id: websiteId }, select: { id: true, name: true, url: true, organizationId: true } });
  if (website) await remind(website, kind, row);
  return row;
}

export function describeRenewal(row: { kind: string; status: string; expiresAt: Date | null; detectedExpiry: Date | null; manualExpiresAt: Date | null; provider: string | null; notes: string | null; error: string | null; checkedAt: Date | null; details: unknown; remindedStage: string | null }) {
  return {
    kind: row.kind,
    label: LABEL[row.kind as RenewalKind] ?? row.kind,
    status: row.status,
    expiresAt: row.expiresAt?.toISOString() ?? null,
    daysLeft: renewalStatus(row.expiresAt).daysLeft,
    source: row.manualExpiresAt ? "manual" : row.detectedExpiry ? "automatic" : null,
    detectedExpiry: row.detectedExpiry?.toISOString() ?? null,
    provider: row.provider,
    notes: row.notes,
    error: row.error,
    checkedAt: row.checkedAt?.toISOString() ?? null,
    details: row.details ?? null,
    lastReminder: row.remindedStage,
  };
}

/** Refresh sites not checked in the last day, within a time budget (called from the monitor cron). */
export async function refreshDueRenewals(budgetMs = 20_000) {
  const started = Date.now();
  const since = new Date(Date.now() - DAY);
  const sites = await db.website.findMany({
    where: { OR: [{ renewals: { none: {} } }, { renewals: { some: { kind: "ssl", OR: [{ checkedAt: null }, { checkedAt: { lt: since } }] } } }] },
    select: { id: true }, take: 10,
  });
  let refreshed = 0;
  for (const site of sites) {
    if (Date.now() - started > budgetMs * 0.7) break;
    try { await refreshRenewals(site.id); refreshed += 1; } catch (error) { console.error("Renewal check failed:", error instanceof Error ? error.message : error); }
  }
  // Manual dates move closer every day without a new check; send their reminders too.
  for (const row of await db.siteRenewal.findMany({ where: { expiresAt: { lte: new Date(Date.now() + 31 * DAY) } }, include: { website: { select: { id: true, name: true, url: true, organizationId: true } } }, take: 200 })) {
    if (Date.now() - started > budgetMs) break;
    const status = row.kind === "ssl" ? row.status : renewalStatus(row.expiresAt).status;
    if (row.kind !== "ssl" && status !== row.status) await db.siteRenewal.update({ where: { id: row.id }, data: { status } });
    const updated = { ...row, status };
    await syncIssue(row.websiteId, row.kind as RenewalKind, updated);
    await remind(row.website, row.kind as RenewalKind, updated);
  }
  return { refreshed };
}

