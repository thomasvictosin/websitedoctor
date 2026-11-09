import type { Prisma } from "@prisma/client";
import { db } from "./db.ts";

/**
 * Browser checks need a real browser, so they run on a GitHub Actions runner
 * (scripts/browser-checks.mjs) rather than in the app. After a fix that only a
 * browser can confirm (accessibility names and labels), the app records a
 * re-check request here; the runner wakes every 30 minutes, scans only the
 * sites with a pending request, and storing the result marks it answered. The
 * answered request is kept so the dashboard can tell "waiting for the re-check"
 * from "re-checked and still found" (what is left needs a manual fix).
 */
const KEY = "browser_recheck";

export type BrowserRecheck = { requestedAt: string; reason: string; answeredAt: string | null };

export async function requestBrowserRecheck(websiteId: string, reason: string, now = new Date()) {
  const website = await db.website.findUnique({ where: { id: websiteId }, select: { organizationId: true } });
  if (!website?.organizationId) return;
  const value: BrowserRecheck = { requestedAt: now.toISOString(), reason: reason.slice(0, 200), answeredAt: null };
  await db.systemSetting.upsert({
    where: { organizationId_scope_scopeId_key: { organizationId: website.organizationId, scope: "site", scopeId: websiteId, key: KEY } },
    create: { organizationId: website.organizationId, scope: "site", scopeId: websiteId, key: KEY, value: value as unknown as Prisma.InputJsonValue },
    update: { value: value as unknown as Prisma.InputJsonValue },
  });
}

function parse(value: unknown): BrowserRecheck | null {
  const record = value && typeof value === "object" ? value as Record<string, unknown> : {};
  return typeof record.requestedAt === "string" && Number.isFinite(Date.parse(record.requestedAt))
    ? {
      requestedAt: record.requestedAt,
      reason: typeof record.reason === "string" ? record.reason : "",
      answeredAt: typeof record.answeredAt === "string" && Number.isFinite(Date.parse(record.answeredAt)) ? record.answeredAt : null,
    }
    : null;
}

/** Latest re-check request per website id, answered or not. */
export async function browserRechecks(websiteIds?: string[]) {
  const rows = await db.systemSetting.findMany({
    where: { scope: "site", key: KEY, ...(websiteIds ? { scopeId: { in: websiteIds } } : {}) },
    select: { scopeId: true, value: true },
  });
  const rechecks = new Map<string, BrowserRecheck>();
  for (const row of rows) {
    const parsed = parse(row.value);
    if (parsed) rechecks.set(row.scopeId, parsed);
  }
  return rechecks;
}

/** A request the runner could not answer (the site timed out, say) is left to the daily full scan. */
const MAX_PENDING_MS = 24 * 60 * 60_000;

export function isPendingRecheck(recheck: BrowserRecheck | null | undefined, now = new Date()) {
  return Boolean(recheck && !recheck.answeredAt && now.getTime() - Date.parse(recheck.requestedAt) < MAX_PENDING_MS);
}

/** Sites waiting for a re-check. */
export async function pendingBrowserRechecks(websiteIds?: string[], now = new Date()) {
  const rechecks = await browserRechecks(websiteIds);
  for (const [websiteId, recheck] of rechecks) if (!isPendingRecheck(recheck, now)) rechecks.delete(websiteId);
  return rechecks;
}

/** A scan that started after the request answers it; a request made during the scan stays pending. */
export async function answerBrowserRecheck(websiteId: string, scanStartedAt: Date, now = new Date()) {
  const rows = await db.systemSetting.findMany({ where: { scope: "site", scopeId: websiteId, key: KEY }, select: { id: true, value: true } });
  for (const row of rows) {
    const parsed = parse(row.value);
    if (!parsed) { await db.systemSetting.delete({ where: { id: row.id } }); continue; }
    if (parsed.answeredAt || Date.parse(parsed.requestedAt) > scanStartedAt.getTime()) continue;
    await db.systemSetting.update({ where: { id: row.id }, data: { value: { ...parsed, answeredAt: now.toISOString() } as unknown as Prisma.InputJsonValue } });
  }
}
