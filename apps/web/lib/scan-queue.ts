import { Prisma } from "@prisma/client";
import { db } from "@/lib/db";
import { runAndStoreCheck } from "@/lib/monitoring-service";

const MAX_ATTEMPTS = 3;
const LEASE_MS = 12 * 60_000;
const TENANT_ACTIVE_LIMIT = 2;
const TENANT_WINDOW_LIMIT = 6;
const TENANT_WINDOW_MS = 15 * 60_000;
const globalQueue = globalThis as typeof globalThis & { scanQueueRunning?: boolean; scanQueueTimer?: ReturnType<typeof setInterval> };

export async function enqueueScan(input: { websiteId: string; organizationId: string; initiatedBy: string; idempotencyKey?: string }) {
  const key = input.idempotencyKey ?? `manual-scan:${input.websiteId}:${crypto.randomUUID()}`;
  try {
    return await db.$transaction(async (tx) => {
      await tx.$queryRaw`WITH advisory_lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(hashtext(${input.organizationId}))) SELECT 1 FROM advisory_lock`;
      const activeCount = await tx.backgroundJob.count({ where: { organizationId: input.organizationId, jobType: "website_scan", status: { in: ["pending", "running"] } } });
      if (activeCount >= TENANT_ACTIVE_LIMIT) return { queued: false as const, reason: "scan_limit" };
      const recentCount = await tx.backgroundJob.count({ where: { organizationId: input.organizationId, jobType: "website_scan", createdAt: { gte: new Date(Date.now() - TENANT_WINDOW_MS) } } });
      if (recentCount >= TENANT_WINDOW_LIMIT) return { queued: false as const, reason: "scan_rate_limit" };
      const job = await tx.backgroundJob.create({ data: { organizationId: input.organizationId, websiteId: input.websiteId, jobType: "website_scan", status: "pending", payload: { initiatedBy: input.initiatedBy } as Prisma.InputJsonObject, idempotencyKey: key, maxAttempts: MAX_ATTEMPTS } });
      const session = await tx.scanSession.create({ data: { websiteId: input.websiteId, scanType: "availability_and_browser", initiatedBy: input.initiatedBy, status: "queued", jobId: job.id }, select: { id: true } });
      return { queued: true as const, jobId: job.id, scanSessionId: session.id };
    });
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "P2002") {
      const job = await db.backgroundJob.findUnique({ where: { idempotencyKey: key }, select: { id: true } });
      const session = job ? await db.scanSession.findFirst({ where: { jobId: job.id }, select: { id: true } }) : null;
      if (job && session) return { queued: true as const, jobId: job.id, scanSessionId: session.id };
    }
    throw error;
  }
}

async function recoverExpiredJobs(now: Date) {
  const expired = await db.backgroundJob.findMany({ where: { jobType: "website_scan", status: "running", lockExpiresAt: { lt: now } }, take: 50, select: { id: true, attempts: true, maxAttempts: true } });
  for (const job of expired) {
    const terminal = job.attempts >= job.maxAttempts;
    await db.$transaction([
      db.backgroundJob.updateMany({ where: { id: job.id, status: "running", lockExpiresAt: { lt: now } }, data: { status: terminal ? "failed" : "pending", runAt: now, lockedAt: null, lockExpiresAt: null, lastError: "Worker lease expired; the previous worker stopped before completing the scan." } }),
      db.scanSession.updateMany({ where: { jobId: job.id, status: "running" }, data: { status: terminal ? "failed" : "queued", completedAt: terminal ? now : null } }),
    ]);
  }
}

async function claimNext() {
  const now = new Date();
  await recoverExpiredJobs(now);
  const candidates = await db.backgroundJob.findMany({ where: { jobType: "website_scan", status: "pending", runAt: { lte: now }, attempts: { lt: MAX_ATTEMPTS } }, orderBy: { runAt: "asc" }, take: 30, include: { website: { select: { id: true, name: true, url: true, organizationId: true, monitoringEnabled: true } } } });
  for (const candidate of candidates) {
    if (!candidate.website) {
      await db.backgroundJob.updateMany({ where: { id: candidate.id, status: "pending" }, data: { status: "failed", completedAt: now, lastError: "The website for this scan no longer exists." } });
      continue;
    }
    const initiatedBy = (candidate.payload as { initiatedBy?: string }).initiatedBy ?? "manual";
    if (initiatedBy === "scheduler" && !candidate.website.monitoringEnabled) {
      await db.backgroundJob.updateMany({ where: { id: candidate.id, status: "pending" }, data: { status: "cancelled", completedAt: now, lastError: "Periodic monitoring was disabled before this scan started." } });
      await db.scanSession.updateMany({ where: { jobId: candidate.id, status: "queued" }, data: { status: "cancelled", completedAt: now } });
      continue;
    }
    const result = await db.$transaction(async (tx) => {
      await tx.$queryRaw`WITH advisory_lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(hashtext(${candidate.organizationId ?? "unowned"}))) SELECT 1 FROM advisory_lock`;
      const active = await tx.backgroundJob.count({ where: { organizationId: candidate.organizationId, status: "running", jobType: "website_scan", lockExpiresAt: { gt: now } } });
      if (active >= TENANT_ACTIVE_LIMIT) return null;
      const claimed = await tx.backgroundJob.updateMany({ where: { id: candidate.id, status: "pending", runAt: { lte: now } }, data: { status: "running", attempts: { increment: 1 }, lockedAt: now, lockExpiresAt: new Date(now.getTime() + LEASE_MS) } });
      if (!claimed.count) return null;
      const session = await tx.scanSession.findUnique({ where: { jobId: candidate.id }, select: { id: true } });
      if (!session) { await tx.backgroundJob.update({ where: { id: candidate.id }, data: { status: "failed", lastError: "Scan session is missing.", completedAt: now } }); return null; }
      await tx.scanSession.update({ where: { id: session.id }, data: { status: "running", startedAt: now, completedAt: null } });
      return { job: candidate, sessionId: session.id };
    });
    if (result) return result;
  }
  return null;
}

export async function processScanQueueOnce() {
  const claimed = await claimNext();
  if (!claimed) return false;
  if (!claimed.job.website) return false;
  const initiatedBy = (claimed.job.payload as { initiatedBy?: string }).initiatedBy ?? "manual";
  const heartbeat = setInterval(() => {
    const now = new Date();
    void db.backgroundJob.updateMany({ where: { id: claimed.job.id, status: "running" }, data: { lockedAt: now, lockExpiresAt: new Date(now.getTime() + LEASE_MS) } }).catch((error) => console.error(`Scan job ${claimed.job.id} lease renewal failed:`, error));
  }, 60_000);
  try {
    await runAndStoreCheck(claimed.job.website, initiatedBy, {}, claimed.sessionId);
    await db.backgroundJob.updateMany({ where: { id: claimed.job.id, status: "running" }, data: { status: "completed", completedAt: new Date(), lockedAt: null, lockExpiresAt: null, lastError: null } });
  } catch (error) {
    const now = new Date();
    const message = (error instanceof Error ? error.message : "Scan failed.").slice(0, 1000);
    const retry = claimed.job.attempts + 1 < claimed.job.maxAttempts;
    await db.$transaction([
      db.backgroundJob.updateMany({ where: { id: claimed.job.id, status: "running" }, data: { status: retry ? "pending" : "failed", runAt: retry ? new Date(now.getTime() + 30_000 * 2 ** claimed.job.attempts) : now, completedAt: retry ? null : now, lockedAt: null, lockExpiresAt: null, lastError: message } }),
      db.scanSession.updateMany({ where: { id: claimed.sessionId, status: "failed" }, data: { status: retry ? "queued" : "failed", completedAt: retry ? null : now } }),
    ]);
    console.error(`Scan job ${claimed.job.id} attempt failed:`, message);
  } finally {
    clearInterval(heartbeat);
  }
  return true;
}

async function drainQueue() {
  const workerCount = 2;
  if (globalQueue.scanQueueRunning) return;
  globalQueue.scanQueueRunning = true;
  try { await Promise.all(Array.from({ length: workerCount }, () => processScanQueueOnce())); }
  finally { globalQueue.scanQueueRunning = false; }
}

export function startScanQueue() {
  if (globalQueue.scanQueueTimer) return;
  globalQueue.scanQueueTimer = setInterval(() => void drainQueue(), 2_000);
  globalQueue.scanQueueTimer.unref();
  void drainQueue();
}
