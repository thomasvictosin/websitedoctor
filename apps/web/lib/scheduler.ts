import { db } from "@/lib/db";
import { enqueueScan, startScanQueue } from "@/lib/scan-queue";

const globalForScheduler = globalThis as typeof globalThis & {
  websiteDoctorScheduler?: ReturnType<typeof setInterval>;
  websiteDoctorSchedulerRunning?: boolean;
};

/** Queue a scan for every website whose monitoring slot is due. Returns how many were queued. */
export async function enqueueDueWebsites(): Promise<number> {
  const now = new Date();
  let queuedCount = 0;
  const due = await db.website.findMany({
    where: {
      monitoringEnabled: true,
      OR: [{ nextCheckAt: null }, { nextCheckAt: { lte: now } }],
    },
    orderBy: { nextCheckAt: "asc" },
    take: 10,
  });
  for (const website of due) {
    const dueSlot = website.nextCheckAt?.toISOString() ?? "initial";
    const queued = await enqueueScan({ websiteId: website.id, organizationId: website.organizationId, initiatedBy: "scheduler", idempotencyKey: `scheduled:${website.id}:${dueSlot}` });
    if (!queued.queued) continue;
    queuedCount += 1;
    const nextCheckAt = new Date(Date.now() + website.intervalMinutes * 60_000);
    await db.website.updateMany({ where: { id: website.id, monitoringEnabled: true, nextCheckAt: website.nextCheckAt }, data: { nextCheckAt } });
  }
  return queuedCount;
}

async function pollDueWebsites() {
  if (globalForScheduler.websiteDoctorSchedulerRunning) return;
  globalForScheduler.websiteDoctorSchedulerRunning = true;
  try {
    await enqueueDueWebsites();
    startScanQueue();
  } catch (error) {
    console.error("Website monitoring scheduler failed:", error);
  } finally {
    globalForScheduler.websiteDoctorSchedulerRunning = false;
  }
}

export function startMonitoringScheduler() {
  if (globalForScheduler.websiteDoctorScheduler) return;
  const timer = setInterval(() => void pollDueWebsites(), 60_000);
  timer.unref();
  globalForScheduler.websiteDoctorScheduler = timer;
  void pollDueWebsites();
}
