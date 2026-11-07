import { db } from "@/lib/db";
import { enqueueScan, startScanQueue } from "@/lib/scan-queue";

const globalForScheduler = globalThis as typeof globalThis & {
  websiteDoctorScheduler?: ReturnType<typeof setInterval>;
  websiteDoctorSchedulerRunning?: boolean;
};

async function pollDueWebsites() {
  if (globalForScheduler.websiteDoctorSchedulerRunning) return;
  globalForScheduler.websiteDoctorSchedulerRunning = true;
  try {
    const now = new Date();
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
      const nextCheckAt = new Date(Date.now() + website.intervalMinutes * 60_000);
      await db.website.updateMany({ where: { id: website.id, monitoringEnabled: true, nextCheckAt: website.nextCheckAt }, data: { nextCheckAt } });
    }
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
