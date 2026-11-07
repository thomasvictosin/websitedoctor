export async function register() {
  // Vercel runs each request in a short-lived serverless function. Starting
  // in-process workers here also eagerly loads the Playwright runtime, which
  // is not part of the page server's traced bundle and cannot be kept alive
  // reliably in this environment.
  if (process.env.NEXT_RUNTIME === "nodejs" && process.env.VERCEL !== "1") {
    const { startMonitoringScheduler } = await import("./lib/scheduler");
    const { startScanQueue } = await import("./lib/scan-queue");
    startMonitoringScheduler();
    startScanQueue();
  }
}
