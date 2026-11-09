// Runs the browser checks (layout overflow, mobile menu, JavaScript errors,
// failed requests, accessibility, Core Web Vitals) for every monitored site
// and posts each result to the app, which stores it like any other scan.
// Vercel functions have no browser, so this runs on a GitHub Actions runner:
//   MONITOR_URL=https://… CRON_SECRET=… node --experimental-strip-types scripts/browser-checks.mjs
// BROWSER_CHECK_MODE=pending scans only the sites waiting for a re-check after a fix.
import { scanBrowserSite } from "../lib/browser-monitor.ts";

const base = (process.env.MONITOR_URL ?? "").replace(/\/$/, "");
const secret = process.env.CRON_SECRET ?? "";
if (!base || !secret) {
  console.log("MONITOR_URL and CRON_SECRET are not configured; skipping browser checks.");
  process.exit(0);
}
const headers = { authorization: `Bearer ${secret}` };

const pendingOnly = process.env.BROWSER_CHECK_MODE === "pending";
const listing = await fetch(`${base}/api/cron/browser-checks${pendingOnly ? "?pending=1" : ""}`, { headers, signal: AbortSignal.timeout(30_000) });
if (!listing.ok) throw new Error(`Listing monitored sites failed: HTTP ${listing.status} ${await listing.text()}`);
const { sites } = await listing.json();
console.log(pendingOnly ? `${sites.length} site(s) waiting for a re-check.` : `${sites.length} monitored site(s).`);

let failures = 0;
for (const site of sites) {
  const started = Date.now();
  try {
    const result = await scanBrowserSite(site.url);
    const response = await fetch(`${base}/api/cron/browser-checks`, {
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify({ siteId: site.id, result }),
      signal: AbortSignal.timeout(110_000),
    });
    const body = await response.text();
    if (!response.ok) throw new Error(`storing the result failed: HTTP ${response.status} ${body.slice(0, 300)}`);
    console.log(`${site.name}: ${result.status}, ${result.findings.length} finding(s), ${result.pages.length} page(s) in ${Math.round((Date.now() - started) / 1000)}s.`);
  } catch (error) {
    failures += 1;
    console.error(`${site.name}: ${error instanceof Error ? error.message : String(error)}`);
  }
}
if (failures) process.exitCode = 1;
