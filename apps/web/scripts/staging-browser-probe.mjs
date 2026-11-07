import { scanBrowserSite } from "../lib/browser-monitor.ts";

const target = process.argv[2];
if (!target) {
  process.stderr.write("Usage: staging-browser-probe.mjs <staging-url>\n");
  process.exit(2);
}

// scanBrowserSite applies the same URL, DNS, redirect, request, viewport,
// crawl-depth, page-count, and duration limits used by central monitoring.
const result = await scanBrowserSite(target);
const summary = {
  status: result.status,
  checkedAt: result.checkedAt,
  pageLimit: result.pageLimit,
  pageLimitReached: result.pageLimitReached,
  crawlIncomplete: result.crawlIncomplete,
  pages: result.pages.map((page) => ({
    url: page.url,
    statusCode: page.statusCode,
    complete: page.complete,
    metrics: page.metrics,
    findingFingerprints: page.findingFingerprints,
  })),
  findings: result.findings.map(({ fingerprint, title, severity, description }) => ({ fingerprint, title, severity, description })),
  errors: result.errors.slice(0, 20),
};
process.stdout.write(JSON.stringify(summary));
