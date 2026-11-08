import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { scanBrowserSite } from "../lib/browser-monitor.ts";

const fixture = new URL("./fixtures/problematic-site/", import.meta.url);
const healthyFixture = new URL("./fixtures/healthy-site/", import.meta.url);
const pages = new Map([
  ["/", ["index.html", "text/html"]],
  ["/index.html", ["index.html", "text/html"]],
  ["/style.css", ["style.css", "text/css"]],
  ["/app.js", ["app.js", "text/javascript"]],
  ["/secondary", ["secondary.html", "text/html"]],
]);
let delayFirstDocument = true;
const requestedHosts = [];

test("real browser scan detects layout, accessibility, navigation, runtime, and failed-request defects", async (context) => {
  try {
    const result = await scanBrowserSite("https://fixture.example/", {
      resolve: async (hostname) => hostname === "169.254.169.254"
        ? [{ address: "169.254.169.254", family: 4 }]
        : [{ address: "93.184.216.34", family: 4 }],
      request: async (url) => {
        requestedHosts.push(url.hostname);
        if (url.pathname === "/" && delayFirstDocument) {
          delayFirstDocument = false;
        await new Promise((resolve) => setTimeout(resolve, 5100));
        }
        const entry = pages.get(url.pathname);
        if (!entry) return { status: 404, headers: { "content-type": "text/plain" }, body: Buffer.from("missing") };
        return {
          status: 200,
          headers: { "content-type": entry[1] },
          body: Buffer.from(await readFile(new URL(entry[0], fixture))),
        };
      },
    });

    if (result.status === "unavailable" && result.errors.some((error) => /Executable doesn't exist/.test(error))) {
      context.skip("Install the Playwright Chromium runtime with `npm run browser:install --workspace apps/web` to execute browser integration tests.");
      return;
    }
    assert.equal(result.status, "issues_found", JSON.stringify(result));
    const fingerprints = new Set(result.findings.map(({ fingerprint }) => fingerprint));
    const hasFinding = (kind) => [...fingerprints].some((fingerprint) => fingerprint.startsWith(`browser:${kind}:`));
    assert.ok(hasFinding("horizontal-overflow"));
    const overflow = result.findings.find(({ fingerprint }) => fingerprint.startsWith("browser:horizontal-overflow:"));
    assert.ok(overflow.evidence.observations.some((observation) => observation.viewport.width === 390 && observation.scrollWidth > observation.viewportWidth));
    assert.ok(overflow.evidence.observations.some((observation) => observation.overflowingElements?.some((element) => element.selector && element.width > element.parentWidth)));
    assert.ok(hasFinding("mobile-navigation"));
    assert.ok(hasFinding("missing-image-alt"));
    assert.ok(hasFinding("missing-form-label"));
    assert.ok(hasFinding("accessibility-color-contrast"));
    assert.ok(hasFinding("accessibility-image-alt"), "axe-core should record a WCAG-referenced image alternative violation");
    assert.ok(hasFinding("javascript-error"));
    assert.ok(hasFinding("failed-request"));
    assert.ok(hasFinding("broken-link"), "same-origin links that return 404 should identify their source link");
    assert.ok(hasFinding("slow-page-load"));
    assert.equal(result.viewports.length, 3);
    assert.ok(result.metrics.resourceCount >= 2);
    assert.equal(result.pages.length, 2);
    assert.equal(result.metrics.processedPages, 2);
    assert.ok(result.metrics.completePages <= result.metrics.processedPages);
    assert.ok(result.metrics.viewportMetricSummary.loadTimeMs.sampleCount > 0);
    assert.ok(result.pages.some((page) => page.url === "https://fixture.example/secondary"));
    assert.ok(result.pages.every((page) => page.complete));
    assert.equal(result.pages.some((page) => /other\.example|search\?/.test(page.url)), false);
    // Both pages miss alt text; that is one site-wide issue listing both pages, not two issues.
    const missingAlt = result.findings.filter(({ fingerprint }) => fingerprint.startsWith("browser:missing-image-alt:"));
    assert.equal(missingAlt.length, 1);
    assert.equal(missingAlt[0].fingerprint, "browser:missing-image-alt:site");
    assert.equal(missingAlt[0].evidence.pageCount, 2);
    assert.equal(result.pageLimitReached, false);
    assert.equal(requestedHosts.includes("169.254.169.254"), false, "private metadata destinations must never reach the fetcher");
  } catch (error) {
    if (String(error).includes("Executable doesn't exist")) {
      context.skip("Install Chromium with `npx playwright install chromium` to run browser integration tests.");
      return;
    }
    throw error;
  }
});

test("browser scan rejects private targets before starting Chromium", async () => {
  let browserStarted = false;
  const result = await scanBrowserSite("http://127.0.0.1/", {
    resolve: async () => [{ address: "127.0.0.1", family: 4 }],
    launch: async () => {
      browserStarted = true;
      throw new Error("Private target should have been rejected first.");
    },
  });
  assert.equal(result.status, "unavailable");
  assert.equal(browserStarted, false);
  assert.match(result.errors[0], /non-public address/i);
});

test("browser crawl discovers same-origin sitemap pages", async (context) => {
  try {
    const result = await scanBrowserSite("https://fixture.example/", {
      resolve: async () => [{ address: "93.184.216.34", family: 4 }],
      request: async (url) => {
        if (url.pathname === "/robots.txt") return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("Sitemap: https://fixture.example/sitemap-index.xml") };
        if (url.pathname === "/sitemap-index.xml") return { status: 200, headers: { "content-type": "application/xml" }, body: Buffer.from("<sitemapindex><sitemap><loc>https://fixture.example/pages.xml</loc></sitemap></sitemapindex>") };
        if (url.pathname === "/pages.xml") return { status: 200, headers: { "content-type": "application/xml" }, body: Buffer.from("<urlset><url><loc>https://fixture.example/sitemap-page</loc></url><url><loc>https://other.example/private</loc></url></urlset>") };
        const files = { "/": ["index.html", "text/html"], "/sitemap-page": ["index.html", "text/html"], "/style.css": ["style.css", "text/css"], "/app.js": ["app.js", "text/javascript"], "/control.svg": ["control.svg", "image/svg+xml"] };
        const entry = files[url.pathname];
        if (!entry) return { status: 404, headers: { "content-type": "text/plain" }, body: Buffer.from("missing") };
        return { status: 200, headers: { "content-type": entry[1] }, body: Buffer.from(await readFile(new URL(entry[0], healthyFixture))) };
      },
    });
    if (result.status === "unavailable" && result.errors.some((error) => /Executable doesn't exist/.test(error))) {
      context.skip("Install Chromium to run the sitemap crawl control.");
      return;
    }
    assert.ok(result.pages.some((page) => page.url === "https://fixture.example/sitemap-page"));
    assert.equal(result.pages.some((page) => page.url.includes("other.example")), false);
  } catch (error) {
    if (String(error).includes("Executable doesn't exist")) {
      context.skip("Install Chromium to run the sitemap crawl control.");
      return;
    }
    throw error;
  }
});

test("healthy browser control produces no layout, accessibility, runtime, request, or performance findings", async (context) => {
  try {
    const result = await scanBrowserSite("https://fixture.example/healthy/", {
      resolve: async () => [{ address: "93.184.216.34", family: 4 }],
      request: async (url) => {
        const files = {
          "/healthy": ["index.html", "text/html"],
          "/healthy/": ["index.html", "text/html"],
          "/healthy/style.css": ["style.css", "text/css"],
          "/healthy/app.js": ["app.js", "text/javascript"],
          "/healthy/control.svg": ["control.svg", "image/svg+xml"],
          "/style.css": ["style.css", "text/css"],
          "/app.js": ["app.js", "text/javascript"],
          "/control.svg": ["control.svg", "image/svg+xml"],
        };
        const entry = files[url.pathname];
        if (!entry) return { status: 404, headers: { "content-type": "text/plain" }, body: Buffer.from("missing") };
        return {
          status: 200,
          headers: { "content-type": entry[1] },
          body: Buffer.from(await readFile(new URL(entry[0], healthyFixture))),
        };
      },
    });
    if (result.status === "unavailable" && result.errors.some((error) => /Executable doesn't exist/.test(error))) {
      context.skip("Install the Playwright Chromium runtime to execute browser controls.");
      return;
    }
    assert.equal(result.status, "passed", JSON.stringify(result));
    assert.equal(result.findings.length, 0);
    assert.equal(result.findings.some(({ fingerprint }) => ["broken-link", "large-resource", "slow-resource", "resource-heavy-page"].some((kind) => fingerprint.startsWith(`browser:${kind}:`))), false, "healthy control should remain clear for the dedicated link and resource detectors");
    assert.equal(result.pages.length, 1);
    assert.ok(result.pages[0].complete);
    assert.ok(result.metrics.viewportMetricSummary.firstContentfulPaintMs.sampleCount > 0);
    assert.ok(result.metrics.viewportMetricSummary.timeToFirstByteMs.sampleCount > 0);
  } catch (error) {
    if (String(error).includes("Executable doesn't exist")) {
      context.skip("Install Chromium to run browser control tests.");
      return;
    }
    throw error;
  }
});
