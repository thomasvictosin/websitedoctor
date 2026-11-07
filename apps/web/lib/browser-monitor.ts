import { createHash } from "node:crypto";
import http, { type RequestOptions } from "node:http";
import https from "node:https";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { chromium, type Browser, type BrowserContext, type Page, type Route } from "playwright";
import { assertSafeTarget, isPublicAddress, pinnedLookup, resolvePublicAddresses } from "./monitor.ts";
import { redactApiValue } from "./redaction.ts";

export type BrowserFinding = {
  fingerprint: string;
  title: string;
  description: string;
  severity: "low" | "medium" | "high";
  evidence: Record<string, unknown>;
};

export type BrowserScanResult = {
  status: "passed" | "issues_found" | "partial" | "unavailable";
  scannedUrl: string;
  checkedAt: string;
  viewports: Array<{ width: number; height: number }>;
  pages: Array<{
    url: string;
    pageKey: string;
    statusCode: number | null;
    durationMs: number;
    metrics: { viewports: Array<{ width: number; height: number; loadTimeMs: number | null; resourceCount: number; failedRequestCount: number; largestContentfulPaintMs: number | null; cumulativeLayoutShift: number | null; firstContentfulPaintMs: number | null; timeToFirstByteMs: number | null; transferSizeBytes: number | null }> };
    findingFingerprints: string[];
    discoveredPageCount: number;
    complete: boolean;
    errors: string[];
  }>;
  pageLimit: number;
  pageLimitReached: boolean;
  crawlIncomplete: boolean;
  findings: BrowserFinding[];
    metrics: { processedPages: number; completePages: number; viewportSamples: number; resourceCount: number; failedRequestCount: number; transferSizeBytes: number; viewportMetricSummary: Record<string, { sampleCount: number; median: number | null; p75: number | null; max: number | null }> };
  errors: string[];
};

const VIEWPORTS = [
  { width: 390, height: 844 },
  { width: 768, height: 1024 },
  { width: 1365, height: 900 },
];
const MAX_REQUESTS = 3000;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 12_000;
const MAX_TOTAL_RESPONSE_BYTES = 100 * 1024 * 1024;
const MAX_PAGES = 250;
const MAX_CRAWL_DEPTH = 8;
const MAX_LINKS_PER_PAGE = 1000;
const MAX_LINK_PROBES = 200;
const MAX_LINK_CANDIDATES = 1000;
const MAX_SCAN_DURATION_MS = 600_000;
const WEBRTC_DISABLED_MARKER = "WebRTC is disabled during website diagnostics.";

function loadAxeSource(): string {
  const directories: string[] = [];
  for (let directory = process.cwd(); ; directory = dirname(directory)) {
    directories.push(directory);
    if (dirname(directory) === directory) break;
  }
  const candidates = directories.flatMap((directory) => [
    resolve(directory, "node_modules/axe-core/axe.min.js"),
    resolve(directory, "apps/web/node_modules/axe-core/axe.min.js"),
  ]);
  const sourcePath = candidates.find(existsSync);
  if (!sourcePath) throw new Error("Unable to locate axe-core/axe.min.js from " + process.cwd());
  return readFileSync(sourcePath, "utf8");
}

const AXE_SOURCE = loadAxeSource();

function safeEvidenceUrl(value: string): string {
  try {
    const url = new URL(value);
    url.search = "";
    url.hash = "";
    return url.toString().slice(0, 1000);
  } catch {
    return "[invalid URL]";
  }
}

type BrowserResponse = { status: number; headers: Record<string, string>; body: Buffer };
type BrowserDependencies = {
  launch: () => Promise<Browser>;
  resolve: typeof resolvePublicAddresses;
  request: (url: URL, method: string, headers: Record<string, string>, body: Buffer | null) => Promise<BrowserResponse>;
};

const defaultDependencies: BrowserDependencies = {
  launch: () => chromium.launch({ headless: true, args: ["--disable-dev-shm-usage"] }),
  resolve: resolvePublicAddresses,
  request: secureBrowserRequest,
};

async function discoverSitemapPages(target: URL, origin: string, dependencies: BrowserDependencies, state: { count: number; bytes: number; errors: string[] }): Promise<string[]> {
  const sitemapUrls = new Set<string>([new URL("/sitemap.xml", origin).toString()]);
  try {
    const robots = new URL("/robots.txt", origin);
  await safeAddresses(robots, dependencies);
    const response = await dependencies.request(robots, "GET", {}, null);
    state.count += 1;
    state.bytes += response.body.length;
    if (state.count > MAX_REQUESTS || state.bytes > MAX_TOTAL_RESPONSE_BYTES) throw new Error("Sitemap discovery reached the browser request or response limit.");
    if (response.status < 400) {
      for (const line of response.body.toString("utf8").split(/\r?\n/)) {
        const match = /^\s*sitemap\s*:\s*(\S+)/i.exec(line);
        if (!match) continue;
        const candidate = new URL(match[1], robots);
        if (candidate.origin === origin && await safeAddresses(candidate, dependencies).then(() => true).catch(() => false)) sitemapUrls.add(candidate.toString());
        if (sitemapUrls.size >= 10) break;
      }
    }
  } catch (error) {
    state.errors.push("robots.txt sitemap discovery: " + (error instanceof Error ? error.message.slice(0, 200) : "unavailable"));
  }

  const pages = new Set<string>();
  const queue = [...sitemapUrls];
  const visited = new Set<string>();
  while (queue.length && visited.size < 10 && pages.size < 5000) {
    const sitemap = new URL(queue.shift()!);
    if (visited.has(sitemap.toString()) || sitemap.origin !== origin) continue;
    visited.add(sitemap.toString());
    try {
      await safeAddresses(sitemap, dependencies);
      let response = await dependencies.request(sitemap, "GET", {}, null);
      state.count += 1;
      state.bytes += response.body.length;
      if (state.count > MAX_REQUESTS || state.bytes > MAX_TOTAL_RESPONSE_BYTES || response.body.length > 2 * 1024 * 1024) throw new Error("Sitemap response exceeded its safety limit.");
      for (let redirects = 0; response.status >= 300 && response.status < 400 && response.headers.location && redirects < 5; redirects += 1) {
        const redirected = new URL(response.headers.location, sitemap);
        if (redirected.origin !== origin) throw new Error("Sitemap redirected outside the registered origin: " + safeEvidenceUrl(redirected.toString()));
        await safeAddresses(redirected, dependencies);
        response = await dependencies.request(redirected, "GET", {}, null);
        state.count += 1;
        state.bytes += response.body.length;
        if (state.count > MAX_REQUESTS || state.bytes > MAX_TOTAL_RESPONSE_BYTES || response.body.length > 2 * 1024 * 1024) throw new Error("Sitemap response exceeded its safety limit.");
      }
      if (response.status >= 400) continue;
      const xml = response.body.toString("utf8");
      const locs = [...xml.matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/gi)].map((match) => match[1].replaceAll("&amp;", "&").trim());
      if (/<sitemapindex\b/i.test(xml)) {
        for (const loc of locs) {
          const nested = new URL(loc, sitemap);
          if (nested.origin === origin && queue.length + visited.size < 10) queue.push(nested.toString());
        }
      } else {
        for (const loc of locs) {
          const normalized = normalizeCrawlUrlWithQuery(loc, sitemap.toString(), origin, true);
          if (normalized) pages.add(normalized);
          if (pages.size >= 5000) break;
        }
      }
    } catch (error) {
      state.errors.push("sitemap " + sitemap.pathname + ": " + (error instanceof Error ? error.message.slice(0, 200) : "unavailable"));
    }
  }
  if (queue.length || pages.size >= 5000) state.errors.push("Sitemap discovery reached its document or URL limit.");
  return [...pages];
}

function assertPublicHttpUrl(url: URL, addresses: Array<{ address: string }>): void {
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("Browser scan blocked a non-HTTP request.");
  if (url.username || url.password) throw new Error("Browser scan blocked a URL containing credentials.");
  if (!addresses.length || addresses.some(({ address }) => !isPublicAddress(address))) {
    throw new Error("Browser scan blocked a request to a non-public address.");
  }
}

async function safeAddresses(url: URL, dependencies: BrowserDependencies) {
  assertSafeTarget(url);
  const addresses = await dependencies.resolve(url.hostname.replace(/^\[|\]$/g, ""));
  assertPublicHttpUrl(url, addresses);
  return addresses;
}

function secureBrowserRequest(
  target: URL,
  method: string,
  headers: Record<string, string>,
  body: Buffer | null,
): Promise<BrowserResponse> {
  return new Promise((resolve, reject) => {
    assertSafeTarget(target);
    void resolvePublicAddresses(target.hostname.replace(/^\[|\]$/g, "")).then((addresses) => {
      assertPublicHttpUrl(target, addresses);
      const transport = target.protocol === "https:" ? https : http;
      const requestHeaders = { ...headers, "accept-encoding": "identity", host: target.host };
      const options: RequestOptions = {
        method,
        headers: requestHeaders,
        timeout: REQUEST_TIMEOUT_MS,
        lookup: pinnedLookup(addresses),
      };
      const request = transport.request(target, options, (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_RESPONSE_BYTES) {
            response.destroy(new Error("Browser scan response exceeded the size limit."));
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => {
          const responseHeaders: Record<string, string> = {};
          for (const [key, value] of Object.entries(response.headers)) {
            if (typeof value === "string" && !["set-cookie", "content-length", "content-encoding", "transfer-encoding", "connection"].includes(key.toLowerCase())) {
              responseHeaders[key] = value;
            }
          }
          resolve({ status: response.statusCode ?? 502, headers: responseHeaders, body: Buffer.concat(chunks) });
        });
        response.on("error", reject);
      });
      request.on("timeout", () => request.destroy(new Error("Browser scan request timed out.")));
      request.on("error", reject);
      if (body) request.write(body);
      request.end();
    }).catch(reject);
  });
}

async function fulfillPublicRequest(route: Route, dependencies: BrowserDependencies, state: { count: number; bytes: number; errors: string[]; blockedUrls: Set<string> }) {
  if (!["GET", "HEAD"].includes(route.request().method())) {
    state.blockedUrls.add(route.request().url());
    await route.abort("blockedbyclient");
    return;
  }
  try {
    let target = new URL(route.request().url());
    let addresses = await safeAddresses(target, dependencies);
    const redirectTrace: string[] = [];
    for (let redirects = 0; redirects <= 5; redirects += 1) {
      if (++state.count > MAX_REQUESTS) throw new Error("Browser scan reached its request limit.");
      const response = await dependencies.request(
        target,
        route.request().method(),
        route.request().headers(),
        route.request().postDataBuffer(),
      );
      const location = response.headers.location;
      if (response.status >= 300 && response.status < 400 && location) {
        const redirected = new URL(location, target);
        redirectTrace.push(`${response.status} ${safeEvidenceUrl(target.toString())} -> ${safeEvidenceUrl(redirected.toString())}`);
        if (redirects === 5) throw new Error("Browser request exceeded redirect limit: " + redirectTrace.join(" | "));
        target = redirected;
        addresses = await safeAddresses(target, dependencies);
        continue;
      }
      state.bytes += response.body.length;
      if (state.bytes > MAX_TOTAL_RESPONSE_BYTES) throw new Error("Browser scan reached its total response-size limit.");
      await route.fulfill({ status: response.status, headers: response.headers, body: response.body });
      return;
    }
    throw new Error("Browser request exceeded redirect limit: " + redirectTrace.join(" | "));
  } catch (error) {
    state.blockedUrls.add(route.request().url());
    state.errors.push(error instanceof Error ? error.message.slice(0, 300) : "Browser request was blocked.");
    await route.abort("failed").catch(() => undefined);
  }
}

const CHECK_PAGE = `() => {
  const visible = (el) => { const s = getComputedStyle(el); const r = el.getBoundingClientRect(); return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 0 && r.height > 0; };
  const describe = (el) => ({ tag: el.tagName.toLowerCase(), id: el.id || null, className: typeof el.className === 'string' ? el.className.slice(0, 120) : '' });
  const rgb = (value) => { const m = value.match(/[\\d.]+/g); return m && m.length >= 3 ? m.slice(0,3).map(Number) : null; };
  const luminance = (c) => { const a = c.map((v) => { v /= 255; return v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4; }); return .2126*a[0] + .7152*a[1] + .0722*a[2]; };
  const contrast = (a,b) => { const x=luminance(a), y=luminance(b); return (Math.max(x,y)+.05)/(Math.min(x,y)+.05); };
  const background = (el) => { for (let n=el; n; n=n.parentElement) { const c=rgb(getComputedStyle(n).backgroundColor); if (c && getComputedStyle(n).backgroundColor !== 'rgba(0, 0, 0, 0)') return c; } return [255,255,255]; };
  const missingAlt = [...document.images].filter((img) => !img.hasAttribute('alt')).slice(0,20).map(describe);
  const unlabeled = [...document.querySelectorAll('input:not([type=hidden]),select,textarea')].filter((el) => !el.labels?.length && !el.getAttribute('aria-label') && !el.getAttribute('aria-labelledby')).slice(0,20).map(describe);
  const hiddenNavs = [...document.querySelectorAll('nav,[role=navigation]')].filter((el) => !visible(el));
  const hasMenuControl = [...document.querySelectorAll('button,[role=button],a')].some((el) => visible(el) && (/menu|navigation/i.test((el.innerText||'')+' '+(el.getAttribute('aria-label')||'')) || (el.getAttribute('aria-controls') && hiddenNavs.some((nav) => nav.id === el.getAttribute('aria-controls')))));
  const navIssue = innerWidth <= 600 && hiddenNavs.length > 0 && !hasMenuControl ? hiddenNavs.slice(0,5).map(describe) : [];
  const root=document.documentElement;
  const documentWidth=Math.max(root.scrollWidth,document.body?.scrollWidth ?? 0);
  const overflowingElements=[...document.querySelectorAll('body *')].slice(0,2000).flatMap((el)=>{const r=el.getBoundingClientRect();const parent=el.parentElement;const parentWidth=parent?.getBoundingClientRect().width??innerWidth;if(r.width<=parentWidth+2||r.right<=innerWidth+2)return[];const id=el.id;const classes=[...el.classList];const selector=id&&document.querySelectorAll('#'+CSS.escape(id)).length===1?'#'+id:classes.map((name)=>'.'+CSS.escape(name)).find((candidate)=>{try{return document.querySelectorAll(candidate).length===1}catch{return false}});return[{tag:el.tagName.toLowerCase(),selector:selector??null,width:Math.round(r.width),parentWidth:Math.round(parentWidth),right:Math.round(r.right)}]}).slice(0,20);
  const navigation=performance.getEntriesByType('navigation')[0];
  const links=[...document.querySelectorAll('a[href]')].map((link) => ({url:link.href,text:(link.innerText||link.getAttribute('aria-label')||'').trim().slice(0,120)})).slice(0,${MAX_LINKS_PER_PAGE});
  const brokenFragments=links.filter((link)=>{const u=new URL(link.url,location.href);let target;try{target=decodeURIComponent(u.hash.slice(1))}catch{return false}return u.origin===location.origin&&u.pathname===location.pathname&&u.search===location.search&&u.hash.length>1&&target.toLowerCase()!=='top'&&!document.getElementById(target)&&![...document.querySelectorAll('[name]')].some((el)=>el.getAttribute('name')===target)}).slice(0,20);
  const paints=performance.getEntriesByType('paint');
  const lcp=performance.getEntriesByType('largest-contentful-paint').at(-1);
  const shifts=performance.getEntriesByType('layout-shift').filter((entry)=>!entry.hadRecentInput).reduce((sum,entry)=>sum+entry.value,0);
  const resources=performance.getEntriesByType('resource');
  return { viewport:{width:innerWidth,height:innerHeight}, overflow:documentWidth>innerWidth ? {scrollWidth:documentWidth,clientWidth:root.clientWidth,viewportWidth:innerWidth,overflowingElements} : null, missingAlt, unlabeled, mobileNavigationUnavailable:navIssue, loadTimeMs:navigation && navigation.loadEventEnd > 0 ? Math.round(navigation.loadEventEnd) : null, resourceCount:resources.length, resourceEntries:resources.map((entry)=>({url:entry.name,transferSizeBytes:entry.transferSize||0,encodedBodySizeBytes:entry.encodedBodySize||0,durationMs:Math.round(entry.duration||0),initiatorType:entry.initiatorType||'other'})),performance:{largestContentfulPaintMs:lcp ? Math.round(lcp.startTime) : null,cumulativeLayoutShift:Math.round(shifts*1000)/1000,firstContentfulPaintMs:paints.find((entry)=>entry.name==='first-contentful-paint')?.startTime ?? null,timeToFirstByteMs:navigation && navigation.responseStart > 0 ? Math.round(navigation.responseStart-navigation.requestStart) : null,transferSizeBytes:resources.reduce((sum,entry)=>sum+(entry.transferSize||0),0)}, links, brokenFragments };
}`;

export function browserPageKey(pageUrl: string): string {
  const url = new URL(pageUrl);
  return createHash("sha256").update(`${url.pathname}${url.search}`).digest("hex").slice(0, 12);
}

function finding(key: string, pageUrl: string, title: string, severity: BrowserFinding["severity"], description: string, evidence: Record<string, unknown>): BrowserFinding {
  const pageKey = browserPageKey(pageUrl);
  return { fingerprint: `browser:${key}:${pageKey}`, title, severity, description, evidence: { pageUrl: safeEvidenceUrl(pageUrl), ...evidence } };
}

function collectFindings(snapshot: Record<string, any>, runtimeErrors: string[], consoleErrors: string[], failedRequests: Array<Record<string, unknown>>, viewport: { width: number; height: number }, pageUrl: string): BrowserFinding[] {
  const findings: BrowserFinding[] = [];
  if (snapshot.overflow) findings.push(finding("horizontal-overflow", pageUrl, "Horizontal overflow detected", "medium", `The document is wider than the viewport at ${viewport.width}px.`, { viewport, ...snapshot.overflow }));
  if (snapshot.mobileNavigationUnavailable?.length) findings.push(finding("mobile-navigation", pageUrl, "Mobile navigation may be unavailable", "medium", "A navigation region is hidden on a narrow viewport and no visible menu control was found.", { viewport, elements: snapshot.mobileNavigationUnavailable }));
  if (snapshot.mobileNavigationBroken) findings.push(finding("mobile-navigation", pageUrl, "Mobile navigation control did not open its navigation", "high", "A mobile navigation button was tested, but its controlled navigation remained hidden or aria-expanded did not change to true.", { viewport, ...snapshot.mobileNavigationBroken }));
  if (snapshot.missingAlt?.length) findings.push(finding("missing-image-alt", pageUrl, "Images are missing alternative text", "medium", `${snapshot.missingAlt.length} image(s) have no alt attribute.`, { viewport, elements: snapshot.missingAlt }));
  if (snapshot.unlabeled?.length) findings.push(finding("missing-form-label", pageUrl, "Form controls lack accessible labels", "medium", `${snapshot.unlabeled.length} form control(s) have no associated label or accessible name.`, { viewport, elements: snapshot.unlabeled }));
  if (runtimeErrors.length) findings.push(finding("javascript-error", pageUrl, "Uncaught JavaScript exceptions occurred", "high", `${runtimeErrors.length} uncaught page exception(s) were observed.`, { viewport, errors: runtimeErrors.slice(0, 10) }));
  if (consoleErrors.length) findings.push(finding("console-error", pageUrl, "Browser console errors were reported", "medium", `${consoleErrors.length} console error(s) were reported by the page.`, { viewport, errors: consoleErrors.slice(0, 10) }));
  if (failedRequests.length) findings.push(finding("failed-request", pageUrl, "Browser requests failed", "medium", `${failedRequests.length} distinct page or resource request(s) failed or returned an error in this viewport.`, { viewport, requests: failedRequests.slice(0, 20) }));
  if (snapshot.loadTimeMs !== null && snapshot.loadTimeMs > 5000) findings.push(finding("slow-page-load", pageUrl, "Page load is slow", "medium", `The browser load event took ${snapshot.loadTimeMs}ms at ${viewport.width}px.`, { viewport, loadTimeMs: snapshot.loadTimeMs, thresholdMs: 5000, resourceCount: snapshot.resourceCount }));
  const resourceEntries = Array.isArray(snapshot.resourceEntries) ? snapshot.resourceEntries as Array<Record<string, unknown>> : [];
  const largeResources = resourceEntries.filter((resource) => typeof resource.encodedBodySizeBytes === "number" && resource.encodedBodySizeBytes >= 1_000_000)
    .sort((left, right) => Number(right.encodedBodySizeBytes) - Number(left.encodedBodySizeBytes)).slice(0, 10)
    .map((resource) => ({ url: typeof resource.url === "string" ? safeEvidenceUrl(resource.url) : "[unknown resource]", encodedBodySizeBytes: resource.encodedBodySizeBytes, initiatorType: resource.initiatorType }));
  if (largeResources.length) findings.push(finding("large-resource", pageUrl, "Large browser resources detected", "medium", `${largeResources.length} measured resource(s) were at least 1 MB encoded.`, { viewport, thresholdBytes: 1_000_000, resources: largeResources }));
  const slowResources = resourceEntries.filter((resource) => typeof resource.durationMs === "number" && resource.durationMs >= 3000)
    .sort((left, right) => Number(right.durationMs) - Number(left.durationMs)).slice(0, 10)
    .map((resource) => ({ url: typeof resource.url === "string" ? safeEvidenceUrl(resource.url) : "[unknown resource]", durationMs: resource.durationMs, initiatorType: resource.initiatorType }));
  if (slowResources.length) findings.push(finding("slow-resource", pageUrl, "Slow browser resources detected", "medium", `${slowResources.length} resource(s) took at least 3 seconds in this browser sample.`, { viewport, thresholdMs: 3000, resources: slowResources }));
  if (Number(snapshot.resourceCount) > 100) findings.push(finding("resource-heavy-page", pageUrl, "Page loads many browser resources", "low", `The browser recorded ${Number(snapshot.resourceCount)} resource entries for this viewport.`, { viewport, resourceCount: Number(snapshot.resourceCount), thresholdCount: 100 }));
  for (const violation of (Array.isArray(snapshot.accessibility) ? snapshot.accessibility : []).slice(0, 50)) {
    const ruleId = String(violation.id ?? "unknown").slice(0, 80);
    const impact = String(violation.impact ?? "moderate");
    const severity = impact === "critical" || impact === "serious" ? "high" : "medium";
    findings.push(finding("accessibility-" + ruleId, pageUrl, String(violation.help ?? ruleId).slice(0, 200), severity, String(violation.description ?? "Automated accessibility rule violation.").slice(0, 500), {
      viewport, ruleId, impact, helpUrl: String(violation.helpUrl ?? "").slice(0, 500),
      wcagTags: Array.isArray(violation.tags) ? violation.tags.filter((tag: unknown) => typeof tag === "string" && tag.startsWith("wcag")).slice(0, 12) : [],
      nodes: Array.isArray(violation.nodes) ? violation.nodes.slice(0, 10).map((node: any) => ({ target: Array.isArray(node.target) ? node.target.slice(0, 5) : [], failureSummary: String(node.failureSummary ?? "").slice(0, 500), html: String(node.html ?? "").slice(0, 300) })) : [],
    }));
  }
  const performance = snapshot.performance && typeof snapshot.performance === "object" ? snapshot.performance as Record<string, unknown> : {};
  if (typeof performance.largestContentfulPaintMs === "number" && performance.largestContentfulPaintMs > 2500) findings.push(finding("poor-lcp", pageUrl, "Largest contentful paint is slow", "medium", "Largest contentful paint exceeded 2.5 seconds.", { viewport, valueMs: performance.largestContentfulPaintMs, thresholdMs: 2500 }));
  if (typeof performance.cumulativeLayoutShift === "number" && performance.cumulativeLayoutShift > 0.1) findings.push(finding("poor-cls", pageUrl, "Cumulative layout shift is high", "medium", "Cumulative layout shift exceeded 0.1.", { viewport, value: performance.cumulativeLayoutShift, threshold: 0.1 }));
  return findings;
}

async function inspectAtViewport(page: Page, context: BrowserContext, url: string, viewport: { width: number; height: number }, dependencies: BrowserDependencies, requestState: { count: number; bytes: number; errors: string[]; blockedUrls: Set<string> }, timeoutMs: number) {
  await page.setViewportSize(viewport);
  const runtimeErrors: string[] = [];
  const consoleErrors: string[] = [];
  const failedRequests: Array<Record<string, unknown>> = [];
  const onPageError = (error: Error) => { if (!error.message.includes(WEBRTC_DISABLED_MARKER)) runtimeErrors.push(String(redactApiValue(error.message)).slice(0, 500)); };
  const onConsole = (message: { type(): string; text(): string }) => { if (message.type() === "error" && !message.text().includes(WEBRTC_DISABLED_MARKER)) consoleErrors.push(String(redactApiValue(message.text())).slice(0, 500)); };
  const onRequestFailed = (request: { url(): string; failure(): { errorText?: string } | null }) => {
    if (requestState.blockedUrls.has(request.url())) return;
    failedRequests.push({ url: safeEvidenceUrl(request.url()), error: String(redactApiValue(request.failure()?.errorText ?? "request failed")).slice(0, 300) });
  };
  const onResponse = (response: { url(): string; status(): number; request(): { resourceType(): string } }) => { if (response.status() >= 400) failedRequests.push({ url: safeEvidenceUrl(response.url()), status: response.status(), resourceType: response.request().resourceType() }); };
  page.on("pageerror", onPageError);
  page.on("console", onConsole);
  page.on("requestfailed", onRequestFailed);
  page.on("response", onResponse);
  const routeHandler = (route: Route) => fulfillPublicRequest(route, dependencies, requestState);
  await context.route("**/*", routeHandler);
  let navigationError: string | null = null;
  let snapshotError: string | null = null;
  const response = await page.goto(url, { waitUntil: "load", timeout: timeoutMs }).catch((error) => {
    navigationError = error instanceof Error ? error.message.slice(0, 500) : "Navigation failed.";
    return null;
  });
  const redirectChain: Array<{ url: string; status: number }> = [];
  if (response) {
    let previous = response.request().redirectedFrom();
    while (previous && redirectChain.length < 6) {
      const previousResponse = await previous.response().catch(() => null);
      if (previousResponse) redirectChain.unshift({ url: safeEvidenceUrl(previous.url()), status: previousResponse.status() });
      previous = previous.redirectedFrom();
    }
  }
  if (page.url() !== "about:blank") await page.waitForTimeout(1000).catch(() => undefined);
  const snapshot = (page.url() !== "about:blank" ? await page.evaluate(`(${CHECK_PAGE})()`).catch((error) => {
    snapshotError = error instanceof Error ? error.message.slice(0, 500) : "Page inspection failed.";
    return null;
  }) : null) as Record<string, any> | null;
  if (snapshot) {
    const axe = await page.addScriptTag({ content: AXE_SOURCE }).then(() => page.evaluate(async () => {
      const axe = (window as any).axe;
      const results = await axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"] } });
      return results.violations.map((violation: any) => ({
        id: violation.id, impact: violation.impact, help: violation.help, description: violation.description, helpUrl: violation.helpUrl,
        tags: violation.tags, nodes: violation.nodes.map((node: any) => ({ target: node.target, failureSummary: node.failureSummary, html: node.html })),
      }));
    })).catch((error) => {
      snapshot.accessibilityAuditError = error instanceof Error ? error.message.slice(0, 200) : "axe-core audit failed.";
      return [];
    });
    snapshot.accessibility = axe;
  }
  if (snapshot && viewport.width <= 600) {
    const controls = page.locator("button[aria-controls]");
    for (let index = 0; index < Math.min(await controls.count(), 5); index += 1) {
      const control = controls.nth(index);
      const candidate = await control.evaluate((element) => {
        const id = element.getAttribute("aria-controls");
        const target = id ? document.getElementById(id) : null;
        const style = element instanceof HTMLElement ? getComputedStyle(element) : null;
        return Boolean(target && (target.matches("nav,[role=navigation]") || target.querySelector("nav,[role=navigation]")) && style?.display !== "none" && style?.visibility !== "hidden");
      });
      if (!candidate) continue;
      await control.click({ timeout: 1000 }).catch(() => undefined);
      await page.waitForTimeout(50);
      const state = await control.evaluate((element) => {
        const id = element.getAttribute("aria-controls");
        const target = id ? document.getElementById(id) : null;
        if (!(target instanceof HTMLElement)) return { visible: false, expanded: element.getAttribute("aria-expanded") };
        const style = getComputedStyle(target);
        const rect = target.getBoundingClientRect();
        return { visible: style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0, expanded: element.getAttribute("aria-expanded") };
      });
      if (!state.visible || state.expanded !== "true") {
        (snapshot as Record<string, any>).mobileNavigationBroken = { control: "button[aria-controls]", state };
      }
      break;
    }
  }
  await context.unroute("**/*", routeHandler);
  page.off("pageerror", onPageError);
  page.off("console", onConsole);
  page.off("requestfailed", onRequestFailed);
  page.off("response", onResponse);
  return { snapshot, runtimeErrors, consoleErrors, failedRequests, statusCode: response?.status() ?? null, navigationError, snapshotError, pageUrl: page.url(), redirectChain };
}

export async function scanBrowserSite(rawUrl: string, injected?: Partial<BrowserDependencies>): Promise<BrowserScanResult> {
  const started = new Date();
  const dependencies = { ...defaultDependencies, ...injected };
  let browser: Browser | null = null;
  const findings: BrowserFinding[] = [];
  const pages: BrowserScanResult["pages"] = [];
  const linkCandidates = new Map<string, Map<string, { text: string; href: string }>>();
  const pageStatuses = new Map<string, number | null>();
  const pageRedirects = new Map<string, { finalUrl: string; chain: Array<{ url: string; status: number }> }>();
  let linkCandidateLimitReached = false;
  const errors: string[] = [];
  const scanMetricSamples: Record<string, number[]> = { loadTimeMs: [], largestContentfulPaintMs: [], cumulativeLayoutShift: [], firstContentfulPaintMs: [], timeToFirstByteMs: [] };
  let aggregateFailedRequestCount = 0;
  const scanResourceSizes = new Map<string, number>();
  let scannedUrl = rawUrl;
  let pageLimitReached = false;
  let crawlIncomplete = false;
  try {
    const target = new URL(rawUrl);
    await safeAddresses(target, dependencies);
    const origin = target.origin;
    const rootUrl = normalizeCrawlUrl(target.href, target.href, origin);
    if (!rootUrl) throw new Error("Registered site URL is not eligible for browser crawling.");
    browser = await dependencies.launch();
    const context = await browser.newContext({ ignoreHTTPSErrors: false, serviceWorkers: "block" });
    await context.routeWebSocket("**/*", (socket) => socket.close());
    await context.addInitScript(() => {
      Object.defineProperty(window, "RTCPeerConnection", {
        configurable: false,
        value: class { constructor() { throw new Error("WebRTC is disabled during website diagnostics."); } },
      });
      Object.defineProperty(window, "webkitRTCPeerConnection", {
        configurable: false,
        value: window.RTCPeerConnection,
      });
    });
    const page = await context.newPage();
    const requestState = { count: 0, bytes: 0, errors, blockedUrls: new Set<string>() };
    const deadline = Date.now() + MAX_SCAN_DURATION_MS;
    const sitemapPages = await discoverSitemapPages(target, origin, dependencies, requestState);
    if (Date.now() >= deadline) throw new Error("Browser scan reached its time limit during sitemap discovery.");
    const queue: Array<{ url: string; depth: number }> = [{ url: rootUrl, depth: 0 }, ...sitemapPages.filter((url) => url !== rootUrl).map((url) => ({ url, depth: 0 }))];
    const queued = new Set(queue.map(({ url }) => url));
    const visited = new Set<string>();

    while (queue.length && pages.length < MAX_PAGES) {
      if (Date.now() >= deadline) {
        crawlIncomplete = true;
        errors.push("Browser scan reached its total time limit.");
        break;
      }
      const current = queue.shift()!;
      if (visited.has(current.url)) continue;
      visited.add(current.url);
      const pageStartedAt = Date.now();
      const pageFindings: BrowserFinding[] = [];
      const pageErrors: string[] = [];
      const discoveredLinks = new Set<string>();
      const viewportMetrics: Array<{ width: number; height: number; loadTimeMs: number | null; resourceCount: number; failedRequestCount: number; largestContentfulPaintMs: number | null; cumulativeLayoutShift: number | null; firstContentfulPaintMs: number | null; timeToFirstByteMs: number | null; transferSizeBytes: number | null }> = [];
      const pageFailedRequests = new Map<string, Record<string, unknown>>();
      let pageStatusCode: number | null = null;
      let pageUrl = current.url;
      let pageRedirectChain: Array<{ url: string; status: number }> = [];
      let successfulViewports = 0;

      for (const viewport of VIEWPORTS) {
        const remaining = deadline - Date.now();
        if (remaining <= 0) {
          crawlIncomplete = true;
          pageErrors.push("Browser scan reached its total time limit before all viewports completed.");
          break;
        }
        const result = await inspectAtViewport(page, context, current.url, viewport, dependencies, requestState, Math.min(15_000, remaining));
        if (!result.snapshot) {
          pageErrors.push(`Page could not be inspected at ${viewport.width}px viewport.`);
          if (viewport.width === VIEWPORTS[0].width) continue;
          break;
        }
        successfulViewports += 1;
        const snapshot = result.snapshot as Record<string, any>;
        pageStatusCode ??= result.statusCode;
        pageUrl = result.pageUrl;
        if (viewport.width === VIEWPORTS[0].width) pageRedirectChain = result.redirectChain;
        scannedUrl = safeEvidenceUrl(pageUrl);
        const observedPerformance = snapshot.performance && typeof snapshot.performance === "object" ? snapshot.performance as Record<string, unknown> : {};
        const viewportMetric = {
          width: viewport.width,
          height: viewport.height,
          loadTimeMs: typeof snapshot.loadTimeMs === "number" ? snapshot.loadTimeMs : null,
          resourceCount: Number(snapshot.resourceCount) || 0,
          failedRequestCount: new Set(result.failedRequests.map((failed) => `${failed.url ?? ""}|${failed.status ?? ""}|${failed.error ?? ""}`)).size,
          largestContentfulPaintMs: typeof observedPerformance.largestContentfulPaintMs === "number" ? observedPerformance.largestContentfulPaintMs : null,
          cumulativeLayoutShift: typeof observedPerformance.cumulativeLayoutShift === "number" ? observedPerformance.cumulativeLayoutShift : null,
          firstContentfulPaintMs: typeof observedPerformance.firstContentfulPaintMs === "number" ? observedPerformance.firstContentfulPaintMs : null,
          timeToFirstByteMs: typeof observedPerformance.timeToFirstByteMs === "number" ? observedPerformance.timeToFirstByteMs : null,
          transferSizeBytes: typeof observedPerformance.transferSizeBytes === "number" ? observedPerformance.transferSizeBytes : null,
        };
        viewportMetrics.push(viewportMetric);
        const viewportFailedRequests = new Map<string, Record<string, unknown>>();
        for (const failed of result.failedRequests) {
          const identity = `${failed.url ?? ""}|${failed.status ?? ""}|${failed.error ?? ""}`;
          viewportFailedRequests.set(identity, failed);
          pageFailedRequests.set(identity, failed);
        }
        viewportMetric.failedRequestCount = viewportFailedRequests.size;
        for (const key of Object.keys(scanMetricSamples)) {
          const value = viewportMetric[key as keyof typeof viewportMetric];
          if (typeof value === "number") scanMetricSamples[key].push(value);
        }
        for (const resource of Array.isArray(snapshot.resourceEntries) ? snapshot.resourceEntries : []) {
          if (resource && typeof resource.url === "string") {
            const resourceKey = createHash("sha256").update(resource.url).digest("hex");
            const size = typeof resource.transferSizeBytes === "number" ? resource.transferSizeBytes : 0;
            scanResourceSizes.set(resourceKey, Math.max(scanResourceSizes.get(resourceKey) ?? 0, size));
          }
        }
        for (const link of Array.isArray(snapshot.links) ? snapshot.links : []) {
          if (!link || typeof link.url !== "string") continue;
          const normalized = normalizeCrawlUrl(link.url, pageUrl, origin);
          if (normalized) discoveredLinks.add(normalized);
          try {
            const target = new URL(link.url, pageUrl);
            if (target.origin !== origin || !["http:", "https:"].includes(target.protocol) || target.username || target.password) continue;
            target.hash = "";
            if (target.pathname !== "/") target.pathname = target.pathname.replace(/\/+$/, "") || "/";
            target.search = new URLSearchParams([...target.searchParams.entries()].sort(([left], [right]) => left.localeCompare(right))).toString();
            const targetUrl = target.toString();
            if (!linkCandidates.has(targetUrl) && linkCandidates.size >= MAX_LINK_CANDIDATES) {
              linkCandidateLimitReached = true;
              continue;
            }
            if (!linkCandidates.has(targetUrl)) linkCandidates.set(targetUrl, new Map());
            linkCandidates.get(targetUrl)!.set(pageUrl, {
              text: typeof link.text === "string" ? link.text.slice(0, 120) : "",
              // Store the resolved URL so relative links can be matched safely
              // against the published post content by the WordPress executor.
              href: targetUrl,
            });
          } catch { /* Invalid links are not eligible for network probes. */ }
        }
        for (const brokenFragment of Array.isArray(snapshot.brokenFragments) ? snapshot.brokenFragments : []) {
          if (!brokenFragment || typeof brokenFragment !== "object" || typeof brokenFragment.url !== "string") continue;
          const fragmentUrl = new URL(brokenFragment.url, pageUrl);
          let fragment = fragmentUrl.hash.slice(1);
          try { fragment = decodeURIComponent(fragment); } catch { /* Preserve the encoded fragment for evidence. */ }
          findings.push(finding(`broken-link:${createHash("sha256").update(brokenFragment.url).digest("hex").slice(0, 16)}`, pageUrl, "In-page link target does not exist", "low", "A same-page link points to an ID or named anchor that was not found in the rendered document.", { kind: "missing_fragment", sourcePage: safeEvidenceUrl(pageUrl), link: safeEvidenceUrl(brokenFragment.url), href: safeEvidenceUrl(brokenFragment.url), anchorText: typeof brokenFragment.text === "string" ? brokenFragment.text.slice(0, 120) : "", fragment: fragment.slice(0, 200) }));
        }
        pageFindings.push(...collectFindings(snapshot, result.runtimeErrors, result.consoleErrors, result.failedRequests, viewport, pageUrl));
        if (result.statusCode !== null && result.statusCode >= 400) {
          pageFindings.push(finding("page-http-error", pageUrl, "Page returned an HTTP error", "high", `The page returned HTTP ${result.statusCode}.`, { statusCode: result.statusCode, viewport }));
        }
      }

      const uniquePageFindings = [...new Map(pageFindings.map((item) => [item.fingerprint, item])).values()];
      const mergedPageFindings = uniquePageFindings.map((item) => ({
        ...item,
        evidence: {
          ...item.evidence,
          observations: pageFindings.filter((observed) => observed.fingerprint === item.fingerprint).map((observed) => observed.evidence),
        },
      }));
      findings.push(...mergedPageFindings);
      errors.push(...pageErrors);
      const newLinks = [...discoveredLinks].filter((url) => !queued.has(url) && !visited.has(url));
      const queuedCount = current.depth < MAX_CRAWL_DEPTH ? newLinks.length : 0;
      pageStatuses.set(current.url, pageStatusCode);
      pageRedirects.set(current.url, { finalUrl: pageUrl, chain: pageRedirectChain });
      pages.push({
        url: safeEvidenceUrl(pageUrl),
        pageKey: browserPageKey(pageUrl),
        statusCode: pageStatusCode,
        durationMs: Date.now() - pageStartedAt,
        metrics: { viewports: viewportMetrics },
        findingFingerprints: mergedPageFindings.map(({ fingerprint }) => fingerprint),
        discoveredPageCount: queuedCount,
        complete: successfulViewports === VIEWPORTS.length,
        errors: pageErrors,
      });
      aggregateFailedRequestCount += pageFailedRequests.size;

      if (current.depth < MAX_CRAWL_DEPTH) {
        for (const url of newLinks) {
          queued.add(url);
          queue.push({ url, depth: current.depth + 1 });
        }
      } else if (newLinks.length > 0) {
        crawlIncomplete = true;
      }
    }
    const canonicalLinkUrl = (value: string) => normalizeCrawlUrlWithQuery(value, origin, origin, true);
    for (const [linkUrl, sourceLinks] of linkCandidates) {
      const status = pageStatuses.get(linkUrl);
      const redirect = pageRedirects.get(linkUrl);
      if (status === undefined || status === null || status < 200 || status >= 300 || !redirect || redirect.chain.length === 0) continue;
      if (!redirect.chain.every((hop) => hop.status === 301 || hop.status === 308)) continue;
      const replacementUrl = canonicalLinkUrl(redirect.finalUrl);
      if (!replacementUrl || replacementUrl === canonicalLinkUrl(linkUrl)) continue;
      for (const [sourcePage, linkEvidence] of sourceLinks) findings.push(finding(
        `link-redirect:${createHash("sha256").update(linkUrl).digest("hex").slice(0, 16)}`,
        sourcePage,
        "Internal link uses a permanent redirect",
        "low",
        "This same-origin link redirects permanently to a reachable page. Updating the stored link can remove the redirect hop.",
        { kind: "permanent_redirect", sourcePage: safeEvidenceUrl(sourcePage), link: safeEvidenceUrl(linkUrl), href: safeEvidenceUrl(linkEvidence.href), replacementUrl: safeEvidenceUrl(replacementUrl), anchorText: linkEvidence.text, statusCode: status, redirectChain: redirect.chain.slice(0, 6) },
      ));
    }
    let probedLinks = 0;
    const linksNeedingProbe = [...linkCandidates.keys()].filter((linkUrl) => pageStatuses.get(linkUrl) === undefined);
    for (const [linkUrl, sourcePages] of linkCandidates) {
      const crawledStatus = pageStatuses.get(linkUrl);
      if (crawledStatus !== undefined) {
        if (crawledStatus !== null && [404, 410].includes(crawledStatus)) {
          for (const [sourcePage, linkEvidence] of sourcePages) findings.push(finding(`broken-link:${createHash("sha256").update(linkUrl).digest("hex").slice(0, 16)}`, sourcePage, "Internal link points to a missing page", "medium", `A same-origin link returned HTTP ${crawledStatus} during page navigation.`, { kind: "missing_page", sourcePage: safeEvidenceUrl(sourcePage), link: safeEvidenceUrl(linkUrl), href: safeEvidenceUrl(linkEvidence.href), anchorText: linkEvidence.text, statusCode: crawledStatus, method: "GET", redirectChain: pageRedirects.get(linkUrl)?.chain ?? [] }));
        }
        continue;
      }
      if (probedLinks >= MAX_LINK_PROBES || Date.now() >= deadline || requestState.count >= MAX_REQUESTS) break;
      probedLinks += 1;
      try {
        let target = new URL(linkUrl);
        let response: BrowserResponse | null = null;
        const redirectChain: Array<{ url: string; status: number }> = [];
        for (let redirects = 0; redirects <= 5; redirects += 1) {
          if (target.origin !== origin) break;
          if (Date.now() >= deadline || requestState.count >= MAX_REQUESTS) {
            response = null;
            break;
          }
          await safeAddresses(target, dependencies);
          requestState.count += 1;
          response = await dependencies.request(target, "HEAD", { "user-agent": "AI-Website-Doctor-Link-Check/1.0" }, null);
          requestState.bytes += response.body.length;
          if (requestState.bytes > MAX_TOTAL_RESPONSE_BYTES) throw new Error("Browser scan reached its total response-size limit during broken-link checks.");
          if (response.status >= 300 && response.status < 400 && response.headers.location) {
            redirectChain.push({ url: safeEvidenceUrl(target.toString()), status: response.status });
            if (redirects === 5) response = null;
            else target = new URL(response.headers.location, target);
            continue;
          }
          break;
        }
        if (response && [404, 410].includes(response.status)) {
          for (const [sourcePage, linkEvidence] of sourcePages) findings.push(finding(`broken-link:${createHash("sha256").update(linkUrl).digest("hex").slice(0, 16)}`, sourcePage, "Internal link points to a missing page", "medium", `A same-origin link returned HTTP ${response.status} to a HEAD request.`, { kind: "missing_page", sourcePage: safeEvidenceUrl(sourcePage), link: safeEvidenceUrl(linkUrl), href: safeEvidenceUrl(linkEvidence.href), anchorText: linkEvidence.text, statusCode: response.status, method: "HEAD", redirectChain }));
        } else if (response && response.status >= 200 && response.status < 300 && redirectChain.length > 0
          && redirectChain.every((hop) => hop.status === 301 || hop.status === 308)) {
          const replacementUrl = canonicalLinkUrl(target.toString());
          if (replacementUrl && replacementUrl !== canonicalLinkUrl(linkUrl)) {
            for (const [sourcePage, linkEvidence] of sourcePages) findings.push(finding(
              `link-redirect:${createHash("sha256").update(linkUrl).digest("hex").slice(0, 16)}`,
              sourcePage,
              "Internal link uses a permanent redirect",
              "low",
              "This same-origin link redirects permanently to a reachable page. Updating the stored link can remove the redirect hop.",
              { kind: "permanent_redirect", sourcePage: safeEvidenceUrl(sourcePage), link: safeEvidenceUrl(linkUrl), href: safeEvidenceUrl(linkEvidence.href), replacementUrl: safeEvidenceUrl(replacementUrl), anchorText: linkEvidence.text, statusCode: response.status, redirectChain: redirectChain.slice(0, 6) },
            ));
          }
        }
      } catch (error) {
        errors.push(`Same-origin link probe failed: ${error instanceof Error ? error.message.slice(0, 150) : "probe unavailable"}`);
      }
    }
    if (linksNeedingProbe.length > probedLinks) errors.push(`Broken-link checks were partial: ${probedLinks} of ${linksNeedingProbe.length} unvisited same-origin links were probed (limit ${MAX_LINK_PROBES}, scan request/time budget applies).`);
    if (linkCandidateLimitReached) errors.push(`Broken-link candidate collection was capped at ${MAX_LINK_CANDIDATES} same-origin links.`);
    if (queue.length > 0) {
      crawlIncomplete = true;
      pageLimitReached = pages.length >= MAX_PAGES;
    }
    await context.close();
    const deduplicated = [...new Map(findings.map((item) => [item.fingerprint, item])).values()];
    const completePageCount = pages.filter((page) => page.complete).length;
    const status = deduplicated.length ? "issues_found" : completePageCount === 0 ? "unavailable" : crawlIncomplete || errors.length ? "partial" : "passed";
    const percentileSummary = (values: number[]) => {
      const sorted = [...values].sort((a, b) => a - b);
      const percentile = (p: number) => sorted.length ? sorted[Math.ceil(p * sorted.length) - 1] : null;
      return { sampleCount: sorted.length, median: percentile(0.5), p75: percentile(0.75), max: sorted.at(-1) ?? null };
    };
    const metrics = {
      processedPages: pages.length,
      completePages: completePageCount,
      viewportSamples: Object.values(scanMetricSamples).reduce((max, values) => Math.max(max, values.length), 0),
      resourceCount: scanResourceSizes.size,
      failedRequestCount: aggregateFailedRequestCount,
      transferSizeBytes: [...scanResourceSizes.values()].reduce((sum, size) => sum + size, 0),
      viewportMetricSummary: Object.fromEntries(Object.entries(scanMetricSamples).map(([key, values]) => [key, percentileSummary(values)])),
    };
    return { status, scannedUrl, checkedAt: started.toISOString(), viewports: VIEWPORTS, pages, pageLimit: MAX_PAGES, pageLimitReached, crawlIncomplete, findings: deduplicated, metrics, errors };
  } catch (error) {
    const reason = error instanceof Error ? error.message : "Browser scan is unavailable.";
    errors.push(reason.slice(0, 500));
    return { status: "unavailable", scannedUrl, checkedAt: started.toISOString(), viewports: VIEWPORTS, pages, pageLimit: MAX_PAGES, pageLimitReached, crawlIncomplete, findings, metrics: { processedPages: pages.length, completePages: pages.filter((page) => page.complete).length, viewportSamples: 0, resourceCount: 0, failedRequestCount: 0, transferSizeBytes: 0, viewportMetricSummary: {} }, errors };
  } finally {
    await browser?.close().catch(() => undefined);
  }
}

function normalizeCrawlUrl(rawUrl: string, baseUrl: string, siteOrigin: string): string | null {
  return normalizeCrawlUrlWithQuery(rawUrl, baseUrl, siteOrigin, false);
}

function normalizeCrawlUrlWithQuery(rawUrl: string, baseUrl: string, siteOrigin: string, includeQuery: boolean): string | null {
  try {
    const url = new URL(rawUrl, baseUrl);
    if ((url.protocol !== "http:" && url.protocol !== "https:") || url.origin !== siteOrigin || url.username || url.password || (!includeQuery && url.search)) return null;
    url.hash = "";
    if (url.pathname !== "/") url.pathname = url.pathname.replace(/\/+$/, "") || "/";
    if (includeQuery && url.search) url.search = new URLSearchParams([...url.searchParams.entries()].sort(([left], [right]) => left.localeCompare(right))).toString();
    return url.toString();
  } catch {
    return null;
  }
}
