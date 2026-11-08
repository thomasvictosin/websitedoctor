import type { Prisma } from "@prisma/client";
import { db } from "./db.ts";
import { getIntegrations } from "./integrations.ts";

/**
 * Performance through Google PageSpeed Insights (the same Lighthouse run and
 * Chrome UX Report field data that pagespeed.web.dev shows), for mobile and
 * desktop. Each failing audit is explained in plain words, the files behind
 * it are attributed to the plugin or theme that loads them, and audits with
 * a safe site-side fix are linked to one-click performance measures that the
 * WordPress plugin (0.8.0+) applies, verifies and can undo.
 */

export type Strategy = "mobile" | "desktop";
type Json = Record<string, unknown>;
const record = (value: unknown): Json => value && typeof value === "object" && !Array.isArray(value) ? value as Json : {};

export const PERFORMANCE_MEASURES = {
  page_cache: { title: "Page caching", description: "Serves ready-made pages instead of building each one with PHP and database queries. Uses the cache plugin already on the site, or installs LiteSpeed Cache (LiteSpeed servers) or Cache Enabler from WordPress.org.", group: "speed" },
  compression: { title: "Text compression", description: "Compresses HTML, CSS and JavaScript (gzip/Brotli) so pages download 60–80% smaller. Works on Apache and LiteSpeed servers.", group: "speed" },
  browser_caching: { title: "Browser caching", description: "Lets returning visitors reuse images, CSS, JavaScript and fonts for up to a year instead of downloading them again.", group: "speed" },
  defer_scripts: { title: "Defer non-critical JavaScript", description: "Loads theme and plugin scripts at the end of the page after it is shown. Header scripts and jQuery stay as they are, because plugins (tracking pixels, for example) call them straight away; WordPress keeps any script whose order matters blocking, and the home page is checked afterwards.", group: "speed" },
  font_display_swap: { title: "Show text while fonts load", description: "Adds font-display: swap to Google Fonts and connects to the font server early, so text appears immediately.", group: "speed" },
  trim_extras: { title: "Remove unused WordPress extras", description: "Stops loading the emoji script, the embed script and dashicons for visitors who are not logged in.", group: "speed" },
  lazy_load: { title: "Lazy-load images and videos", description: "Makes sure images and embedded videos below the first screen load only when the visitor scrolls to them.", group: "speed" },
  webp_uploads: { title: "WebP for new uploads", description: "New JPEG and PNG uploads are saved as WebP (about 30% smaller). Existing images are not changed.", group: "speed" },
  a11y_zoom: { title: "Allow zooming on phones", description: "Removes the page setting that stops visitors from pinch-zooming, so people with low vision can enlarge text.", group: "accessibility" },
  a11y_names: { title: "Name icon-only links and buttons", description: "Icon links and buttons (social icons, menu, search, close) get a spoken name for screen readers, taken from where they point or what the icon shows. Nothing visible changes.", group: "accessibility" },
  a11y_form_labels: { title: "Label form fields", description: "Form fields without any label get one for screen readers, taken from their placeholder or field name. Nothing visible changes.", group: "accessibility" },
} as const;
export type PerformanceMeasure = keyof typeof PERFORMANCE_MEASURES;
export const PERFORMANCE_MEASURE_IDS = Object.keys(PERFORMANCE_MEASURES) as PerformanceMeasure[];

/** Plain-language explanation per Lighthouse audit, and the measure that addresses it (if any). */
const AUDITS: Record<string, { why: string; fix?: PerformanceMeasure; manual?: string }> = {
  "server-response-time": { why: "The server takes too long to send the first byte of the page, so everything else waits.", fix: "page_cache", manual: "If caching is on and this persists, the hosting plan is too slow or overloaded; consider a faster host or a CDN." },
  "uses-text-compression": { why: "HTML, CSS or JavaScript is sent uncompressed.", fix: "compression" },
  "uses-long-cache-ttl": { why: "Static files tell browsers not to keep them, so every visit downloads them again.", fix: "browser_caching" },
  "render-blocking-resources": { why: "CSS and JavaScript in the page head must download before anything is shown.", fix: "defer_scripts", manual: "Remaining render-blocking CSS comes from the theme and page builder; a cache plugin's \"critical CSS\" option can remove it." },
  "font-display": { why: "Text stays invisible while web fonts download.", fix: "font_display_swap" },
  "uses-rel-preconnect": { why: "The browser connects to third-party servers (fonts, analytics) late.", fix: "font_display_swap" },
  "offscreen-images": { why: "Images below the first screen download before they are needed.", fix: "lazy_load" },
  "modern-image-formats": { why: "Images are JPEG/PNG where WebP or AVIF would be much smaller.", fix: "webp_uploads", manual: "Existing images need converting: install an image optimizer such as Converter for Media and run its bulk conversion once." },
  "uses-optimized-images": { why: "Images are not compressed.", manual: "Run an image optimizer once over the media library (for example Converter for Media or EWWW Image Optimizer)." },
  "uses-responsive-images": { why: "Images are larger than the size they are shown at, especially on phones.", manual: "Use WordPress image sizes in the page builder instead of full-size images, and regenerate thumbnails." },
  "efficient-animated-content": { why: "Animated GIFs are used where a video would be far smaller.", manual: "Replace large GIFs with MP4/WebM videos." },
  "unused-javascript": { why: "JavaScript is downloaded but not used on this page.", manual: "Turn off plugins that load scripts on every page but are used on few (sliders, form and chat plugins), or limit them to the pages that need them." },
  "unused-css-rules": { why: "CSS is downloaded but not used on this page.", manual: "Page builders and themes load full stylesheets; their \"improved asset loading\" options (Elementor → Settings → Features) reduce it." },
  "unminified-css": { why: "CSS files contain spaces and comments browsers don't need.", manual: "Turn on CSS minification in the cache plugin." },
  "unminified-javascript": { why: "JavaScript files contain spaces and comments browsers don't need.", manual: "Turn on JavaScript minification in the cache plugin." },
  "bootup-time": { why: "JavaScript takes a long time to run on the visitor's device.", manual: "The biggest scripts are listed; removing or replacing the heaviest plugin usually helps most." },
  "mainthread-work-breakdown": { why: "The browser is busy running scripts and layout, so the page reacts slowly (this drives Total Blocking Time and INP).", manual: "Reduce heavy plugins, sliders and third-party scripts." },
  "third-party-summary": { why: "Scripts from other companies (analytics, chat, ads, embeds) slow the page.", manual: "Remove third-party scripts you don't need, or load them after the page is interactive." },
  "dom-size": { why: "The page has a very large number of elements, which makes every update slow.", manual: "Simplify the page: page builders nest many wrappers; fewer sections and widgets help." },
  "total-byte-weight": { why: "The page is very heavy to download.", manual: "Images and scripts are the usual cause; see the image and JavaScript items." },
  "lcp-lazy-loaded": { why: "The largest image at the top of the page is lazy-loaded, so it appears late.", manual: "Exclude the hero image from lazy loading in the theme or page builder." },
  "largest-contentful-paint-element": { why: "This is the element that sets the Largest Contentful Paint time.", manual: "Make that element (usually the hero image or heading) load first: compress it and don't lazy-load it." },
  "layout-shift-elements": { why: "Elements move after the page appears (Cumulative Layout Shift).", manual: "Give images, ads and embeds a fixed width and height." },
  "unsized-images": { why: "Images have no width and height, so the page jumps while they load.", manual: "Set image dimensions in the page builder." },
  "legacy-javascript": { why: "Scripts include old-browser code modern browsers don't need.", manual: "Update the plugins listed; newer versions usually ship modern code." },
  "duplicated-javascript": { why: "The same library is loaded more than once.", manual: "Two plugins bundle the same library; keep only one of them." },
  "redirects": { why: "The page redirects before loading.", manual: "Link to the final address (with or without www/https) directly." },
};

const LAB = [
  ["first-contentful-paint", "fcp", "First Contentful Paint"],
  ["largest-contentful-paint", "lcp", "Largest Contentful Paint"],
  ["total-blocking-time", "tbt", "Total Blocking Time"],
  ["cumulative-layout-shift", "cls", "Cumulative Layout Shift"],
  ["speed-index", "si", "Speed Index"],
  ["server-response-time", "ttfb", "Server response time"],
] as const;
const FIELD = [
  ["LARGEST_CONTENTFUL_PAINT_MS", "lcp", "Largest Contentful Paint"],
  ["INTERACTION_TO_NEXT_PAINT", "inp", "Interaction to Next Paint"],
  ["CUMULATIVE_LAYOUT_SHIFT_SCORE", "cls", "Cumulative Layout Shift"],
  ["FIRST_CONTENTFUL_PAINT_MS", "fcp", "First Contentful Paint"],
  ["EXPERIMENTAL_TIME_TO_FIRST_BYTE", "ttfb", "Time to First Byte"],
] as const;

export type Opportunity = { id: string; title: string; why: string; displayValue: string | null; savingsMs: number | null; savingsBytes: number | null; score: number | null; fix: PerformanceMeasure | null; manual: string | null; sources: Array<{ name: string; kind: "plugin" | "theme" | "core" | "third-party" | "site"; bytes: number | null; ms: number | null }>; items: Array<{ url: string; bytes: number | null; ms: number | null }> };

function sourceOf(url: string, origin: string, names: Map<string, string>) {
  const plugin = /\/wp-content\/plugins\/([^/]+)\//.exec(url);
  if (plugin) return { name: names.get(`plugin:${plugin[1]}`) ?? plugin[1], kind: "plugin" as const };
  const theme = /\/wp-content\/themes\/([^/]+)\//.exec(url);
  if (theme) return { name: `${names.get(`theme:${theme[1]}`) ?? theme[1]} theme`, kind: "theme" as const };
  if (/\/wp-includes\//.test(url)) return { name: "WordPress core", kind: "core" as const };
  try {
    const host = new URL(url).host;
    if (host && host !== new URL(origin).host) return { name: host, kind: "third-party" as const };
  } catch { /* not a URL (e.g. an element) */ }
  return { name: "This site", kind: "site" as const };
}

/** Reduce a PageSpeed Insights response to scores, metrics and explained opportunities. */
export function parsePageSpeed(body: unknown, diagnostics: unknown = {}) {
  const result = record(body);
  const lighthouse = record(result.lighthouseResult);
  const audits = record(lighthouse.audits);
  const performance = record(record(lighthouse.categories).performance);
  const score = typeof performance.score === "number" ? Math.round(performance.score * 100) : null;
  const metrics: Record<string, { label: string; value: number | null; display: string | null; score: number | null }> = {};
  for (const [auditId, key, label] of LAB) {
    const audit = record(audits[auditId]);
    metrics[key] = { label, value: typeof audit.numericValue === "number" ? audit.numericValue : null, display: typeof audit.displayValue === "string" ? audit.displayValue : null, score: typeof audit.score === "number" ? audit.score : null };
  }
  const loading = record(result.loadingExperience);
  const fieldSource = Object.keys(record(loading.metrics)).length ? { scope: "page", data: loading } : { scope: "origin", data: record(result.originLoadingExperience) };
  const fieldMetrics = record(fieldSource.data.metrics);
  const field: Record<string, { label: string; p75: number; category: string }> = {};
  for (const [id, key, label] of FIELD) {
    const metric = record(fieldMetrics[id]);
    if (typeof metric.percentile === "number") field[key] = { label, p75: id === "CUMULATIVE_LAYOUT_SHIFT_SCORE" ? metric.percentile / 100 : metric.percentile, category: String(metric.category ?? "") };
  }
  const names = new Map<string, string>();
  const data = record(diagnostics);
  for (const plugin of Array.isArray(data.plugins) ? data.plugins.map(record) : []) if (typeof plugin.file === "string") names.set(`plugin:${plugin.file.split("/")[0]}`, String(plugin.name ?? plugin.file));
  for (const theme of Array.isArray(data.themes) ? data.themes.map(record) : []) if (typeof theme.stylesheet === "string") names.set(`theme:${theme.stylesheet}`, String(theme.name ?? theme.stylesheet));
  const origin = String(lighthouse.finalDisplayedUrl ?? lighthouse.finalUrl ?? result.id ?? "https://invalid.invalid");
  const opportunities: Opportunity[] = [];
  for (const [id, guide] of Object.entries(AUDITS)) {
    const audit = record(audits[id]);
    if (!Object.keys(audit).length || audit.scoreDisplayMode === "notApplicable" || audit.scoreDisplayMode === "manual") continue;
    const auditScore = typeof audit.score === "number" ? audit.score : null;
    if (auditScore !== null && auditScore >= 0.9) continue;
    if (auditScore === null && audit.scoreDisplayMode !== "informative") continue;
    const details = record(audit.details);
    const rows = Array.isArray(details.items) ? details.items.map(record) : [];
    const items = rows.map((row) => ({ url: typeof row.url === "string" ? row.url : typeof record(row.node).snippet === "string" ? String(record(row.node).snippet) : typeof row.entity === "string" ? row.entity : "", bytes: typeof row.wastedBytes === "number" ? row.wastedBytes : typeof row.transferSize === "number" ? row.transferSize : null, ms: typeof row.wastedMs === "number" ? row.wastedMs : typeof row.total === "number" ? row.total : typeof row.blockingTime === "number" ? row.blockingTime : null })).filter((item) => item.url);
    if (audit.scoreDisplayMode === "informative" && !items.length) continue;
    const bySource = new Map<string, Opportunity["sources"][number]>();
    for (const item of items) {
      const source = sourceOf(item.url, origin, names);
      const entry = bySource.get(source.name) ?? { ...source, bytes: null, ms: null };
      if (item.bytes !== null) entry.bytes = (entry.bytes ?? 0) + item.bytes;
      if (item.ms !== null) entry.ms = (entry.ms ?? 0) + item.ms;
      bySource.set(source.name, entry);
    }
    const metricSavings = record(audit.metricSavings);
    opportunities.push({
      id, title: String(audit.title ?? id).slice(0, 200), why: guide.why,
      displayValue: typeof audit.displayValue === "string" ? audit.displayValue : null,
      savingsMs: typeof details.overallSavingsMs === "number" ? Math.round(details.overallSavingsMs) : typeof metricSavings.LCP === "number" ? Math.round(metricSavings.LCP) : null,
      savingsBytes: typeof details.overallSavingsBytes === "number" ? Math.round(details.overallSavingsBytes) : null,
      score: auditScore, fix: guide.fix ?? null, manual: guide.manual ?? null,
      sources: [...bySource.values()].sort((a, b) => (b.bytes ?? 0) + (b.ms ?? 0) * 1000 - (a.bytes ?? 0) - (a.ms ?? 0) * 1000).slice(0, 6),
      items: items.slice(0, 8).map((item) => ({ ...item, url: item.url.slice(0, 300) })),
    });
  }
  opportunities.sort((a, b) => (b.savingsMs ?? 0) - (a.savingsMs ?? 0) || (a.score ?? 1) - (b.score ?? 1));
  return { score, metrics, field: Object.keys(field).length ? { scope: fieldSource.scope, overall: String(record(fieldSource.data).overall_category ?? ""), metrics: field } : null, opportunities, finalUrl: origin };
}

export class PageSpeedError extends Error {
  readonly status: number;
  constructor(message: string, status = 400) {
    super(message);
    this.status = status;
  }
}

export async function fetchPageSpeed(url: string, strategy: Strategy, apiKey: string | null, fetcher: typeof fetch = fetch) {
  const query = new URLSearchParams({ url, strategy, category: "performance" });
  if (apiKey) query.set("key", apiKey);
  const response = await fetcher(`https://www.googleapis.com/pagespeedonline/v5/runPagespeed?${query}`, { signal: AbortSignal.timeout(110_000) });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = String(record(record(body).error).message ?? `HTTP ${response.status}`);
    throw new PageSpeedError(response.status === 429 ? (apiKey ? "Google's PageSpeed quota for this key is used up; try again later." : "Google refuses PageSpeed tests without an API key (quota exceeded). Add a free PageSpeed key in Settings → Integrations.") : response.status === 400 && /key/i.test(message) ? "The PageSpeed API key was rejected; check it in Settings → Integrations." : `PageSpeed Insights could not test the page: ${message.slice(0, 200)}`, response.status === 429 ? 429 : 400);
  }
  return body;
}

/** Score bands used by PageSpeed: 90+ good, 50–89 needs improvement, below 50 poor. */
export function scoreBand(score: number | null) {
  return score === null ? "unknown" : score >= 90 ? "good" : score >= 50 ? "average" : "poor";
}

async function syncPerformanceIssues(websiteId: string, strategy: Strategy, parsed: ReturnType<typeof parsePageSpeed>) {
  const now = new Date();
  const upsert = async (fingerprint: string, issue: { severity: string; title: string; description: string } | null, evidence: Json) => {
    if (issue) {
      await db.issue.upsert({
        where: { websiteId_fingerprint: { websiteId, fingerprint } },
        create: { websiteId, fingerprint, source: "pagespeed", ...issue, evidence: evidence as Prisma.InputJsonValue },
        update: { ...issue, status: "open", resolvedAt: null, lastSeenAt: now, evidence: evidence as Prisma.InputJsonValue },
      });
    } else {
      await db.issue.updateMany({ where: { websiteId, fingerprint, status: { in: ["open", "acknowledged"] } }, data: { status: "resolved", resolvedAt: now, lastSeenAt: now } });
    }
  };
  const band = scoreBand(parsed.score);
  const top = parsed.opportunities.slice(0, 3).map((item) => item.title.toLowerCase()).join(", ");
  await upsert(`perf:score:${strategy}`, band === "poor" || band === "average" ? {
    severity: band === "poor" ? "medium" : "low",
    title: `${band === "poor" ? "Poor" : "Low"} ${strategy} performance score: ${parsed.score}/100`,
    description: `PageSpeed Insights scores this site ${parsed.score}/100 on ${strategy}.${top ? ` Main causes: ${top}.` : ""} Open the website's Performance tab for the full diagnosis and one-click fixes.`,
  } : null, { strategy, score: parsed.score, metrics: parsed.metrics });
  if (strategy === "mobile" && parsed.field) {
    for (const key of ["lcp", "inp", "cls"] as const) {
      const metric = parsed.field.metrics[key];
      const poor = metric && metric.category === "SLOW";
      const value = metric ? key === "cls" ? metric.p75.toFixed(2) : `${Math.round(metric.p75)} ms` : "";
      await upsert(`perf:field:${key}`, poor ? { severity: "medium", title: `Real visitors see a poor ${metric.label} (${value})`, description: `Chrome users' 75th percentile ${metric.label} is ${value}, rated poor by Google. This is a Core Web Vital and affects search ranking.` } : null, { metric: key, field: metric ?? null });
    }
  }
}

/** Run mobile and desktop tests in parallel and store both. */
export async function runPerformanceTest(websiteId: string, fetcher: typeof fetch = fetch) {
  const website = await db.website.findUnique({ where: { id: websiteId }, select: { id: true, url: true, organizationId: true, wordpressAgent: { select: { diagnostics: true } } } });
  if (!website) throw new PageSpeedError("Website not found.", 404);
  const { pagespeedKey } = await getIntegrations(website.organizationId);
  const results = await Promise.all((["mobile", "desktop"] as const).map(async (strategy) => {
    try {
      const parsed = parsePageSpeed(await fetchPageSpeed(website.url, strategy, pagespeedKey, fetcher), website.wordpressAgent?.diagnostics);
      await db.performanceReport.create({ data: { websiteId, strategy, url: website.url, score: parsed.score, metrics: parsed.metrics as Prisma.InputJsonValue, field: (parsed.field ?? undefined) as Prisma.InputJsonValue | undefined, opportunities: parsed.opportunities as unknown as Prisma.InputJsonValue } });
      await syncPerformanceIssues(websiteId, strategy, parsed);
      return { strategy, score: parsed.score, error: null };
    } catch (error) {
      const message = error instanceof Error ? error.message : "PageSpeed test failed.";
      await db.performanceReport.create({ data: { websiteId, strategy, url: website.url, score: null, metrics: {}, opportunities: [], error: message.slice(0, 500) } });
      return { strategy, score: null, error: message };
    }
  }));
  return results;
}

/** Re-test sites whose last test is older than a week (daily cron, within a time budget). */
export async function runDuePerformanceTests(budgetMs = 60_000) {
  const started = Date.now();
  const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60_000);
  const sites = await db.website.findMany({ where: { environmentType: "production", performanceReports: { none: { createdAt: { gte: weekAgo } } } }, select: { id: true, organizationId: true }, take: 5 });
  let tested = 0;
  for (const site of sites) {
    if (Date.now() - started > budgetMs) break;
    if (!(await getIntegrations(site.organizationId)).pagespeedKey) continue;
    await runPerformanceTest(site.id);
    tested += 1;
  }
  return { tested };
}

/** The measures to apply for the selected opportunities (deduplicated, in a sensible order). */
export function measuresFor(opportunities: Array<{ fix: PerformanceMeasure | null }>) {
  const wanted = new Set(opportunities.map((item) => item.fix).filter((fix): fix is PerformanceMeasure => Boolean(fix)));
  return PERFORMANCE_MEASURE_IDS.filter((id) => wanted.has(id));
}
