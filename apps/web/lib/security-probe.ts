import { createHash } from "node:crypto";
import http, { type IncomingHttpHeaders } from "node:http";
import https from "node:https";
import { brotliDecompressSync, gunzipSync, inflateSync } from "node:zlib";
import { assertSafeTarget, pinnedLookup, resolvePublicAddresses } from "./monitor.ts";

/**
 * Compromise detector that needs only plain HTTP (no browser runtime), so it
 * also runs on serverless deployments. It looks for the signatures of SEO-spam
 * compromises that a normal availability check misses: a page that answers
 * 200 but differs completely for search-engine crawlers ("cloaking"), visitors
 * arriving from search being redirected elsewhere, an empty 200 home page,
 * and robots.txt/sitemap files that advertise injected spam URLs.
 *
 * Crawler impersonation uses the User-Agent only. Malware that verifies
 * crawlers by reverse DNS will not be revealed by this probe, so a clean
 * result is "not observed", never "proven clean".
 */

export type ProbeProfile = "browser" | "googlebot" | "search_referral";

export type ProbeSample = {
  profile: ProbeProfile;
  requestedUrl: string;
  statusCode: number | null;
  finalUrl: string | null;
  redirectedOffOrigin: boolean;
  bodyBytes: number;
  bodySha256: string | null;
  title: string | null;
  cjkRatio: number;
  wordpressMarkers: number;
  error: string | null;
};

export type SecurityFinding = {
  fingerprint: string;
  check: SecurityCheck;
  title: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  evidence: Record<string, unknown>;
};

export type SecurityCheck = "homepage" | "robots" | "sitemap";

export type SecurityProbeResult = {
  checkedAt: string;
  url: string;
  samples: ProbeSample[];
  robots: { statusCode: number | null; sitemapEntries: string[]; error: string | null } | null;
  sitemap: SitemapSummary | null;
  spamPageSamples: Array<{ url: string; browser: ProbeSample; googlebot: ProbeSample }>;
  /** Checks that produced enough evidence to also confirm the absence of their findings. */
  completedChecks: SecurityCheck[];
  findings: SecurityFinding[];
  errors: string[];
  limitations: string[];
};

export type SitemapSummary = {
  fetched: string[];
  urlCount: number;
  truncated: boolean;
  dominantSegment: string | null;
  dominantSegmentCount: number;
  randomSlugCount: number;
  exampleUrls: string[];
};

type RawResponse = { statusCode: number; headers: IncomingHttpHeaders; body: Buffer };
export type ProbeRequester = (url: URL, headers: Record<string, string>) => Promise<RawResponse>;

const MAX_BODY_BYTES = 3 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 15_000;
const MAX_SITEMAP_FETCHES = 5;
const MAX_SITEMAP_URLS = 5_000;

const BROWSER_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
const GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

export const PROFILE_HEADERS: Record<ProbeProfile, Record<string, string>> = {
  browser: { "user-agent": BROWSER_UA, accept: "text/html,application/xhtml+xml" },
  googlebot: { "user-agent": GOOGLEBOT_UA, accept: "text/html,application/xhtml+xml" },
  search_referral: { "user-agent": BROWSER_UA, accept: "text/html,application/xhtml+xml", referer: "https://www.google.com/" },
};

async function defaultRequester(url: URL, headers: Record<string, string>): Promise<RawResponse> {
  assertSafeTarget(url);
  const addresses = await resolvePublicAddresses(url.hostname);
  const transport = url.protocol === "https:" ? https : http;
  return new Promise((resolve, reject) => {
    const request = transport.request(url, {
      method: "GET",
      headers: { ...headers, "accept-encoding": "gzip, deflate, br" },
      timeout: REQUEST_TIMEOUT_MS,
      lookup: pinnedLookup(addresses),
    }, (response) => {
      const chunks: Buffer[] = [];
      let size = 0;
      response.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          response.destroy();
          resolve({ statusCode: response.statusCode ?? 0, headers: response.headers, body: Buffer.concat(chunks) });
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => resolve({ statusCode: response.statusCode ?? 0, headers: response.headers, body: Buffer.concat(chunks) }));
      response.on("error", reject);
    });
    request.on("timeout", () => request.destroy(new Error("Request timed out.")));
    request.on("error", reject);
    request.end();
  });
}

function decodeBody(response: RawResponse): string {
  const encoding = String(response.headers["content-encoding"] ?? "").toLowerCase();
  try {
    if (encoding.includes("br")) return brotliDecompressSync(response.body).toString("utf8");
    if (encoding.includes("gzip")) return gunzipSync(response.body).toString("utf8");
    if (encoding.includes("deflate")) return inflateSync(response.body).toString("utf8");
  } catch {
    // A truncated compressed body cannot be decoded; analyze what is readable.
  }
  return response.body.toString("utf8");
}

/** GET that follows at most five redirects, re-validating each hop. */
async function fetchText(rawUrl: string, headers: Record<string, string>, request: ProbeRequester) {
  let target = new URL(rawUrl);
  const origin = target.origin;
  for (let hop = 0; hop <= 5; hop += 1) {
    const response = await request(target, headers);
    const location = response.headers.location;
    if (response.statusCode >= 300 && response.statusCode < 400 && location) {
      const next = new URL(location, target);
      if (next.origin !== origin) {
        // Never follow a redirect off the site: record where it pointed.
        return { statusCode: response.statusCode, finalUrl: next.toString(), redirectedOffOrigin: true, text: "" };
      }
      target = next;
      continue;
    }
    return { statusCode: response.statusCode, finalUrl: target.toString(), redirectedOffOrigin: false, text: decodeBody(response) };
  }
  throw new Error("Too many redirects.");
}

const CJK = /[぀-ヿ㐀-䶿一-鿿가-힯]/g;
const LETTER = /\p{L}/gu;

function decodeEntities(value: string): string {
  return value
    .replace(/&#(\d+);/g, (_, code) => String.fromCodePoint(Number(code)))
    .replace(/&#x([0-9a-f]+);/gi, (_, code) => String.fromCodePoint(Number.parseInt(code, 16)))
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"").replace(/&#39;|&apos;/g, "'")
    .replace(/&[a-z]+;/gi, " ");
}

export function summarizeHtml(html: string) {
  const titleMatch = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  const title = titleMatch ? decodeEntities(titleMatch[1]).replace(/\s+/g, " ").trim().slice(0, 200) : null;
  const visible = decodeEntities(html.slice(0, 200_000)
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " "));
  const letters = visible.match(LETTER)?.length ?? 0;
  const cjk = visible.match(CJK)?.length ?? 0;
  return {
    title: title || null,
    cjkRatio: letters >= 20 ? Math.round((cjk / letters) * 100) / 100 : 0,
    wordpressMarkers: (html.match(/\/wp-(?:content|includes)\//g) ?? []).length,
  };
}

async function sample(url: string, profile: ProbeProfile, request: ProbeRequester): Promise<ProbeSample> {
  try {
    const response = await fetchText(url, PROFILE_HEADERS[profile], request);
    const body = response.text;
    const trimmed = body.trim();
    return {
      profile,
      requestedUrl: url,
      statusCode: response.statusCode,
      finalUrl: response.finalUrl,
      redirectedOffOrigin: response.redirectedOffOrigin,
      bodyBytes: Buffer.byteLength(trimmed),
      bodySha256: trimmed ? createHash("sha256").update(trimmed).digest("hex") : null,
      ...summarizeHtml(body),
      error: null,
    };
  } catch (error) {
    return {
      profile, requestedUrl: url, statusCode: null, finalUrl: null, redirectedOffOrigin: false,
      bodyBytes: 0, bodySha256: null, title: null, cjkRatio: 0, wordpressMarkers: 0,
      error: error instanceof Error ? error.message.slice(0, 300) : "Request failed.",
    };
  }
}

function normalizedTitle(title: string | null) {
  return (title ?? "").toLowerCase().replace(/[^\p{L}\p{N}]+/gu, " ").trim();
}

function isSuccess(sampleValue: ProbeSample) {
  return sampleValue.statusCode !== null && sampleValue.statusCode >= 200 && sampleValue.statusCode < 300;
}

/** Signals that two responses for the same URL are materially different pages. */
export function contentDivergence(reference: ProbeSample, crawler: ProbeSample): string[] {
  const signals: string[] = [];
  if (!isSuccess(crawler) || crawler.bodyBytes < 1024) return signals;
  if (!isSuccess(reference)) signals.push(`visitors get HTTP ${reference.statusCode ?? "error"} while the crawler gets HTTP ${crawler.statusCode}`);
  if (reference.bodyBytes < 512) signals.push(`visitors get an empty page (${reference.bodyBytes} bytes) while the crawler gets ${crawler.bodyBytes} bytes`);
  const refTitle = normalizedTitle(reference.title);
  const crawlerTitle = normalizedTitle(crawler.title);
  if (crawlerTitle && refTitle !== crawlerTitle) signals.push(`page title differs ("${reference.title ?? "none"}" vs "${crawler.title}")`);
  if (Math.abs(crawler.cjkRatio - reference.cjkRatio) >= 0.3) signals.push(`page language differs (CJK share ${reference.cjkRatio} vs ${crawler.cjkRatio})`);
  if (reference.bodyBytes >= 512) {
    const ratio = crawler.bodyBytes / reference.bodyBytes;
    if (ratio > 3 || ratio < 1 / 3) signals.push(`page size differs (${reference.bodyBytes} vs ${crawler.bodyBytes} bytes)`);
  }
  if (reference.wordpressMarkers > 0 && crawler.wordpressMarkers === 0) signals.push("crawler page contains no WordPress theme or plugin assets");
  return signals;
}

export function analyzeHomepage(samples: ProbeSample[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const browser = samples.find((item) => item.profile === "browser");
  const googlebot = samples.find((item) => item.profile === "googlebot");
  const referral = samples.find((item) => item.profile === "search_referral");
  if (!browser || !googlebot || !referral) return findings;
  const evidence = { samples };

  const divergence = contentDivergence(browser, googlebot);
  // A title change alone can be legitimate (A/B tests, consent pages); require corroboration.
  const strong = divergence.some((signal) => /empty page|HTTP|language|WordPress/.test(signal));
  if (divergence.length >= 2 && (strong || divergence.length >= 3)) {
    findings.push({
      fingerprint: "security:cloaking",
      check: "homepage",
      severity: "critical",
      title: "Search engines are shown a different website (cloaking)",
      description: `The home page served to Googlebot is a different page from the one served to visitors: ${divergence.join("; ")}. This is the signature of an SEO-spam compromise that injects pages only crawlers see. Treat the site as compromised: check core-file integrity, unknown PHP files and .htaccess on the server, then clean and rescan.`,
      evidence: { ...evidence, signals: divergence },
    });
  }

  if (referral.redirectedOffOrigin && !browser.redirectedOffOrigin) {
    findings.push({
      fingerprint: "security:search-redirect",
      check: "homepage",
      severity: "critical",
      title: "Visitors arriving from search are redirected to another site",
      description: `A visitor arriving from Google is redirected to ${referral.finalUrl}, but a direct visitor is not. This conditional redirect is a common malware behavior. Treat the site as compromised.`,
      evidence,
    });
  }

  if (isSuccess(browser) && browser.bodyBytes < 256) {
    findings.push({
      fingerprint: "security:blank-homepage",
      check: "homepage",
      severity: "high",
      title: "Home page is blank for visitors",
      description: `The home page answers HTTP ${browser.statusCode} but returns ${browser.bodyBytes} bytes of content, so visitors see an empty page while an availability check reports the site as up. Typical causes are a suppressed PHP fatal error, a broken theme template, or an index.php replaced by malware.`,
      evidence,
    });
  }
  return findings;
}

export function analyzeRobots(text: string, origin: string): { sitemapEntries: string[]; findings: SecurityFinding[] } {
  const sitemapEntries = [...text.matchAll(/^\s*sitemap\s*:\s*(\S+)/gim)].map((match) => match[1]).slice(0, 200);
  const numbered = sitemapEntries.filter((entry) => /sitemap[-_]?\d+\.xml/i.test(entry));
  const offOrigin = sitemapEntries.filter((entry) => {
    try { return new URL(entry).origin !== origin; } catch { return true; }
  });
  const findings: SecurityFinding[] = [];
  if (numbered.length >= 5 || offOrigin.length > 0) {
    findings.push({
      fingerprint: "security:robots-sitemaps",
      check: "robots",
      severity: "high",
      title: "robots.txt advertises unexpected sitemaps",
      description: `robots.txt lists ${sitemapEntries.length} sitemap entries${numbered.length ? `, including ${numbered.length} numbered sitemap files` : ""}${offOrigin.length ? ` and ${offOrigin.length} on another domain` : ""}. WordPress and SEO plugins normally advertise one sitemap index. Spam injections rewrite robots.txt so search engines index injected pages.`,
      evidence: { sitemapEntries: sitemapEntries.slice(0, 40), numberedCount: numbered.length, offOrigin: offOrigin.slice(0, 10) },
    });
  }
  return { sitemapEntries, findings };
}

/** A slug that looks machine-generated: long, alphanumeric, mixing digits and letters, no word separators. */
export function isRandomSlug(segment: string) {
  return (/^[a-z0-9]{10,}$/i.test(segment) && /\d/.test(segment) && /[a-z]/i.test(segment)) || /^\d{10,}$/.test(segment);
}

export function analyzeSitemapUrls(urls: string[], origin: string, fetched: string[], truncated: boolean): { summary: SitemapSummary; findings: SecurityFinding[] } {
  const segments = new Map<string, { count: number; random: number; examples: string[] }>();
  let randomSlugCount = 0;
  for (const raw of urls) {
    let url: URL;
    try { url = new URL(raw); } catch { continue; }
    if (url.origin !== origin) continue;
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length === 0) continue;
    const segment = parts.length > 1 ? parts[0] : "/";
    const last = parts.at(-1)!;
    const entry = segments.get(segment) ?? { count: 0, random: 0, examples: [] };
    entry.count += 1;
    if (isRandomSlug(last)) { entry.random += 1; randomSlugCount += 1; if (entry.examples.length < 5) entry.examples.push(url.toString()); }
    segments.set(segment, entry);
  }
  const [dominantSegment, dominant] = [...segments.entries()].sort((a, b) => b[1].random - a[1].random)[0] ?? [null, null];
  const summary: SitemapSummary = {
    fetched,
    urlCount: urls.length,
    truncated,
    dominantSegment: dominant && dominant.random > 0 ? dominantSegment : null,
    dominantSegmentCount: dominant?.random ?? 0,
    randomSlugCount,
    exampleUrls: dominant?.examples ?? [],
  };
  const findings: SecurityFinding[] = [];
  if (dominant && dominant.random >= 50 && dominant.random / Math.max(urls.length, 1) >= 0.5) {
    findings.push({
      fingerprint: "security:sitemap-spam",
      check: "sitemap",
      severity: "high",
      title: "Sitemap is dominated by machine-generated URLs",
      description: `${dominant.random} of ${urls.length}${truncated ? "+" : ""} sitemap URLs are random-looking slugs under "${dominantSegment === "/" ? "/" : `/${dominantSegment}/`}" (for example ${dominant.examples[0]}). Legitimate WordPress content uses readable slugs; this pattern is typical of injected spam pages.`,
      evidence: { sitemap: summary },
    });
  }
  return { summary, findings };
}

function extractLocs(xml: string) {
  return [...xml.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((match) => decodeEntities(match[1]));
}

export async function runSecurityProbe(rawUrl: string, injected?: { request?: ProbeRequester }): Promise<SecurityProbeResult> {
  const request = injected?.request ?? defaultRequester;
  const target = new URL(rawUrl);
  assertSafeTarget(target);
  const origin = target.origin;
  const home = target.toString();
  const errors: string[] = [];
  const completedChecks: SecurityCheck[] = [];
  const findings: SecurityFinding[] = [];

  const samples: ProbeSample[] = [];
  for (const profile of ["browser", "googlebot", "search_referral"] as const) samples.push(await sample(home, profile, request));
  if (samples.every((item) => item.error === null)) completedChecks.push("homepage");
  else errors.push(...samples.filter((item) => item.error).map((item) => `${item.profile} home page: ${item.error}`));
  findings.push(...analyzeHomepage(samples));

  let robots: SecurityProbeResult["robots"] = null;
  let sitemapCandidates = ["/sitemap_index.xml", "/wp-sitemap.xml", "/sitemap.xml"].map((path) => new URL(path, origin).toString());
  try {
    const response = await fetchText(new URL("/robots.txt", origin).toString(), PROFILE_HEADERS.googlebot, request);
    if (response.statusCode >= 200 && response.statusCode < 300) {
      const analyzed = analyzeRobots(response.text, origin);
      robots = { statusCode: response.statusCode, sitemapEntries: analyzed.sitemapEntries.slice(0, 40), error: null };
      findings.push(...analyzed.findings);
      const advertised = analyzed.sitemapEntries.filter((entry) => { try { return new URL(entry).origin === origin; } catch { return false; } });
      sitemapCandidates = [...new Set([...advertised.slice(0, 2), ...sitemapCandidates])];
    } else {
      robots = { statusCode: response.statusCode, sitemapEntries: [], error: null };
    }
    completedChecks.push("robots");
  } catch (error) {
    const message = error instanceof Error ? error.message.slice(0, 300) : "Request failed.";
    robots = { statusCode: null, sitemapEntries: [], error: message };
    errors.push(`robots.txt: ${message}`);
  }

  let sitemap: SitemapSummary | null = null;
  const spamPageSamples: SecurityProbeResult["spamPageSamples"] = [];
  const urls: string[] = [];
  const fetched: string[] = [];
  const queue = [...sitemapCandidates];
  let sitemapReadable = false;
  while (queue.length && fetched.length < MAX_SITEMAP_FETCHES && urls.length < MAX_SITEMAP_URLS) {
    const next = queue.shift()!;
    if (fetched.includes(next)) continue;
    fetched.push(next);
    try {
      const response = await fetchText(next, PROFILE_HEADERS.googlebot, request);
      if (response.statusCode < 200 || response.statusCode >= 300 || !/<(urlset|sitemapindex)\b/i.test(response.text)) continue;
      sitemapReadable = true;
      const locs = extractLocs(response.text);
      if (/<sitemapindex\b/i.test(response.text)) {
        queue.unshift(...locs.filter((loc) => { try { return new URL(loc).origin === origin; } catch { return false; } }).slice(0, 3));
        continue;
      }
      urls.push(...locs.slice(0, MAX_SITEMAP_URLS - urls.length));
      // Several candidate paths often alias the same generated sitemap.
      if (urls.length >= 200) break;
    } catch (error) {
      errors.push(`sitemap ${new URL(next).pathname}: ${error instanceof Error ? error.message.slice(0, 200) : "unavailable"}`);
    }
  }
  if (sitemapReadable) {
    const analyzed = analyzeSitemapUrls([...new Set(urls)], origin, fetched, urls.length >= MAX_SITEMAP_URLS);
    sitemap = analyzed.summary;
    completedChecks.push("sitemap");
    const spam = analyzed.findings[0];
    if (spam) {
      // Confirm with two pages: injected pages typically exist only for crawlers.
      for (const url of analyzed.summary.exampleUrls.slice(0, 2)) {
        spamPageSamples.push({ url, browser: await sample(url, "browser", request), googlebot: await sample(url, "googlebot", request) });
      }
      const crawlerOnly = spamPageSamples.filter((item) => contentDivergence(item.browser, item.googlebot).length > 0);
      if (crawlerOnly.length > 0) {
        spam.severity = "critical";
        spam.title = "Spam pages are served only to search engines";
        spam.description += ` Confirmed: ${crawlerOnly.length} sampled URL(s) return a full page to Googlebot but ${crawlerOnly.map((item) => `HTTP ${item.browser.statusCode ?? "error"}/${item.browser.bodyBytes} bytes`).join(", ")} to visitors.`;
      }
      spam.evidence = { ...spam.evidence, spamPageSamples };
    }
    findings.push(...analyzed.findings);
  }

  return {
    checkedAt: new Date().toISOString(),
    url: home,
    samples,
    robots,
    sitemap,
    spamPageSamples,
    completedChecks,
    findings,
    errors,
    limitations: [
      "Crawler requests impersonate Googlebot by User-Agent only; malware that verifies crawlers by reverse DNS can hide from this probe.",
      `At most ${MAX_SITEMAP_FETCHES} sitemap files and ${MAX_SITEMAP_URLS} URLs are inspected.`,
    ],
  };
}
