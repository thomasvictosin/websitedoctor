import test from "node:test";
import assert from "node:assert/strict";
import { analyzeRobots, analyzeSitemapUrls, contentDivergence, isRandomSlug, runSecurityProbe } from "../lib/security-probe.ts";
import { deterministicIssueRecommendation } from "../lib/repair-policy.ts";

const ORIGIN = "https://fixture.example";
const realPage = `<!doctype html><html><head><title>Fixture Builders | Sustainable homes</title>
<link rel="stylesheet" href="/wp-content/themes/fixture/style.css"></head>
<body><h1>Fixture Builders</h1><p>${"We design and build sustainable homes. ".repeat(60)}</p>
<script src="/wp-includes/js/jquery.js"></script></body></html>`;
const spamPage = `<!doctype html><html><head><title>サッカー・フットサル 実使用ハット 送料無料</title></head>
<body>${"<div>激安 通販 送料無料 正規品 新品 未使用 人気 ブランド 限定 セール</div>".repeat(200)}</body></html>`;
const spamSlugs = Array.from({ length: 120 }, (_, index) => `${(0x5a3c00000000 + index * 7919).toString(16)}${index}`);

function response(statusCode, body, headers = {}) {
  return { statusCode, headers: { "content-type": "text/html", ...headers }, body: Buffer.from(body) };
}

/** Fake HTTP layer: `compromised` reproduces a cloaked Japanese-keyword-hack site. */
function site({ compromised }) {
  const requests = [];
  const request = async (url, headers) => {
    requests.push({ url: url.toString(), headers });
    const crawler = /Googlebot/.test(headers["user-agent"] ?? "");
    if (url.pathname === "/robots.txt") {
      const lines = ["User-agent: *", "Allow: /"];
      if (compromised) for (let index = 1; index <= 19; index += 1) lines.push(`Sitemap: ${ORIGIN}/sitemap-${index}.xml`);
      else lines.push(`Sitemap: ${ORIGIN}/sitemap_index.xml`);
      return response(200, lines.join("\n"), { "content-type": "text/plain" });
    }
    if (/sitemap/.test(url.pathname)) {
      const locs = compromised
        ? [`${ORIGIN}/`, ...spamSlugs.map((slug) => `${ORIGIN}/dp/${slug}`)]
        : [`${ORIGIN}/`, `${ORIGIN}/about-us/`, `${ORIGIN}/projects/green-roof-retrofit/`, `${ORIGIN}/2026/10/autumn-update/`];
      return response(200, `<?xml version="1.0"?><urlset>${locs.map((loc) => `<url><loc>${loc}</loc></url>`).join("")}</urlset>`, { "content-type": "application/xml" });
    }
    if (url.pathname.startsWith("/dp/")) return compromised && crawler ? response(200, spamPage) : response(404, "");
    if (url.pathname === "/") return compromised ? response(200, crawler ? spamPage : "") : response(200, realPage);
    return response(404, "");
  };
  return { request, requests };
}

test("detects cloaking, blank home page, robots.txt sitemap injection and crawler-only spam pages", async () => {
  const fake = site({ compromised: true });
  const result = await runSecurityProbe(`${ORIGIN}/`, { request: fake.request });
  const byFingerprint = new Map(result.findings.map((finding) => [finding.fingerprint, finding]));
  assert.deepEqual([...result.completedChecks].sort(), ["homepage", "robots", "sitemap"]);
  assert.equal(byFingerprint.get("security:cloaking")?.severity, "critical");
  assert.equal(byFingerprint.get("security:blank-homepage")?.severity, "high");
  assert.equal(byFingerprint.get("security:robots-sitemaps")?.severity, "high");
  const sitemap = byFingerprint.get("security:sitemap-spam");
  assert.equal(sitemap?.severity, "critical", "spam confirmed on sampled URLs escalates to critical");
  assert.match(sitemap.title, /only to search engines/);
  assert.equal(result.sitemap.dominantSegment, "dp");
  assert.equal(result.spamPageSamples.length, 2);
  assert.ok(fake.requests.length <= 15, "probe must stay within its request budget");
});

test("healthy site produces no findings and completes every check", async () => {
  const fake = site({ compromised: false });
  const result = await runSecurityProbe(`${ORIGIN}/`, { request: fake.request });
  assert.deepEqual(result.findings, []);
  assert.deepEqual([...result.completedChecks].sort(), ["homepage", "robots", "sitemap"]);
});

test("search-referrer redirect off the site is reported and never followed", async () => {
  const requests = [];
  const request = async (url, headers) => {
    requests.push(url.toString());
    if (url.pathname === "/" && headers.referer) return { statusCode: 302, headers: { location: "https://scam.example/shop" }, body: Buffer.alloc(0) };
    if (url.pathname === "/") return response(200, realPage);
    return response(404, "");
  };
  const result = await runSecurityProbe(`${ORIGIN}/`, { request });
  const finding = result.findings.find((item) => item.fingerprint === "security:search-redirect");
  assert.equal(finding?.severity, "critical");
  assert.ok(!requests.some((url) => url.startsWith("https://scam.example")), "off-site redirect targets must not be fetched");
});

test("network failures leave checks incomplete instead of reporting a clean result", async () => {
  const result = await runSecurityProbe(`${ORIGIN}/`, { request: async () => { throw new Error("connect ECONNREFUSED"); } });
  assert.deepEqual(result.findings, []);
  assert.deepEqual(result.completedChecks, []);
  assert.ok(result.errors.length >= 3);
});

test("a title change alone is not treated as cloaking", () => {
  const base = { requestedUrl: `${ORIGIN}/`, finalUrl: `${ORIGIN}/`, redirectedOffOrigin: false, bodySha256: "x", error: null, statusCode: 200, cjkRatio: 0, wordpressMarkers: 4 };
  const signals = contentDivergence({ ...base, profile: "browser", bodyBytes: 40_000, title: "Home | Fixture" }, { ...base, profile: "googlebot", bodyBytes: 41_000, title: "Fixture Builders" });
  assert.equal(signals.length, 1);
});

test("robots and sitemap heuristics", () => {
  assert.equal(analyzeRobots(`Sitemap: ${ORIGIN}/sitemap_index.xml`, ORIGIN).findings.length, 0);
  assert.equal(analyzeRobots(`Sitemap: https://elsewhere.example/sitemap.xml`, ORIGIN).findings.length, 1);
  assert.ok(isRandomSlug("d94f80947299") && isRandomSlug("070573807700"));
  assert.ok(!isRandomSlug("green-roof-retrofit") && !isRandomSlug("about") && !isRandomSlug("2026"));
  const readable = Array.from({ length: 300 }, (_, index) => `${ORIGIN}/blog/post-number-${index}/`);
  assert.equal(analyzeSitemapUrls(readable, ORIGIN, [], false).findings.length, 0);
});

test("compromise findings get cleanup guidance, never an executable operation", () => {
  for (const fingerprint of ["security:cloaking", "wp:integrity:core-modified", "wp:integrity:uploads-php"]) {
    const recommendation = deterministicIssueRecommendation({ fingerprint, title: "t", description: "d" }, {});
    const text = JSON.stringify(recommendation);
    assert.match(text, /backup/i, `${fingerprint} guidance starts from a backup`);
    assert.match(text, /salts/i, `${fingerprint} guidance includes credential rotation`);
    assert.equal(recommendation.executableOperation ?? recommendation.recommendation?.executableOperation ?? null, null);
  }
});
