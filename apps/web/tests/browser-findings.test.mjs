import test from "node:test";
import assert from "node:assert/strict";
import { groupSiteWideFindings, isLegacyPerPageFingerprint, siteWideBrowserKind, siteWideFindingCleared } from "../lib/browser-findings.ts";

const at = (kind, pageKey, page, severity = "medium", title = "Links must have discernible text") => ({
  fingerprint: `browser:${kind}:${pageKey}`,
  title,
  severity,
  description: "Rule description.",
  evidence: { pageUrl: `https://example.com/${page}`, viewport: { width: 390, height: 844 } },
});

test("a rule seen on several pages becomes one issue listing the pages", () => {
  const grouped = groupSiteWideFindings([
    at("accessibility-link-name", "8a5edab28263", "", "high"),
    at("accessibility-link-name", "e445df49f687", "about"),
    at("accessibility-link-name", "dd834186dfd9", "contact"),
    at("console-error", "8a5edab28263", "", "medium", "Browser console errors were reported"),
  ]);
  assert.equal(grouped.length, 2);
  const links = grouped.find((item) => item.fingerprint === "browser:accessibility-link-name:site");
  assert.ok(links);
  assert.equal(links.severity, "high");
  assert.equal(links.title, "Links must have discernible text (3 pages)");
  assert.deepEqual(links.evidence.pageKeys, ["8a5edab28263", "e445df49f687", "dd834186dfd9"]);
  assert.equal(links.evidence.pageCount, 3);
  assert.equal(links.evidence.pageUrl, "https://example.com/");
  assert.match(links.description, /Seen on 3 pages:\n- https:\/\/example.com\/\n- https:\/\/example.com\/about/);
  const consoleError = grouped.find((item) => item.fingerprint === "browser:console-error:site");
  assert.equal(consoleError.title, "Browser console errors were reported");
});

test("findings repaired page by page keep their own fingerprint", () => {
  const perPage = [
    at("horizontal-overflow", "8a5edab28263", ""),
    at("horizontal-overflow", "e445df49f687", "about"),
    at("broken-link:0123456789abcdef", "8a5edab28263", ""),
    at("link-redirect:0123456789abcdef", "8a5edab28263", ""),
    at("page-http-error", "e445df49f687", "about"),
  ];
  assert.deepEqual(groupSiteWideFindings(perPage).map((item) => item.fingerprint), perPage.map((item) => item.fingerprint));
});

test("legacy per-page copies of grouped rules are recognised", () => {
  assert.equal(siteWideBrowserKind("browser:accessibility-color-contrast:8a5edab28263"), "accessibility-color-contrast");
  assert.equal(isLegacyPerPageFingerprint("browser:accessibility-color-contrast:8a5edab28263"), true);
  assert.equal(isLegacyPerPageFingerprint("browser:accessibility-color-contrast:site"), false);
  assert.equal(isLegacyPerPageFingerprint("browser:horizontal-overflow:8a5edab28263"), false);
  assert.equal(isLegacyPerPageFingerprint("browser:broken-link:0123456789abcdef:8a5edab28263"), false);
  assert.equal(isLegacyPerPageFingerprint("security:sitemap-spam"), false);
});

test("a site-wide finding clears when most of its pages were rescanned without it", () => {
  const keys = Array.from({ length: 23 }, (_, index) => index.toString(16).padStart(12, "0"));
  // One page that never completes in every viewport must not keep a fixed issue open.
  assert.equal(siteWideFindingCleared(keys, new Set(keys.slice(1))), true);
  assert.equal(siteWideFindingCleared(keys, new Set(keys.slice(0, 19))), true);
  assert.equal(siteWideFindingCleared(keys, new Set(keys.slice(0, 18))), false);
  // Small sets still need (almost) every page: 1 of 1, 4 of 5.
  assert.equal(siteWideFindingCleared(keys.slice(0, 1), new Set()), false);
  assert.equal(siteWideFindingCleared(keys.slice(0, 1), new Set(keys.slice(0, 1))), true);
  assert.equal(siteWideFindingCleared(keys.slice(0, 5), new Set(keys.slice(0, 3))), false);
  assert.equal(siteWideFindingCleared(keys.slice(0, 5), new Set(keys.slice(0, 4))), true);
  assert.equal(siteWideFindingCleared(undefined, new Set(keys)), false);
  assert.equal(siteWideFindingCleared([], new Set(keys)), false);
});
