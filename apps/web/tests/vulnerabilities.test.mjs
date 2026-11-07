import test from "node:test";
import assert from "node:assert/strict";
import { matchVulnerabilities, parseFeed, versionInRange } from "../lib/vulnerabilities.ts";
import { fixPlanForIssue } from "../lib/cleanup-plan.ts";

const feed = {
  "a1b2": { id: "a1b2", title: "Elementor <= 4.3.5 - Authenticated Arbitrary File Upload", cve: "CVE-2026-0001", cvss: { score: 8.8, rating: "High" }, references: ["https://example.test/a1b2"],
    software: [{ type: "plugin", slug: "elementor", affected_versions: { "* - 4.3.5": { from_version: "*", from_inclusive: true, to_version: "4.3.5", to_inclusive: true } }, patched: true, patched_versions: ["4.3.6"] }] },
  "c3d4": { id: "c3d4", title: "Slider Revolution <= 6.8.1 - Unauthenticated RCE", cvss: { score: 9.8, rating: "Critical" },
    software: [{ type: "plugin", slug: "revslider", affected_versions: { "* - 6.8.1": { from_version: "*", from_inclusive: true, to_version: "6.8.1", to_inclusive: true } }, patched: false, patched_versions: [] }] },
  "e5f6": { id: "e5f6", title: "Yoast SEO 20.0 - 20.2 XSS", cvss: { score: 6.1, rating: "Medium" },
    software: [{ type: "plugin", slug: "wordpress-seo", affected_versions: { "20.0 - 20.2": { from_version: "20.0", from_inclusive: true, to_version: "20.2", to_inclusive: true } }, patched: true, patched_versions: ["20.3"] }] },
  "g7h8": { id: "g7h8", title: "Unrelated plugin", software: [{ type: "plugin", slug: "not-installed", affected_versions: { "*": { from_version: "*", to_version: "*" } } }] },
};
const diagnostics = {
  site: { wpVersion: "7.1.4" },
  plugins: [
    { name: "Elementor", version: "4.3.5", file: "elementor/elementor.php", active: true, updateAvailable: true, source: "wordpress.org", newVersion: "4.3.6" },
    { name: "Slider Revolution", version: "6.8.1", file: "revslider/revslider.php", active: true, updateAvailable: false, source: "other" },
    { name: "Yoast SEO", version: "28.8", file: "wordpress-seo/wp-seo.php", active: true, updateAvailable: false, source: "wordpress.org" },
  ],
};

test("the feed is reduced to installed software and matched by version range", () => {
  const wanted = new Set(["plugin:elementor", "plugin:revslider", "plugin:wordpress-seo", "core:wordpress"]);
  const parsed = parseFeed(feed, wanted);
  assert.equal(parsed.total, 4);
  assert.deepEqual(Object.keys(parsed.bySlug).sort(), ["plugin:elementor", "plugin:revslider", "plugin:wordpress-seo"]);
  const findings = matchVulnerabilities(parsed, diagnostics);
  assert.deepEqual(findings.map((finding) => [finding.fingerprint, finding.severity]), [["vuln:plugin-elementor:a1b2", "high"], ["vuln:plugin-revslider:c3d4", "critical"]]);
  assert.match(findings[0].description, /Fixed in version 4\.3\.6\. The available update \(4\.3\.6\) includes the fix/);
  assert.match(findings[1].description, /No fixed version/);
});

test("version ranges honour inclusive and exclusive bounds", () => {
  const range = { from: "1.2", fromInclusive: false, to: "2.0", toInclusive: false };
  assert.equal(versionInRange("1.2", range), false);
  assert.equal(versionInRange("1.2.1", range), true);
  assert.equal(versionInRange("2.0", range), false);
  assert.equal(versionInRange("10.0", { from: "*", fromInclusive: true, to: "9.9", toInclusive: true }), false);
});

test("a vulnerability fix updates when the patched version is offered, otherwise quarantines", () => {
  const parsed = parseFeed(feed, new Set(["plugin:elementor", "plugin:revslider"]));
  const [elementor, revslider] = matchVulnerabilities(parsed, diagnostics);
  const update = fixPlanForIssue(elementor.fingerprint, { ...diagnostics, __issueEvidence: elementor.evidence });
  assert.deepEqual(update.steps.map((step) => step.operation), ["update_plugin"]);
  const remove = fixPlanForIssue(revslider.fingerprint, { ...diagnostics, __issueEvidence: revslider.evidence });
  assert.deepEqual(remove.steps.map((step) => [step.operation, step.parameters.plugin]), [["quarantine_plugin", "revslider/revslider.php"]]);
});

test("an unrecognized feed yields no entries", () => {
  assert.equal(parseFeed({ unexpected: true }, new Set(["plugin:elementor"])).total, 0);
  assert.equal(parseFeed([], new Set()).total, 0);
});
