import test from "node:test";
import assert from "node:assert/strict";
import { matchVulnerabilities, parseFeed, severityFor, versionInRange } from "../lib/vulnerabilities.ts";
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
  assert.deepEqual(findings.map((finding) => [finding.fingerprint, finding.severity]), [["vuln:plugin-elementor:known", "high"], ["vuln:plugin-revslider:known", "critical"]]);
  assert.match(findings[0].description, /Version 4\.3\.6 or later fixes it\. The available update \(4\.3\.6\) includes the fix/);
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

const range = (to, inclusive = false) => ({ [`* - ${to}`]: { from_version: "*", from_inclusive: true, to_version: to, to_inclusive: inclusive } });
const scannerFeed = {
  d1: { id: "d1", title: "Duplicator <= 1.5.17 and Duplicator Pro <= 4.6.10 - Unauthenticated PHP Object Injection", cvss: null, software: [{ type: "plugin", slug: "duplicator-pro", affected_versions: range("4.6.10", true), patched_versions: ["4.6.11"] }] },
  d2: { id: "d2", title: "Duplicator < 5.1.0 - Reflected Cross-Site Scripting", software: [{ type: "plugin", slug: "duplicator-pro", affected_versions: range("5.1.0"), patched_versions: ["5.1.0"] }] },
  d3: { id: "d3", title: "Duplicator < 5.1.0 - Unauthenticated Full Path Disclosure", software: [{ type: "plugin", slug: "duplicator-pro", affected_versions: range("5.1.0"), patched_versions: ["5.1.0"] }] },
  d4: { id: "d4", title: "Duplicator Pro < 5.1.0 - Authenticated (Subscriber+) SQL Injection", software: [{ type: "plugin", slug: "duplicator-pro", affected_versions: range("5.1.0"), patched_versions: ["5.1.0"] }] },
  s1: { id: "s1", title: "Superfly Responsive Menu <= 5.0.25 - Authenticated (Subscriber+) Stored Cross-Site Scripting", software: [{ type: "plugin", slug: "superfly-menu", affected_versions: range("5.0.25", true), patched_versions: ["5.0.26"] }] },
  s2: { id: "s2", title: "Superfly Responsive Menu <= 5.0.29 - Cross-Site Request Forgery to Arbitrary File Deletion", software: [{ type: "plugin", slug: "superfly-menu", affected_versions: range("5.0.29", true), patched_versions: [] }] },
};
const premium = { plugins: [
  { name: "Duplicator Pro", version: "4.5.17.3", file: "duplicator-pro/duplicator-pro.php", source: "other" },
  { name: "Superfly Menu", version: "5.0.24", file: "superfly-menu/main.php", source: "other" },
] };

test("each plugin gets one issue that lists all its vulnerabilities", () => {
  const findings = matchVulnerabilities(parseFeed(scannerFeed, new Set(["plugin:duplicator-pro", "plugin:superfly-menu"])), premium);
  assert.deepEqual(findings.map((finding) => finding.fingerprint), ["vuln:plugin-duplicator-pro:known", "vuln:plugin-superfly-menu:known"]);
  const [duplicator, superfly] = findings;
  assert.equal(duplicator.title, "Duplicator Pro 4.5.17.3 has 4 known vulnerabilities");
  assert.equal(duplicator.severity, "high", "unauthenticated object injection is the worst of the four");
  assert.equal(duplicator.evidence.count, 4);
  assert.equal(duplicator.evidence.fixedIn, "5.1.0", "the version that fixes all of them");
  assert.equal(duplicator.evidence.vulnerabilities[0].id, "d1", "worst first");
  assert.match(duplicator.description, /Version 5\.1\.0 or later fixes all 4\. Get it from the vendor/);
  assert.equal(superfly.evidence.fixedIn, null, "one of them has no fix yet");
  assert.equal(superfly.evidence.partialFix, "5.0.26");
  assert.equal(superfly.severity, "high");
});

test("without a CVSS score the severity is estimated from the vulnerability type", () => {
  const estimate = (title) => severityFor({ title, cvss: null, rating: null }).severity;
  assert.equal(estimate("X <= 1.0 - Unauthenticated Remote Code Execution"), "critical");
  assert.equal(estimate("X <= 1.0 - Unauthenticated SQL Injection"), "high");
  assert.equal(estimate("X <= 1.0 - Authenticated (Subscriber+) SQL Injection"), "medium");
  assert.equal(estimate("X <= 1.0 - Authenticated (Contributor+) Privilege Escalation"), "high");
  assert.equal(estimate("X <= 1.0 - Authenticated (Administrator+) Arbitrary File Upload"), "medium");
  assert.equal(estimate("X <= 1.0 - Reflected Cross-Site Scripting"), "medium");
  assert.equal(estimate("WordPress Core - All Known Versions - Cleartext Storage of wp_signups.activation_key"), "low");
  assert.deepEqual(severityFor({ title: "Unauthenticated Remote Code Execution", cvss: 5.4, rating: "Medium" }), { severity: "medium", estimated: false }, "a real score wins");
});
