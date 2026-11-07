import test from "node:test";
import assert from "node:assert/strict";
import { awdCustomRules, awdRateLimitRule, mergeRules, zoneCandidates } from "../lib/cloudflare.ts";
import { runSecurityProbe } from "../lib/security-probe.ts";

test("edge rules cover uploads PHP, sensitive files, fake crawlers on protected paths and attack tools", () => {
  const [block, challenge] = awdCustomRules({ blockXmlrpc: true });
  assert.equal(block.action, "block");
  assert.match(block.expression, /starts_with\(lower\(http\.request\.uri\.path\), "\/wp-content\/uploads\/"\)/);
  assert.match(block.expression, /"\/wp-config\.php"/);
  assert.match(block.expression, /"\/xmlrpc\.php"/);
  assert.match(block.expression, /not cf\.client\.bot and \(http\.request\.uri\.path in \{"\/wp-login\.php" "\/xmlrpc\.php"\}/, "crawler identity is judged only on protected paths, so the outside check keeps working");
  assert.equal(challenge.action, "managed_challenge");
  assert.ok(!awdCustomRules({ blockXmlrpc: false })[0].expression.includes('"/xmlrpc.php" "'), "xmlrpc is not in the sensitive file list without blockXmlrpc");
  assert.deepEqual(awdRateLimitRule().ratelimit, { characteristics: ["cf.colo.id", "ip.src"], period: 10, requests_per_period: 5, mitigation_timeout: 10 });
  // Balanced parentheses: a malformed expression would be rejected by Cloudflare.
  for (const rule of [block, challenge, awdRateLimitRule()]) {
    let depth = 0;
    for (const character of rule.expression) { depth += character === "(" ? 1 : character === ")" ? -1 : 0; assert.ok(depth >= 0); }
    assert.equal(depth, 0, rule.description);
  }
});

test("merging keeps the owner's rules and replaces only the app's", () => {
  const existing = [
    { id: "1", version: "3", description: "Owner: block a country", action: "block", expression: "(ip.geoip.country eq \"XX\")" },
    { id: "2", description: "AWD: old rule", action: "block", expression: "(true)" },
  ];
  const merged = mergeRules(existing, awdCustomRules({ blockXmlrpc: true }));
  assert.equal(merged.length, 3);
  assert.deepEqual(merged[0], { description: "Owner: block a country", action: "block", expression: "(ip.geoip.country eq \"XX\")" });
  assert.ok(!merged.some((rule) => rule.description === "AWD: old rule"));
  assert.deepEqual(mergeRules(existing, []).map((rule) => rule.description), ["Owner: block a country"]);
});

test("zone candidates walk up the host name", () => {
  assert.deepEqual(zoneCandidates("www.shop.example.co.uk"), ["www.shop.example.co.uk", "shop.example.co.uk", "example.co.uk", "co.uk"]);
  assert.deepEqual(zoneCandidates("avantgardian.com"), ["avantgardian.com"]);
});

test("an edge challenge makes the outside check inconclusive instead of clean", async () => {
  const request = async () => ({ statusCode: 403, headers: { "cf-mitigated": "challenge", "content-type": "text/html" }, body: Buffer.from("<html><title>Just a moment...</title></html>") });
  const result = await runSecurityProbe("https://fixture.example/", { request });
  assert.ok(!result.completedChecks.includes("homepage"));
  assert.deepEqual(result.findings, []);
  assert.ok(result.errors.some((error) => /edge challenge/.test(error)));
});
