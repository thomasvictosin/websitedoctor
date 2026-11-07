import test from "node:test";
import assert from "node:assert/strict";
import { buildCleanupPlan, cleanupStepSchema, cleanupStepsDigest, compareVersions, fetchOfficialChecksums, isAllowedCleanupStep, selectCleanupSteps } from "../lib/cleanup-plan.ts";

const NOW = new Date("2026-11-07T17:00:00Z");
const h = (character) => character.repeat(64);
const official = { "index.php": "a".repeat(32), "wp-includes/version.php": "b".repeat(32), "wp-admin/about.php": "c".repeat(32) };

function diagnostics(overrides = {}) {
  return {
    collectedAt: NOW.toISOString(),
    site: { pluginVersion: "0.3.0", wpVersion: "7.1.4" },
    plugins: [
      { name: "WP File Manager", version: "8.0.6", file: "wp-file-manager/file_folder_manager.php", active: true, updateAvailable: true },
      { name: "Yoast SEO", version: "28.8", file: "wordpress-seo/wp-seo.php", active: true, updateAvailable: false },
    ],
    integrity: {
      scannedAt: new Date(NOW.getTime() - 5 * 60_000).toISOString(),
      status: "complete",
      core: { version: "7.1.4", locale: "en_US", checksumsAvailable: true, checkedFiles: 3, modified: ["index.php"], missing: [], unknownPhp: ["wp-includes/class-wp-cache-loader.php", "wp-l0gin.php"] },
      rootUnknownFiles: ["sitemap-1.xml", "sitemap-2.xml", "google1234.html", "README.md"],
      uploadsPhp: ["wp-content/uploads/2026/11/thumb.php"],
      muPlugins: [],
      contentRootPhp: [],
      suspiciousFiles: [
        { path: "index.php", signatures: ["eval_encoded_payload"] },
        { path: "wp-content/themes/bauen-child/functions.php", signatures: ["request_code_execution"] },
        { path: "wp-content/uploads/2026/11/thumb.php", signatures: ["request_code_execution"] },
      ],
      htaccess: { present: true, bytes: 300, sha256: h("d"), hasWordPressBlock: true, suspiciousLines: [{ line: 2, reason: "crawler_condition", text: "RewriteCond %{HTTP_USER_AGENT} google" }, { line: 3, reason: "rewrite_to_non_wordpress_script", text: "RewriteRule ^(.*)$ wp-cache.php [L]" }] },
      robotsFile: { present: true, bytes: 1035, sitemapEntries: 21 },
      admins: { count: 2, recent: [{ login: "wpsupport", registeredAt: "2026-11-01T09:00:00+00:00" }] },
      fileHashes: {
        "index.php": h("1"), "wp-includes/class-wp-cache-loader.php": h("2"), "wp-l0gin.php": h("3"), "wp-content/uploads/2026/11/thumb.php": h("4"),
        "robots.txt": h("5"), "sitemap-1.xml": h("6"), "sitemap-2.xml": h("7"), "wp-content/themes/bauen-child/functions.php": h("8"),
      },
      truncated: false,
      ...overrides.integrity,
    },
    ...overrides.root,
  };
}
const issues = [
  { fingerprint: "security:cloaking", severity: "critical", title: "Cloaking" },
  { fingerprint: "security:robots-sitemaps", severity: "high", title: "robots" },
  { fingerprint: "wp:plugin-update:abc", severity: "low", title: "update" },
];

test("builds the full playbook for a cloaked SEO-spam compromise", () => {
  const plan = buildCleanupPlan({ diagnostics: diagnostics(), openIssues: issues, officialChecksums: official, now: NOW });
  assert.deepEqual(plan.blockers, []);
  const byOperation = (operation) => plan.steps.filter((step) => step.operation === operation);
  assert.deepEqual(byOperation("quarantine_file").map((step) => step.parameters.path).sort(), [
    "robots.txt", "sitemap-1.xml", "sitemap-2.xml", "wp-content/uploads/2026/11/thumb.php", "wp-includes/class-wp-cache-loader.php", "wp-l0gin.php",
  ]);
  assert.deepEqual(byOperation("restore_core_file").map((step) => step.parameters), [{ path: "index.php", officialMd5: "a".repeat(32), expectedCurrentSha256: h("1") }]);
  assert.deepEqual(byOperation("remove_htaccess_rules")[0].parameters, { expectedSha256: h("d"), lines: "2,3" });
  assert.equal(plan.steps.at(-2).operation, "rotate_salts");
  assert.equal(plan.steps.at(-1).operation, "purge_page_cache");
  assert.ok(plan.steps.every((step) => cleanupStepSchema.safeParse(step).success && isAllowedCleanupStep(step)));
  assert.ok(!plan.steps.some((step) => step.parameters.path === "index.php" && step.operation === "quarantine_file"), "core files are restored, never quarantined");
  assert.ok(plan.manual.some((item) => item.includes("bauen-child/functions.php") && /Reinstall/.test(item)), "theme code goes to manual reinstall");
  assert.ok(!plan.steps.some((step) => step.parameters.path?.startsWith("wp-content/themes/")));
  assert.deepEqual(plan.optional.map((item) => item.id), ["plugin:wp-file-manager/file_folder_manager.php", "admin:wpsupport"]);
  assert.ok(!plan.steps.some((step) => step.operation === "quarantine_plugin" || step.operation === "demote_user"), "risky removals are never preselected");
  assert.match(plan.planDigest, /^[a-f0-9]{64}$/);
});

test("optional items run before salt rotation; unknown ids are rejected", () => {
  const plan = buildCleanupPlan({ diagnostics: diagnostics(), openIssues: issues, officialChecksums: official, now: NOW });
  const steps = selectCleanupSteps(plan, ["admin:wpsupport"]);
  const demote = steps.findIndex((step) => step.operation === "demote_user");
  assert.ok(demote > 0 && demote < steps.findIndex((step) => step.operation === "rotate_salts"));
  assert.throws(() => selectCleanupSteps(plan, ["admin:someone-else"]), /Unknown optional/);
  assert.notEqual(cleanupStepsDigest(steps), cleanupStepsDigest(plan.steps));
});

test("the plan digest changes when any reviewed file content changes", () => {
  const first = buildCleanupPlan({ diagnostics: diagnostics(), openIssues: issues, officialChecksums: official, now: NOW });
  const changed = diagnostics();
  changed.integrity.fileHashes["wp-l0gin.php"] = h("9");
  const second = buildCleanupPlan({ diagnostics: changed, openIssues: issues, officialChecksums: official, now: NOW });
  assert.notEqual(first.planDigest, second.planDigest);
  assert.equal(buildCleanupPlan({ diagnostics: diagnostics(), openIssues: issues, officialChecksums: official, now: NOW }).planDigest, first.planDigest);
});

test("blocks on an old plugin, a missing or stale integrity scan", () => {
  const old = buildCleanupPlan({ diagnostics: diagnostics({ root: { site: { pluginVersion: "0.2.0" } } }), openIssues: issues, officialChecksums: official, now: NOW });
  assert.ok(old.blockers.some((blocker) => blocker.includes("0.3.0")));
  const stale = buildCleanupPlan({ diagnostics: diagnostics({ integrity: { scannedAt: "2026-11-07T15:00:00Z" } }), openIssues: issues, officialChecksums: official, now: NOW });
  assert.ok(stale.blockers.some((blocker) => /30 minutes/.test(blocker)));
  const missing = buildCleanupPlan({ diagnostics: { site: { pluginVersion: "0.1.0" }, plugins: [] }, openIssues: issues, officialChecksums: null, now: NOW });
  assert.ok(missing.blockers.some((blocker) => /integrity scan/.test(blocker)));
});

test("without official checksums, core files become manual guidance", () => {
  const plan = buildCleanupPlan({ diagnostics: diagnostics(), openIssues: issues, officialChecksums: null, now: NOW });
  assert.ok(!plan.steps.some((step) => step.operation === "restore_core_file"));
  assert.ok(plan.manual.some((item) => /Re-install/.test(item)));
});

test("a clean site gets no steps", () => {
  const clean = diagnostics({ integrity: { core: { version: "7.1.4", locale: "en_US", checksumsAvailable: true, checkedFiles: 3, modified: [], missing: [], unknownPhp: [] }, rootUnknownFiles: [], uploadsPhp: [], suspiciousFiles: [], htaccess: { present: true, suspiciousLines: [] }, robotsFile: { present: false }, admins: { count: 1, recent: [] } } });
  clean.plugins = [];
  const plan = buildCleanupPlan({ diagnostics: clean, openIssues: [], officialChecksums: official, now: NOW });
  assert.deepEqual(plan.steps, []);
  assert.match(plan.summary, /No compromise evidence/);
});

test("step validation rejects traversal, absolute paths and unknown operations", () => {
  for (const step of [
    { operation: "quarantine_file", parameters: { path: "../wp-config.php", expectedSha256: h("a") } },
    { operation: "quarantine_file", parameters: { path: "/etc/passwd", expectedSha256: h("a") } },
    { operation: "restore_core_file", parameters: { path: "wp-content/x.php", officialMd5: "a".repeat(32), expectedCurrentSha256: h("a") } },
    { operation: "quarantine_plugin", parameters: { plugin: "ai-website-doctor/ai-website-doctor.php", expectedVersion: "1" } },
    { operation: "run_shell", parameters: {} },
    { operation: "rotate_salts", parameters: { extra: "1" } },
  ]) assert.equal(isAllowedCleanupStep(step), false, JSON.stringify(step));
});

test("version comparison and checksum fetch", async () => {
  assert.ok(compareVersions("0.3.0", "0.2.9") > 0 && compareVersions("0.3", "0.3.0") === 0 && compareVersions("0.10.0", "0.3.0") > 0);
  const urls = [];
  const checksums = Object.fromEntries(Array.from({ length: 150 }, (_, index) => [`wp-includes/file-${index}.php`, "e".repeat(32)]));
  const fetcher = async (url) => { urls.push(url); return url.includes("locale=de_DE") ? new Response("false", { status: 200 }) : Response.json({ checksums }); };
  const result = await fetchOfficialChecksums("7.1.4", "de_DE", fetcher);
  assert.equal(Object.keys(result).length, 150);
  assert.deepEqual(urls.map((url) => new URL(url).searchParams.get("locale")), ["de_DE", "en_US"]);
  assert.equal(await fetchOfficialChecksums("not a version", "en_US", fetcher), null);
});
