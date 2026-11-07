import test from "node:test";
import assert from "node:assert/strict";
import {
  deriveEvidenceSignals,
  selectEvidenceForAnalysis,
  selectRelevantTools,
} from "../lib/ai/tool-registry.ts";
import { determineRepairRisk, determineSeverity } from "../lib/ai/policy.ts";
import { analyzeFindingWithEngine } from "../lib/ai/finding-analysis.ts";

test("central tool selection uses the evidence that is actually present", () => {
  const availability = selectRelevantTools(deriveEvidenceSignals("availability_check", {
    available: false,
    statusCode: 503,
  }));
  assert.deepEqual(availability.map((tool) => tool.id), ["http_availability"]);

  const wordpress = selectRelevantTools(deriveEvidenceSignals("wordpress_agent", {
    site: { wpVersion: "6.x", cronDisabled: true },
    plugins: [{ active: true }],
    authorizedLogExcerpt: "PHP warning",
  }, {
    fingerprint: "wp-cron-disabled",
    title: "WP-Cron disabled",
    description: "Scheduled events are not running.",
  }));
  assert.deepEqual(wordpress.map((tool) => tool.id), [
    "wordpress_configuration",
    "wordpress_cron",
  ]);
  assert.equal(wordpress.some((tool) => tool.id === "http_availability"), false);

  const pluginIssue = selectRelevantTools(deriveEvidenceSignals("wordpress_agent", {
    plugins: [{ name: "Example", updateAvailable: true }],
  }, {
    fingerprint: "plugin-update:abc",
    title: "Plugin update available",
    description: "An update is available for this plugin.",
  }));
  assert.deepEqual(pluginIssue.map((tool) => tool.id), ["wordpress_plugin_inventory"]);
});

test("browser monitor evidence selects browser diagnostics and is forwarded to central AI", async () => {
  const evidence = { browser: { finding: { ruleId: "image-alt", pageUrl: "https://fixture.example/" }, metrics: { firstContentfulPaintMs: 320 } }, collectedAt: "2026-01-01T00:00:00Z" };
  const finding = { fingerprint: "browser:accessibility-image-alt:abc", title: "Images need alternative text", description: "axe-core reported image-alt." };
  const tools = selectRelevantTools(deriveEvidenceSignals("browser_monitor", evidence, finding)).map(({ id }) => id);
  assert.deepEqual(tools, ["browser_diagnostics"]);
  const selected = selectEvidenceForAnalysis("browser_monitor", evidence, tools, finding);
  assert.deepEqual(selected.browser, evidence.browser);
  let received;
  const result = await analyzeFindingWithEngine({ async diagnose(input) { received = input; return { severity: "medium", confidence: 0.8, evidenceReferences: [{ id: "E1", path: "browser.finding.ruleId", value: "image-alt" }] }; } }, {
    website: { name: "Fixture", url: "https://fixture.example/" }, source: "browser_monitor", finding: { ...finding, severity: "medium" }, evidence,
  });
  assert.equal(received.evidence.browser.finding.ruleId, "image-alt");
  assert.equal(result.aiStatus, "completed");
});

test("central analysis sends only evidence relevant to the finding", () => {
  const finding = {
    fingerprint: "wp-cron-disabled",
    title: "WP-Cron disabled",
    description: "Scheduled events are not running.",
  };
  const evidence = {
    collectedAt: "2026-01-01T00:00:00Z",
    site: { wpVersion: "6.x", cronDisabled: true },
    plugins: [{ name: "Unrelated plugin" }],
    authorizedLogExcerpt: "Unrelated log entry",
    centralAvailability: { available: true, statusCode: 200 },
  };
  const toolIds = selectRelevantTools(
    deriveEvidenceSignals("wordpress_agent", evidence, finding),
  ).map((tool) => tool.id);
  const selected = selectEvidenceForAnalysis("wordpress_agent", evidence, toolIds, finding);

  assert.deepEqual(Object.keys(selected).sort(), [
    "centralAvailability",
    "collectedAt",
    "cron",
    "finding",
    "site",
  ]);
  assert.equal("plugins" in selected, false);
  assert.equal("authorizedLogExcerpt" in selected, false);
});

test("PHP log findings select bounded structured log evidence without unrelated inventories", () => {
  const finding = { fingerprint: "wp:php-log:0123456789abcdef0123456789abcdef", title: "PHP Warning recorded in WordPress debug log", description: "Undefined array key (plugin.php:42)" };
  const phpErrors = [{ id: "0123456789abcdef0123456789abcdef", level: "warning", message: "Undefined array key", file: "plugin.php", line: 42 }];
  const evidence = { site: { phpVersion: "8.3" }, plugins: [{ name: "Unrelated" }], phpErrors, phpErrorLog: { collectionEnabled: true, status: "readable", observedCount: 1, limit: 20 } };
  const tools = selectRelevantTools(deriveEvidenceSignals("wordpress_agent", evidence, finding)).map(({ id }) => id);
  assert.ok(tools.includes("wordpress_authorized_logs"));
  const selected = selectEvidenceForAnalysis("wordpress_agent", evidence, tools, finding);
  assert.deepEqual(selected.phpErrors, phpErrors);
  assert.equal(selected.phpErrorLog.status, "readable");
  assert.equal("plugins" in selected, false);
});

test("central AI receives relevant evidence and the stored diagnosis cites that evidence", async () => {
  let received;
  const diagnosis = { severity: "medium", confidence: 0.9, evidenceReferences: [{ id: "E1", path: "cron.cronDisabled", value: true }] };
  const result = await analyzeFindingWithEngine({ async diagnose(input) { received = input; return diagnosis; } }, {
    website: { name: "Fixture", url: "https://fixture.example/" },
    source: "wordpress_agent",
    finding: { fingerprint: "wp-cron-disabled", title: "WP-Cron disabled", description: "Events may not run.", severity: "medium" },
    evidence: { site: { cronDisabled: true, overdueCronCount: 7 }, plugins: [{ name: "Unrelated" }] },
  });
  assert.equal(received.evidence.cron.cronDisabled, true);
  assert.equal("plugins" in received.evidence, false);
  assert.equal(result.aiStatus, "completed");
  assert.equal(result.diagnosis.evidenceReferences[0].value, true);
});

test("AI unavailability preserves deterministic evidence severity and returns no diagnosis", async () => {
  const result = await analyzeFindingWithEngine({ async diagnose() { throw new Error("Model endpoint unavailable."); } }, {
    website: { name: "Fixture", url: "https://fixture.example/" },
    source: "wordpress_agent",
    finding: { fingerprint: "wp-cron-disabled", title: "WP-Cron disabled", description: "Events may not run.", severity: "high" },
    evidence: { site: { cronDisabled: true } },
  });
  assert.equal(result.aiStatus, "unavailable");
  assert.equal(result.diagnosis, null);
  assert.equal(result.severity, "high");
  assert.match(result.aiError, /unavailable/i);
});

test("severity policy preserves observed severity and prioritizes central availability failures", () => {
  assert.equal(determineSeverity("critical", "low", "wordpress_agent"), "critical");
  assert.equal(determineSeverity("low", "critical", "wordpress_agent"), "critical");
  assert.equal(determineSeverity("low", "low", "availability_check"), "high");
});

test("repair risk is centrally bounded by operation impact", () => {
  assert.equal(determineRepairRisk(["clear_cache"]), "high");
  assert.equal(determineRepairRisk(["update_setting"]), "medium");
  assert.equal(determineRepairRisk(["disable_plugin"]), "high");
  assert.equal(determineRepairRisk([]), "high");
  assert.equal(determineRepairRisk(["run_shell"]), "high");
});
