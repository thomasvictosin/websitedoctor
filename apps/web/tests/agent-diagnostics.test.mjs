import test from "node:test";
import assert from "node:assert/strict";
import { agentDiagnosticSchema } from "../lib/agent-diagnostics.ts";

const sample = {
  collectedAt: "2026-11-03T10:00:00.000Z",
  site: {
    wpVersion: "6.8",
    phpVersion: "8.3",
    memoryLimit: "256M",
    debugMode: false,
    cronDisabled: false,
    overdueCronCount: 0,
    activeTheme: { name: "Fixture", version: "1.0", stylesheet: "fixture" },
  },
  plugins: [{ name: "Fixture", version: "1.0", file: "fixture/fixture.php", active: true, updateAvailable: false }],
  phpErrors: [],
  phpErrorLog: { collectionEnabled: false, status: "disabled", observedCount: 0, limit: 20 },
  settings: { blogname: "Test site", blogdescription: "Fixture" },
  issues: [{ fingerprint: "wp-cron-disabled", title: "WP-Cron is disabled", description: "Configure a scheduler.", severity: "medium" },
    { fingerprint: "php-fatal:plugin-a", title: "Fatal error in Plugin A", description: "Fatal error evidence from an explicitly collected log excerpt.", severity: "critical" }],
};

test("accepts bounded WordPress diagnostics containing known findings", () => {
  assert.equal(agentDiagnosticSchema.safeParse(sample).success, true);
});

test("accepts WordPress RFC 3339 timestamps with an explicit UTC offset", () => {
  const timestamp = "2026-11-03T10:00:00+00:00";
  assert.equal(agentDiagnosticSchema.safeParse({
    ...sample,
    collectedAt: timestamp,
    scheduledTasks: [{
      id: "scheduled-task",
      hook: "wp_scheduled_task",
      scheduledAt: timestamp,
      overdue: false,
      status: "pending",
      lastStartedAt: timestamp,
      lastCompletedAt: null,
      failure: null,
    }],
  }).success, true);
});

test("accepts a healthy PHP evidence control and rejects unbounded or malformed PHP log evidence", () => {
  assert.equal(agentDiagnosticSchema.safeParse({ ...sample, phpErrors: [], phpErrorLog: { collectionEnabled: true, status: "readable", observedCount: 0, limit: 20 } }).success, true);
  assert.equal(agentDiagnosticSchema.safeParse({ ...sample, phpErrors: Array.from({ length: 21 }, (_, index) => ({ id: index.toString(16).padStart(32, "0"), level: "warning", message: "Warning", file: "plugin.php", line: 4 })) }).success, false);
});

test("rejects malformed dates, unsafe fingerprints, unsupported severities, and oversized diagnostic data", () => {
  assert.equal(agentDiagnosticSchema.safeParse({ ...sample, collectedAt: "yesterday" }).success, false);
  assert.equal(agentDiagnosticSchema.safeParse({ ...sample, issues: [{ ...sample.issues[0], fingerprint: "../wp-config.php" }] }).success, false);
  assert.equal(agentDiagnosticSchema.safeParse({ ...sample, issues: [{ ...sample.issues[0], severity: "urgent" }] }).success, false);
  assert.equal(agentDiagnosticSchema.safeParse({ ...sample, authorizedLogExcerpt: "x".repeat(16_385) }).success, false);
  assert.equal(agentDiagnosticSchema.safeParse({ ...sample, plugins: Array.from({ length: 501 }, () => sample.plugins[0]) }).success, false);
});
