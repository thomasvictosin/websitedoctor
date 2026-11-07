import test from "node:test";
import assert from "node:assert/strict";
import {
  boundedRepairPlan,
  deriveRepairStatus,
  evidenceBackedRepairs,
  repairInstructionsSchema,
  repairRiskForOperations,
  requiresRecoveryPoint,
} from "../lib/repair-policy.ts";
import { verifyBrowserConflictRepair, verifyBrowserLayoutRepair, verifyRecoveryState, verifyRepairEvidence } from "../lib/repair-verification.ts";
import { parseAssistantRepairPermissionCommand } from "../lib/repair-assistant-intent.ts";
import { categoryIssueIds, hasExplicitBroadRepairScope, isDiagnosisOnlyPrompt, promptExplicitlyAuthorizesRepair, promptNamesPage, validateIssueCategoryScope, validateRepairRequestScope } from "../lib/repair-request-scope.ts";
import { createHash } from "node:crypto";
import { hasExpiredRepairGrant, matchRepairGrant, repairOperationDigest } from "../lib/repair-grant-policy.ts";
import { redactApiValue } from "../lib/redaction.ts";
import { validateWordPressRecoverySnapshot } from "../lib/wordpress-recovery-snapshot.ts";

test("assistant permission changes require an explicit low-risk operation instruction", () => {
  assert.equal(parseAssistantRepairPermissionCommand("Enable automatic repair for broken internal links"), "enable_broken_link_automation");
  assert.equal(parseAssistantRepairPermissionCommand("Please disable automatic broken-link repairs"), "disable_broken_link_automation");
  assert.equal(parseAssistantRepairPermissionCommand("Enable automatic repairs"), null);
  assert.equal(parseAssistantRepairPermissionCommand("Automatically deactivate plugins"), null);
  assert.equal(parseAssistantRepairPermissionCommand("Tell me about automatic repair options for broken links"), null);
});

test("prompt repair scope keeps diagnosis and recommendations non-executing and bounds batch intent", () => {
  assert.equal(isDiagnosisOnlyPrompt("Diagnose the checkout issue and explain why it happens"), true);
  assert.equal(promptExplicitlyAuthorizesRepair("Diagnose the checkout issue and explain why it happens"), false);
  assert.equal(promptExplicitlyAuthorizesRepair("Fix the broken internal link on the pricing page"), true);
  assert.equal(validateRepairRequestScope("Fix the broken link", "repair_one", ["issue-1", "issue-2"]), "A single-issue repair request must identify exactly one issue.");
  assert.match(validateRepairRequestScope("Fix these", "repair_multiple", ["issue-1", "issue-2"]), /explicit category, batch, or all\/every scope/);
  assert.equal(hasExplicitBroadRepairScope("Fix all broken links"), true);
  assert.equal(validateRepairRequestScope("Fix all broken links", "repair_multiple", ["issue-1", "issue-2"]), null);
  assert.equal(validateRepairRequestScope("Recommend a fix for the checkout issue", "recommend", ["issue-1"]), null);
  const issues = [
    { id: "link-1", fingerprint: "browser:broken-link:abc", title: "Broken link", description: "A pricing link returns 404." },
    { id: "a11y-1", fingerprint: "browser:accessibility-image-alt:abc", title: "Missing image alt text", description: "An image has no accessible name." },
  ];
  assert.deepEqual([...categoryIssueIds("Fix all broken links", issues)], ["link-1"]);
  assert.equal(validateIssueCategoryScope("Fix all broken links", ["link-1"], issues), true);
  assert.equal(validateIssueCategoryScope("Fix all broken links", ["link-1", "a11y-1"], issues), false);
  assert.equal(promptNamesPage("Fix the issue on /pricing", "https://example.test/pricing"), true);
  assert.equal(promptNamesPage("Fix the issue on the homepage", "https://example.test/pricing"), false);
});

test("repair grants expire, bind to unchanged proposals, and cannot be replayed or borrowed across batch items", () => {
  const now = new Date("2026-11-05T12:00:00.000Z");
  const proposal = { instructions: { steps: [{ operation: "replace_post_link", parameters: { postId: "42", linkUrl: "https://example.test/old" } }] } };
  const digest = repairOperationDigest(proposal, ["replace_post_link"]);
  const grant = {
    id: "grant-a",
    authorizationMethod: "batch",
    expiresAt: new Date(now.getTime() + 60_000),
    consumedAt: null,
    decision: "authorized",
    batchId: "batch-a",
    executionWebsiteId: "site-a",
    executionIssueId: "issue-a",
    executionProposalId: "repair-a",
  };
  const matches = (overrides = {}) => matchRepairGrant([grant], {
    now, websiteId: "site-a", issueId: "issue-a", repairId: "repair-a", batchId: "batch-a", consume: true, ...overrides,
  });

  assert.equal(matches()?.id, "grant-a");
  assert.equal(matches({ now: new Date(now.getTime() + 60_000) }), undefined);
  assert.equal(hasExpiredRepairGrant([grant], new Date(now.getTime() + 60_000)), true);
  assert.equal(matches({ grantId: "different-grant" }), undefined);
  assert.equal(matches({ batchId: "different-batch" }), undefined);
  assert.equal(matches({ websiteId: "site-b" }), undefined);
  assert.equal(matches({ issueId: "issue-b" }), undefined);
  assert.equal(matches({ repairId: "repair-b" }), undefined);
  assert.equal(matchRepairGrant([grant], { now, websiteId: "site-a", issueId: "issue-a", repairId: "repair-a", batchId: null }), undefined);

  const consumed = { ...grant, consumedAt: new Date(now.getTime() - 1) };
  assert.equal(matchRepairGrant([consumed], { now, websiteId: "site-a", issueId: "issue-a", repairId: "repair-a", batchId: "batch-a", consume: true }), undefined);
  assert.equal(repairOperationDigest({ instructions: { steps: [{ operation: "replace_post_link", parameters: { linkUrl: "https://example.test/old", postId: "42" } }] } }, ["replace_post_link"]), digest);
  assert.notEqual(repairOperationDigest({ ...proposal, instructions: { steps: [{ operation: "replace_post_link", parameters: { postId: "99", linkUrl: "https://example.test/other" } }] } }, ["replace_post_link"]), digest);
  assert.notEqual(repairOperationDigest(proposal, ["disable_plugin"]), digest);
});

test("authorization grant IDs remain available to executors while other auth values are redacted", () => {
  const payload = {
    tasks: [{
      authorizationGrantId: "grant_123",
      authorizationExpiresAt: "2026-11-05T12:30:00.000Z",
      authorizationMethod: "individual",
      authorization: "Bearer secret-token",
      nested: { authorization: "top-secret" },
    }],
  };
  const redacted = redactApiValue(payload);
  assert.equal(redacted.tasks[0].authorizationGrantId, "grant_123");
  assert.equal(redacted.tasks[0].authorizationExpiresAt, "2026-11-05T12:30:00.000Z");
  assert.equal(redacted.tasks[0].authorizationMethod, "individual");
  assert.equal(redacted.tasks[0].authorization, "******");
  assert.equal(redacted.tasks[0].nested.authorization, "******");
});

test("repair risk and recovery requirements are deterministic", () => {
  assert.equal(repairRiskForOperations(["clear_cache"]), "high");
  assert.equal(repairRiskForOperations(["update_setting"]), "medium");
  assert.equal(repairRiskForOperations(["disable_plugin"]), "high");
  assert.equal(repairRiskForOperations(["arbitrary_code"]), "high");
  assert.equal(requiresRecoveryPoint(["clear_cache"]), true);
  assert.equal(requiresRecoveryPoint(["update_setting"]), true);
});

test("WordPress recovery snapshots are bound to the exact approved operation and target", () => {
  const snapshot = {
    id: "backup-123",
    created_at: "2026-11-05T12:00:00.000Z",
    description: "Repair snapshot",
    complete: true,
    operations: [{
      operation: "update_setting",
      target: "blogname",
      before: "Old name",
      after: "New name",
      applied: false,
    }],
  };
  const expected = {
    backupId: "backup-123",
    repairOperation: "update_setting",
    repairParameters: { option: "blogname", expectedCurrentValue: "Old name", value: "New name" },
  };
  assert.equal(validateWordPressRecoverySnapshot({ ...expected, snapshot }).ok, true);
  assert.equal(validateWordPressRecoverySnapshot({ ...expected, backupId: "different-id", snapshot }).ok, false);
  assert.equal(validateWordPressRecoverySnapshot({
    ...expected,
    repairParameters: { ...expected.repairParameters, option: "blogdescription" },
    snapshot,
  }).ok, false);
  assert.equal(validateWordPressRecoverySnapshot({
    ...expected,
    snapshot: { ...snapshot, operations: [{ ...snapshot.operations[0], applied: true }] },
  }).ok, false);

  const cssBefore = "body { color: #222; }\n";
  const cssAfter = `${cssBefore}\n/* AI Website Doctor approved staging width repair */\nbody.page-id-25 #wide-image { max-width: 100%; }\n`;
  const cssSnapshot = {
    ...snapshot,
    operations: [{
      operation: "add_scoped_css_rule",
      target: "fixture-theme",
      selector: "body.page-id-25 #wide-image",
      before: cssBefore,
      before_sha256: createHash("sha256").update(cssBefore).digest("hex"),
      after: cssAfter,
      after_sha256: createHash("sha256").update(cssAfter).digest("hex"),
      applied: false,
    }],
  };
  assert.equal(validateWordPressRecoverySnapshot({
    backupId: cssSnapshot.id,
    repairOperation: "add_scoped_css_rule",
    repairParameters: { selector: "body.page-id-25 #wide-image" },
    snapshot: cssSnapshot,
  }).ok, true);
});

test("repair instruction schemas reject unknown operations, parameters, and fields", () => {
  const valid = {
    steps: [{
      description: "Update site title",
      operation: "update_setting",
      parameters: { option: "blogname", expectedCurrentValue: "Old", value: "Example" },
    }],
    rollbackPlan: ["Restore the exact previous setting value."],
    requiresApproval: true,
  };
  assert.equal(repairInstructionsSchema.safeParse(valid).success, true);
  assert.equal(repairInstructionsSchema.safeParse({
    ...valid,
    steps: [{ description: "Run SQL", operation: "run_sql", parameters: { query: "DROP TABLE" } }],
  }).success, false);
  assert.equal(repairInstructionsSchema.safeParse({
    ...valid,
    steps: [{ ...valid.steps[0], unexpected: "field" }],
  }).success, false);
  assert.equal(repairInstructionsSchema.safeParse({
    ...valid,
    steps: [{ description: "Constrain measured overflow on staging", operation: "add_scoped_css_rule", parameters: { selector: "body.page-id-25 #wide-image" } }],
  }).success, true);
  assert.equal(repairInstructionsSchema.safeParse({
    ...valid,
    steps: [{ description: "Inject CSS", operation: "add_scoped_css_rule", parameters: { selector: "body { display:none }" } }],
  }).success, false);
});

test("repair status cannot be successful until verification passes", () => {
  assert.equal(deriveRepairStatus({
    executionStatus: "completed",
    verificationStatus: "inconclusive",
    rollbackApplied: false,
    rollbackRequired: false,
  }), "inconclusive");
  assert.equal(deriveRepairStatus({
    executionStatus: "completed",
    verificationStatus: "failed",
    rollbackApplied: false,
    rollbackRequired: true,
  }), "rollback_required");
  assert.equal(deriveRepairStatus({
    executionStatus: "completed",
    verificationStatus: "passed",
    rollbackApplied: false,
    rollbackRequired: false,
  }), "verified");
});

test("verification checks original issue and rejects newly introduced severe findings", () => {
  const baseline = { issues: [
    { fingerprint: "fixed-issue", severity: "medium" },
    { fingerprint: "old-warning", severity: "high" },
  ] };
  assert.equal(verifyRepairEvidence({
    issueFingerprint: "wp:fixed-issue",
    baselineEvidence: baseline,
    afterEvidence: { issues: [] },
  }).status, "passed");
  assert.equal(verifyRepairEvidence({
    issueFingerprint: "wp:fixed-issue",
    baselineEvidence: baseline,
    afterEvidence: { issues: [{ fingerprint: "fixed-issue", severity: "medium" }] },
  }).status, "failed");
  const regression = verifyRepairEvidence({
    issueFingerprint: "wp:fixed-issue",
    baselineEvidence: baseline,
    afterEvidence: { issues: [
      { fingerprint: "old-warning", severity: "high" },
      { fingerprint: "new-fatal", severity: "critical" },
    ] },
  });
  assert.equal(regression.status, "failed");
  assert.deepEqual(regression.regressions, ["new-fatal"]);
  assert.equal(verifyRepairEvidence({
    issueFingerprint: "wp:fixed-issue",
    baselineEvidence: { issues: [] },
    afterEvidence: { issues: [] },
  }).status, "inconclusive");
});

test("rollback verification requires restoration of the saved theme and active plugins", () => {
  const before = {
    site: { activeTheme: { stylesheet: "original-theme" } },
    plugins: [{ file: "safe/safe.php", active: true }],
    settings: { blogname: "Site", blogdescription: "Description" },
  };
  assert.equal(verifyRecoveryState({ beforeEvidence: before, afterEvidence: before }).status, "passed");
  assert.equal(verifyRecoveryState({
    beforeEvidence: before,
    afterEvidence: {
      site: { activeTheme: { stylesheet: "original-theme" } },
      plugins: [{ file: "safe/safe.php", active: true }],
      settings: { blogname: "Changed", blogdescription: "Description" },
    },
  }).status, "failed");
  assert.equal(verifyRecoveryState({ beforeEvidence: before, afterEvidence: {} }).status, "inconclusive");
});

test("browser findings need a measured, uniquely targeted staging element before creating a CSS repair", () => {
  const plan = boundedRepairPlan({
    fingerprint: "browser:horizontal-overflow:page",
    title: "Horizontal overflow",
    description: "The mobile viewport overflows.",
  }, { browser: { finding: { viewport: 390 } } });
  assert.equal(plan.instructions.steps.length, 0);
  assert.equal(plan.proposal.requiresApproval, true);
  assert.match(plan.proposal.proposedChanges[0], /No automatic change is supported/);

  const evidence = {
    environmentType: "staging",
    editablePages: [{ id: 25, url: "https://example.test/pricing/", postType: "page" }],
    browser: { finding: {
      pageUrl: "https://example.test/pricing/",
      observations: [{ viewport: { width: 390, height: 844 }, overflowingElements: [{ selector: "#wide-image", width: 900, parentWidth: 380 }] }],
    } },
  };
  const stagedPlan = boundedRepairPlan({
    fingerprint: "browser:horizontal-overflow:page",
    title: "Horizontal overflow",
    description: "The mobile viewport overflows.",
  }, evidence);
  assert.equal(stagedPlan.candidate?.operation, "add_scoped_css_rule");
  assert.deepEqual(stagedPlan.instructions.steps[0].parameters, { selector: "body.page-id-25 #wide-image" });
  assert.equal(stagedPlan.proposal.risk, "high");
  assert.equal(repairRiskForOperations(["add_scoped_css_rule"]), "high");
  assert.equal(boundedRepairPlan({
    fingerprint: "browser:horizontal-overflow:page",
    title: "Horizontal overflow",
    description: "The mobile viewport overflows.",
  }, { ...evidence, environmentType: "production" }).instructions.steps.length, 0);
  assert.equal(boundedRepairPlan({
    fingerprint: "browser:horizontal-overflow:page",
    title: "Horizontal overflow",
    description: "The mobile viewport overflows.",
  }, { ...evidence, browser: { finding: { ...evidence.browser.finding, observations: [{ overflowingElements: [{ selector: "body", width: 900, parentWidth: 380 }] }] } } }).instructions.steps.length, 0);
});

test("staging layout verification requires a complete retest and disappearance of the original overflow", () => {
  const issueFingerprint = "browser:horizontal-overflow:page";
  assert.equal(verifyBrowserLayoutRepair({
    issueFingerprint,
    scan: { status: "issues_found", crawlIncomplete: false, findings: [] },
  }).status, "passed");
  assert.equal(verifyBrowserLayoutRepair({
    issueFingerprint,
    scan: { status: "issues_found", crawlIncomplete: false, findings: [{ fingerprint: issueFingerprint }] },
  }).status, "failed");
  assert.equal(verifyBrowserLayoutRepair({
    issueFingerprint,
    scan: { status: "partial", crawlIncomplete: true, findings: [] },
  }).status, "inconclusive");
});

test("CSS recovery verification confirms the active theme and exact custom CSS digest", () => {
  const before = {
    site: { activeTheme: { stylesheet: "fixture-theme" }, customCssSha256: "a".repeat(64) },
  };
  const operation = { operation: "add_scoped_css_rule", parameters: { selector: "body.page-id-25 #wide-image" } };
  assert.equal(verifyRecoveryState({ beforeEvidence: before, afterEvidence: before, operations: [operation] }).status, "passed");
  assert.equal(verifyRecoveryState({
    beforeEvidence: before,
    afterEvidence: { site: { activeTheme: { stylesheet: "another-theme" }, customCssSha256: "a".repeat(64) } },
    operations: [operation],
  }).status, "failed");
  assert.equal(verifyRecoveryState({
    beforeEvidence: before,
    afterEvidence: { site: { activeTheme: { stylesheet: "fixture-theme" }, customCssSha256: "b".repeat(64) } },
    operations: [operation],
  }).status, "failed");
});

test("only a matching disposable-staging comparison creates a reversible operation", () => {
  const components = ["fixture-conflict/fixture-conflict.php"];
  const fingerprint = `wp:staging-conflict:${createHash("sha256").update(components.join("|")).digest("hex").slice(0, 32)}`;
  const evidence = {
    plugins: [{ file: components[0], active: true }],
    conflictTesting: {
      status: "completed", environment: "disposable_staging", liveDeactivationPerformed: false,
      activePlugins: components, activeTheme: "current-theme",
      findings: [{ components, result: "conflict", evidence: "Staging browser scan resolved one finding.",
        baselineFindings: [{ fingerprint: "browser:horizontal-overflow:home", severity: "medium" }],
        probeFindings: [] }],
    },
  };
  const repairs = evidenceBackedRepairs(fingerprint, evidence);
  assert.deepEqual(repairs.map(({ operation, parameters }) => ({ operation, parameters })), [{
    operation: "disable_plugin", parameters: { plugin: components[0] },
  }]);
  const plan = boundedRepairPlan({ fingerprint, title: "Staging conflict", description: "Evidence" }, evidence);
  assert.equal(plan.instructions.steps[0].operation, "disable_plugin");
  assert.equal(plan.instructions.requiresApproval, true);
  assert.equal(plan.instructions.steps.length, 1);
});

test("browser verification fails on persistent staged findings, regressions, or incomplete scans", () => {
  const components = ["fixture-conflict/fixture-conflict.php"];
  const fingerprint = `wp:staging-conflict:${createHash("sha256").update(components.join("|")).digest("hex").slice(0, 32)}`;
  const issueEvidence = { conflictTesting: {
    status: "completed", environment: "disposable_staging", liveDeactivationPerformed: false,
    findings: [{ components, result: "conflict",
      baselineFindings: [{ fingerprint: "browser:overflow", severity: "medium" }],
      probeFindings: [] }],
  } };
  const makeScan = (findings, extra = {}) => ({ status: "issues_found", crawlIncomplete: false, findings, ...extra });
  assert.equal(verifyBrowserConflictRepair({ issueFingerprint: fingerprint, issueEvidence, scan: makeScan([]) }).status, "passed");
  assert.equal(verifyBrowserConflictRepair({ issueFingerprint: fingerprint, issueEvidence, scan: makeScan([{ fingerprint: "browser:overflow", severity: "medium" }]) }).status, "failed");
  assert.equal(verifyBrowserConflictRepair({ issueFingerprint: fingerprint, issueEvidence, scan: makeScan([{ fingerprint: "browser:new-error", severity: "high" }]) }).status, "failed");
  assert.equal(verifyBrowserConflictRepair({ issueFingerprint: fingerprint, issueEvidence, scan: makeScan([], { status: "partial", crawlIncomplete: true }) }).status, "inconclusive");
});
