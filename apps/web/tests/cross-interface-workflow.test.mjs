import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const root = new URL("../../../", import.meta.url);
const source = async (path) => readFile(new URL(path, root), "utf8");

test("WordPress and custom-app issue views read the same central issue records", async () => {
  const [diagnostics, appIssues, plugin] = await Promise.all([
    source("apps/web/app/api/agents/[agentId]/diagnostics/route.ts"),
    source("apps/web/app/api/issues/route.ts"),
    source("wordpress-plugin/ai-website-doctor/ai-website-doctor.php"),
  ]);
  assert.match(diagnostics, /db\.issue\.upsert/);
  assert.match(appIssues, /db\.issue\.findMany/);
  assert.match(plugin, /\/dashboard/);
  assert.match(plugin, /awd_render_central_issues\(\$settings, \$central_dashboard\)/);
});

test("both interfaces request diagnosis from the same central AI orchestrator and diagnosis records", async () => {
  const [agentAnalysis, appAnalysis, plugin] = await Promise.all([
    source("apps/web/app/api/agents/[agentId]/analysis/route.ts"),
    source("apps/web/app/api/issues/[issueId]/diagnose/route.ts"),
    source("wordpress-plugin/ai-website-doctor/ai-website-doctor.php"),
  ]);
  assert.match(agentAnalysis, /analyzeFinding/);
  assert.match(appAnalysis, /analyzeFinding/);
  assert.match(agentAnalysis, /db\.aiDiagnosis\.create/);
  assert.match(plugin, /\/analysis/);
});

test("repair proposals from either interface persist to the same RepairProposal model", async () => {
  const [agentRepairs, appRepairs, plugin] = await Promise.all([
    source("apps/web/app/api/agents/[agentId]/repairs/route.ts"),
    source("apps/web/app/api/issues/[issueId]/repairs/route.ts"),
    source("wordpress-plugin/ai-website-doctor/ai-website-doctor.php"),
  ]);
  assert.match(agentRepairs, /repairProposal\.create/);
  assert.match(appRepairs, /repairProposal\.create/);
  assert.match(appRepairs, /websiteId: issue\.websiteId/);
  for (const route of [agentRepairs, appRepairs]) {
    assert.match(route, /pg_advisory_xact_lock/);
    assert.match(route, /An active repair proposal already exists/);
  }
  const tasks = await source("apps/web/app/api/agents/[agentId]/tasks/route.ts");
  assert.match(tasks, /websiteId: auth\.agent\.websiteId/);
  assert.match(tasks, /proposal\.issue\?\.fingerprint/);
  assert.match(plugin, /\/repairs', 'POST'/);
  assert.match(plugin, /awd_render_pending_repairs\(\$settings\)/);
});

test("approvals made in either interface update the same proposal and approval/event history", async () => {
  const [agentDecision, appDecision, plugin] = await Promise.all([
    source("apps/web/app/api/agents/[agentId]/repairs/[repairId]/route.ts"),
    source("apps/web/app/api/repairs/[repairId]/route.ts"),
    source("wordpress-plugin/ai-website-doctor/ai-website-doctor.php"),
  ]);
  for (const route of [agentDecision, appDecision]) {
    assert.match(route, /repairProposal\.updateMany/);
    assert.match(route, /repairApproval\.create/);
    assert.match(route, /repairEvent\.create/);
  }
  assert.match(agentDecision, /pg_advisory_xact_lock/);
  assert.match(agentDecision, /findActiveRepairConflict/);
  assert.match(plugin, /\/repairs\/'.*'PATCH'/);
  assert.match(plugin, /awd_decide_repair/);
});

test("both interfaces use the shared approved-task and execution lifecycle, including verification and rollback", async () => {
  const [tasks, executions, agentDashboard, appIssues, plugin] = await Promise.all([
    source("apps/web/app/api/agents/[agentId]/tasks/route.ts"),
    source("apps/web/app/api/agents/[agentId]/executions/route.ts"),
    source("apps/web/app/api/agents/[agentId]/dashboard/route.ts"),
    source("apps/web/app/api/issues/route.ts"),
    source("wordpress-plugin/ai-website-doctor/ai-website-doctor.php"),
  ]);
  assert.match(tasks, /status: "approved"/);
  assert.match(tasks, /rollbackRequests/);
  assert.match(executions, /agentExecution\.create/);
  assert.match(executions, /verificationResult\.create/);
  assert.match(executions, /rollback_completed/);
  assert.match(agentDashboard, /verificationResults:/);
  assert.match(agentDashboard, /approvals:/);
  assert.match(appIssues, /verificationResults:/);
  assert.match(appIssues, /approvals:/);
  assert.match(plugin, /\/tasks/);
  assert.match(plugin, /\/executions/);
  assert.match(plugin, /awd_execute_central_rollback/);
  assert.match(plugin, /rollbackRequests/);
  assert.match(plugin, /Central verification results/);
});

test("website-specific Drive recovery requests require a local WordPress administrator and report the result", async () => {
  const [backupRestore, download, restoreResult, tasks, executions, plugin] = await Promise.all([
    source("apps/web/app/api/backups/[backupId]/restore/route.ts"),
    source("apps/web/app/api/agents/[agentId]/backups/[backupId]/route.ts"),
    source("apps/web/app/api/agents/[agentId]/backups/[backupId]/restore-result/route.ts"),
    source("apps/web/app/api/agents/[agentId]/tasks/route.ts"),
    source("apps/web/app/api/agents/[agentId]/executions/route.ts"),
    source("wordpress-plugin/ai-website-doctor/ai-website-doctor.php"),
  ]);
  assert.match(backupRestore, /restoreStatus: "requested"/);
  assert.match(download, /restoreStatus: "requested"/);
  assert.match(download, /validateWordPressRecoverySnapshot/);
  assert.match(restoreResult, /restoreStatus: "requested"/);
  assert.match(tasks, /manualRecoveryRequests/);
  assert.match(tasks, /requireCloudBackup: Boolean/);
  assert.match(executions, /repairId_externalId/);
  assert.match(executions, /transaction\.backup\.update/);
  assert.match(plugin, /name="manual_restore" value="1"/);
  assert.match(plugin, /awd_import_recovery_point/);
  assert.match(plugin, /restore-result/);
});

test("the shared database schema links issues, diagnoses, proposals, approvals, executions, verification, and events", async () => {
  const schema = await source("apps/web/prisma/schema.prisma");
  for (const model of ["Issue", "AiDiagnosis", "RepairProposal", "RepairApproval", "AgentExecution", "VerificationResult", "RepairEvent"]) {
    assert.match(schema, new RegExp(`model ${model} \\{`));
  }
  assert.match(schema, /model AiDiagnosis[\s\S]*issue\s+Issue/);
  assert.match(schema, /model RepairApproval[\s\S]*repair\s+RepairProposal/);
  assert.match(schema, /model AgentExecution[\s\S]*repair\s+RepairProposal/);
  assert.match(schema, /model VerificationResult[\s\S]*repair\s+RepairProposal/);
  assert.match(schema, /model RepairEvent[\s\S]*repair\s+RepairProposal/);
});

test("prompt repair requests validate user scope and only authorize explicit repair requests", async () => {
  const route = await source("apps/web/app/api/sites/[siteId]/repair-requests/route.ts");
  assert.match(route, /validateRepairRequestScope\(parsed\.data\.prompt, intent\.requestKind, intent\.issueIds\)/);
  assert.match(route, /validateIssueCategoryScope\(parsed\.data\.prompt, intent\.issueIds, evidenceIssues\)/);
  assert.match(route, /pg_advisory_xact_lock/);
  assert.match(route, /Another request created an active proposal/);
  assert.match(route, /if \(intent\.requestKind === "recommend"\) return/);
  assert.match(route, /if \(intent\.requestKind === "diagnose"\) return/);
  assert.match(route, /explicitRepairRequest && await applyStandingRepairAuthorization/);
  assert.match(route, /if \(!autoApproved && explicitRepairRequest/);
});
