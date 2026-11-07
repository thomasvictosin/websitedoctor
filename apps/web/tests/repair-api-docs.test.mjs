import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const root = new URL("../../../", import.meta.url);

test("repair API reference tracks implemented route boundaries and authorization guarantees", async () => {
  const [docs, policyRoute, proposalRoute, requestRoute, hostingProposalRoute, hostingOperationsRoute, approvalRoute, batchRoute, agentContract, agentApprovalRoute, agentTasksRoute, hostingWrites] = await Promise.all([
    readFile(new URL("docs/repair-api.md", root), "utf8"),
    readFile(new URL("apps/web/app/api/sites/[siteId]/repair-authorization/route.ts", root), "utf8"),
    readFile(new URL("apps/web/app/api/issues/[issueId]/repairs/route.ts", root), "utf8"),
    readFile(new URL("apps/web/app/api/sites/[siteId]/repair-requests/route.ts", root), "utf8"),
    readFile(new URL("apps/web/app/api/sites/[siteId]/hosting/repairs/route.ts", root), "utf8"),
    readFile(new URL("apps/web/app/api/sites/[siteId]/hosting/operations/route.ts", root), "utf8"),
    readFile(new URL("apps/web/app/api/repairs/[repairId]/route.ts", root), "utf8"),
    readFile(new URL("apps/web/app/api/repairs/batch/route.ts", root), "utf8"),
    readFile(new URL("contracts/wordpress-agent-api.md", root), "utf8"),
    readFile(new URL("apps/web/app/api/agents/[agentId]/repairs/[repairId]/route.ts", root), "utf8"),
    readFile(new URL("apps/web/app/api/agents/[agentId]/tasks/route.ts", root), "utf8"),
    readFile(new URL("docs/hosting-write-safety.md", root), "utf8"),
  ]);

  for (const route of [
    "GET /api/sites/{siteId}/repair-authorization",
    "PUT /api/sites/{siteId}/repair-authorization",
    "POST /api/issues/{issueId}/repairs",
    "POST /api/sites/{siteId}/repair-requests",
    "POST /api/sites/{siteId}/hosting/repairs",
    "PATCH /api/repairs/{repairId}",
    "POST /api/repairs/batch",
    "GET /api/agents/{agentId}/tasks",
  ]) assert.ok(docs.includes(route), `missing documented route ${route}`);

  assert.match(policyRoute, /authorizeOwnerRequest\(request, true\)/);
  assert.match(policyRoute, /Only organization owners and administrators/);
  assert.match(policyRoute, /auto_eligible/);
  assert.match(proposalRoute, /applyStandingRepairAuthorization/);
  assert.match(requestRoute, /isDiagnosisOnlyPrompt/);
  assert.match(requestRoute, /authorizeExplicitPromptRepair/);
  assert.match(hostingProposalRoute, /validateHostingRepairProposal/);
  assert.match(hostingProposalRoute, /executionEnabled: false/);
  assert.match(hostingOperationsRoute, /Remote hosting repairs are not implemented/);
  assert.match(hostingOperationsRoute, /status: 501/);
  assert.match(approvalRoute, /approve_and_apply/);
  assert.match(approvalRoute, /Hosting repair execution is disabled/);
  assert.match(approvalRoute, /Review acknowledged and recorded\. Hosting repair execution is disabled/);
  assert.match(approvalRoute, /decision === "approve" && !isHostingProposal \? "awaiting_local_executor" : "none"/);
  assert.match(batchRoute, /Hosting proposals cannot be batch-authorized/);
  assert.match(agentApprovalRoute, /Hosting proposals are review-only/);
  assert.match(agentTasksRoute, /isHostingRepairProposal/);
  assert.match(hostingWrites, /SFTP does not provide/);
  assert.match(hostingWrites, /RESOLVE_BENEATH \| RESOLVE_NO_SYMLINKS/);
  assert.match(hostingWrites, /Ordinary `lstat`\/hash followed by `rename` is not compare-and-swap/);
  assert.match(batchRoute, /max\(25\)/);
  assert.match(agentContract, /X-AWD-Signature/);
});
