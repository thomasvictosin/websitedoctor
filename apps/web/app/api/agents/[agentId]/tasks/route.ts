import { NextResponse } from "next/server";
import { Prisma } from "@prisma/client";
import { authenticateAgent } from "@/lib/agent-auth";
import { isAllowedAgentOperation } from "@/lib/agent-operations";
import { repairStepSchema } from "@/lib/repair-policy";
import { db } from "@/lib/db";
import { redactApiValue } from "@/lib/redaction";
import { authorizeRepairExecution } from "@/lib/repair-authorization";
import { isHostingRepairProposal } from "@/lib/hosting-proposal-policy";

export const runtime = "nodejs";

export async function GET(
  request: Request,
  { params }: { params: Promise<{ agentId: string }> },
) {
  const { agentId } = await params;
  const auth = await authenticateAgent(request, agentId);
  if ("response" in auth) return auth.response;
  if (auth.agent.id !== agentId) return NextResponse.json({ error: "Agent identity mismatch." }, { status: 403 });

  const agentState = await db.wordPressAgent.findUnique({
    where: { id: agentId },
    select: {
      diagnostics: true,
      website: { select: { organization: { select: { googleDriveConnection: { select: { id: true } } } } } },
    },
  });
  const diagnostics = agentState?.diagnostics && typeof agentState.diagnostics === "object"
    && !Array.isArray(agentState.diagnostics)
    ? agentState.diagnostics as Prisma.JsonObject
    : null;
  const baselineIssues = diagnostics && Array.isArray(diagnostics.issues)
    ? diagnostics.issues as Prisma.JsonArray
    : null;
  const baselineIsValid = baselineIssues !== null;
  const baselineHighSeverityIssues = (baselineIssues ?? []).flatMap((issue) => {
    if (!issue || typeof issue !== "object" || Array.isArray(issue)) return [];
    const item = issue as Prisma.JsonObject;
    return (item.severity === "high" || item.severity === "critical") && typeof item.fingerprint === "string"
      ? [item.fingerprint]
      : [];
  });

  const proposals = await db.repairProposal.findMany({
    where: {
      websiteId: auth.agent.websiteId,
      status: "approved",
      executions: { none: { agentId } },
    },
    orderBy: { approvedAt: "asc" },
    take: 20,
    include: { issue: { select: { title: true, description: true, fingerprint: true, evidence: true, lastSeenAt: true } } },
  });
  const consumedForAgent = await db.repairApproval.findMany({
    where: { repair: { websiteId: auth.agent.websiteId }, consumedAt: { not: null }, executionResult: "task_dispatched" },
    select: { repairId: true },
  });
  const dispatchedRepairIds = new Set(consumedForAgent.map((grant) => grant.repairId));
  const rollbackProposals = await db.repairProposal.findMany({
    where: { websiteId: auth.agent.websiteId, status: "rollback_required" },
    orderBy: { approvedAt: "asc" },
    take: 20,
    include: {
      issue: { select: { title: true } },
      executions: { where: { agentId, status: "rollback_required" }, take: 1 },
    },
  });
  const manualRecoveryPoints = await db.backup.findMany({
    where: {
      websiteId: auth.agent.websiteId,
      agentId,
      backupType: "wordpress_repair_snapshot",
      status: "created",
      storageProvider: "google_drive",
      restoreStatus: "requested",
    },
    orderBy: { restoreRequestedAt: "asc" },
    take: 20,
    select: {
      externalId: true,
      repairId: true,
      metadata: true,
      restoreRequestedAt: true,
      repair: { select: { issue: { select: { title: true } } } },
    },
  });

  const tasks = (await Promise.all(proposals.map(async (proposal) => {
    if (dispatchedRepairIds.has(proposal.id)) return null;
    if (isHostingRepairProposal(proposal.proposal)) return null;
    const data = proposal.proposal as Prisma.JsonObject;
    const authorization = await authorizeRepairExecution({ repairId: proposal.id, websiteId: auth.agent.websiteId, mode: "executor" });
    if (authorization.outcome !== "AUTHORIZED" || !authorization.grantId) return null;
    const instructions = data.instructions;
    if (!instructions || typeof instructions !== "object" || Array.isArray(instructions)) return [];
    const rawSteps = (instructions as Prisma.JsonObject).steps;
    if (!Array.isArray(rawSteps) || rawSteps.length !== 1) return [];
    const steps = rawSteps.filter((step) => step && typeof step === "object" && !Array.isArray(step))
      .map((step) => step as { operation?: unknown; parameters?: unknown; description?: unknown });
    if (steps.length !== rawSteps.length
      || !steps.every((step) => isAllowedAgentOperation(step) && repairStepSchema.safeParse(step).success)) return [];
    const verificationPlan = Array.isArray(data.verificationPlan)
      ? data.verificationPlan.filter((item): item is string => typeof item === "string").slice(0, 10)
      : [];
    const issueFingerprint = proposal.issue?.fingerprint ?? "";
    const wordpressIssue = issueFingerprint.startsWith("wp:") && baselineIssues?.some((issue) => issue && typeof issue === "object" && !Array.isArray(issue)
      && (issue as Prisma.JsonObject).fingerprint === issueFingerprint.slice(3));
    const linkRepairStep = steps.find((step) => step.operation === "replace_post_link");
    const linkParameters = linkRepairStep?.parameters && typeof linkRepairStep.parameters === "object" && !Array.isArray(linkRepairStep.parameters)
      ? linkRepairStep.parameters as { postId?: unknown; pageUrl?: unknown; linkUrl?: unknown; replacementUrl?: unknown }
      : {};
    const isLinkRepair = (issueFingerprint.startsWith("browser:link-redirect:") || issueFingerprint.startsWith("browser:broken-link:"))
      && linkRepairStep?.operation === "replace_post_link";
    const issueEvidence = proposal.issue?.evidence && typeof proposal.issue.evidence === "object" && !Array.isArray(proposal.issue.evidence)
      ? proposal.issue.evidence as Prisma.JsonObject
      : {};
    const browserEvidence = issueEvidence.browser && typeof issueEvidence.browser === "object" && !Array.isArray(issueEvidence.browser)
      ? issueEvidence.browser as Prisma.JsonObject
      : {};
    const findingEvidence = browserEvidence.finding && typeof browserEvidence.finding === "object" && !Array.isArray(browserEvidence.finding)
      ? browserEvidence.finding as Prisma.JsonObject
      : {};
    const scanTime = typeof browserEvidence.checkedAt === "string" ? Date.parse(browserEvidence.checkedAt) : NaN;
    const diagnosticsTime = diagnostics && typeof diagnostics.collectedAt === "string" ? Date.parse(diagnostics.collectedAt) : NaN;
    const requestedPostId = typeof linkParameters.postId === "string" ? Number(linkParameters.postId) : NaN;
    const currentPageMap = diagnostics && Array.isArray(diagnostics.editablePages) ? diagnostics.editablePages : [];
    const sourceMappingIsCurrent = currentPageMap.some((page) => page && typeof page === "object" && !Array.isArray(page)
      && (page as Prisma.JsonObject).id === requestedPostId
      && (page as Prisma.JsonObject).url === linkParameters.pageUrl
      && (page as Prisma.JsonObject).url === findingEvidence.sourcePage);
    const redirectEvidenceIsFresh = Number.isFinite(scanTime) && Number.isFinite(diagnosticsTime)
      && scanTime <= Date.now() && Date.now() - scanTime <= 60 * 60 * 1000
      && diagnosticsTime <= Date.now() && Date.now() - diagnosticsTime <= 15 * 60 * 1000;
    const exactLinkEvidence = (issueFingerprint.startsWith("browser:link-redirect:")
      ? findingEvidence.kind === "permanent_redirect"
        && Array.isArray(findingEvidence.redirectChain)
        && findingEvidence.redirectChain.length > 0
        && (findingEvidence.redirectChain as Prisma.JsonArray).every((hop) => hop && typeof hop === "object" && !Array.isArray(hop)
          && [301, 308].includes(Number((hop as Prisma.JsonObject).status)))
        && findingEvidence.replacementUrl === linkParameters.replacementUrl
      : findingEvidence.kind === "missing_page" && [404, 410].includes(Number(findingEvidence.statusCode))
        && typeof linkParameters.replacementUrl === "string")
      && findingEvidence.href === linkParameters.linkUrl
      && typeof findingEvidence.sourcePage === "string"
      && (() => {
        try {
          const source = new URL(String(findingEvidence.sourcePage));
          const replacement = new URL(String(linkParameters.replacementUrl));
          return source.origin === replacement.origin && !replacement.search && !replacement.hash;
        } catch { return false; }
      })();
    if (!baselineIsValid || (!wordpressIssue && !(isLinkRepair && sourceMappingIsCurrent && redirectEvidenceIsFresh && exactLinkEvidence))) return [];
    const decision = await db.$transaction(async (tx) => {
      await tx.$queryRaw`WITH advisory_lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(hashtext(${auth.agent.websiteId}))) SELECT 1 FROM advisory_lock`;
      const current = await tx.repairProposal.findFirst({ where: { id: proposal.id, websiteId: auth.agent.websiteId, status: "approved" }, select: { id: true } });
      if (!current) return null;
      const claimed = await authorizeRepairExecution({ repairId: proposal.id, websiteId: auth.agent.websiteId, mode: "executor", grantId: authorization.grantId, consume: true });
      if (claimed.outcome !== "AUTHORIZED" || !claimed.grantId) return null;
      await tx.repairApproval.update({ where: { id: claimed.grantId }, data: { executionResult: "task_dispatched" } });
      return claimed;
    });
    if (decision?.outcome !== "AUTHORIZED" || !decision.grantId) return null;
    return {
      repairId: proposal.id,
      authorizationGrantId: decision.grantId,
      authorizationExpiresAt: (await db.repairApproval.findUnique({ where: { id: decision.grantId }, select: { expiresAt: true } }))?.expiresAt?.toISOString() ?? null,
      executeOnPoll: data.executionRequest !== undefined || proposal.approvedBy === "wordpress-admin",
      issue: proposal.issue?.title ?? String(data.issue ?? "Approved repair"),
      issueFingerprint: proposal.issue?.fingerprint ?? "",
      rationale: typeof data.rationale === "string" ? data.rationale : "",
      risk: proposal.risk,
      requiredPermissions: proposal.requiredPermissions,
      baselineHighSeverityIssues,
      approvedAt: proposal.approvedAt?.toISOString() ?? null,
      requiresApproval: true,
      requireCloudBackup: Boolean(agentState?.website.organization.googleDriveConnection),
      steps,
      verificationPlan,
      relevantTools: Array.isArray(data.relevantTools) ? data.relevantTools : [],
    };
  }))).filter((task): task is NonNullable<typeof task> => Boolean(task));
  const rollbackRequests = rollbackProposals.flatMap((proposal) => {
    const execution = proposal.executions[0];
    const result = execution?.result;
    if (!result || typeof result !== "object" || Array.isArray(result)) return [];
    if (!("providerRestoreAvailable" in result) || result.providerRestoreAvailable !== true) return [];
    const backupId = "backupId" in result && typeof result.backupId === "string" ? result.backupId : null;
    if (!backupId) return [];
    const review = "review" in result && result.review && typeof result.review === "object" && !Array.isArray(result.review)
      ? result.review as Prisma.JsonObject
      : {};
    const aiReview = "review" in review && review.review && typeof review.review === "object" && !Array.isArray(review.review)
      ? review.review as Prisma.JsonObject
      : {};
    const summary = typeof aiReview.summary === "string"
      ? aiReview.summary
      : "Central verification recommends restoring the local recovery point.";
    return [{
      repairId: proposal.id,
      issue: proposal.issue?.title ?? "Repair verification",
      backupId,
      reason: summary,
      requiresLocalApproval: true,
    }];
  });
  const manualRecoveryRequests = manualRecoveryPoints.flatMap((backup) => {
    if (!backup.externalId || !backup.repairId) return [];
    const metadata = backup.metadata && typeof backup.metadata === "object" && !Array.isArray(backup.metadata)
      ? backup.metadata as Prisma.JsonObject
      : {};
    return [{
      repairId: backup.repairId,
      issue: backup.repair?.issue?.title ?? "Manual recovery",
      backupId: backup.externalId,
      operation: typeof metadata.operation === "string" ? metadata.operation : "repair",
      target: typeof metadata.target === "string" ? metadata.target : "",
      reason: "A website administrator requested restoration of this repair-specific recovery point.",
      requiresLocalApproval: true,
      requestedAt: backup.restoreRequestedAt?.toISOString() ?? null,
    }];
  });
  return NextResponse.json(redactApiValue({
    tasks,
    rollbackRequests,
    manualRecoveryRequests,
    diagnosticsRequired: !baselineIsValid,
  }), { headers: { "cache-control": "no-store" } });
}
