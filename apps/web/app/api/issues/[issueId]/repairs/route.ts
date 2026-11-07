import { NextResponse } from "next/server";
import { Prisma } from "@prisma/client";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { determineRepairRisk } from "@/lib/ai/orchestrator";
import { ownedIssueWhere } from "@/lib/ownership";
import { boundedRepairPlan, requiresRecoveryPoint } from "@/lib/repair-policy";
import { requestSourceHash } from "@/lib/rate-limit";
import { redactApiValue } from "@/lib/redaction";
import { readBoundedJson } from "@/lib/request-json";
import { checkWebsite } from "@/lib/monitor";
import { applyStandingRepairAuthorization } from "@/lib/repair-authorization";

export const runtime = "nodejs";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ issueId: string }> },
) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const body = await readBoundedJson(request, 4096);
  const replacementUrl = body && typeof body === "object" && !Array.isArray(body)
    && typeof (body as Record<string, unknown>).replacementUrl === "string"
    ? String((body as Record<string, unknown>).replacementUrl).trim()
    : "";
  const { issueId } = await params;
  const issue = await db.issue.findFirst({
    where: ownedIssueWhere(authorization.ownerId, issueId),
    include: { website: { select: { id: true, name: true, url: true, organizationId: true } } },
  });
  if (!issue) return NextResponse.json({ error: "Issue not found." }, { status: 404 });

  if (replacementUrl) {
    if (!issue.fingerprint.startsWith("browser:broken-link:") || replacementUrl.length > 2000) {
      return NextResponse.json({ error: "A replacement URL can only be supplied for a browser broken-link finding." }, { status: 400 });
    }
    try {
      const target = new URL(replacementUrl);
      const site = new URL(issue.website.url);
      if (!["http:", "https:"].includes(target.protocol) || target.origin !== site.origin
        || target.username || target.password || target.hash || target.search) throw new Error("Use a clean same-origin URL without credentials, query, or fragment.");
      const check = await checkWebsite(target.toString());
      if (!check.available || check.statusCode === null || check.statusCode < 200 || check.statusCode >= 300 || check.finalUrl !== target.toString()) {
        throw new Error("The replacement URL must respond successfully without redirecting elsewhere.");
      }
    } catch (error) {
      return NextResponse.json({ error: error instanceof Error ? error.message : "Replacement URL could not be verified." }, { status: 400 });
    }
  }

  try {
    const agent = await db.wordPressAgent.findFirst({
      where: { websiteId: issue.websiteId, revokedAt: null },
      select: { id: true, diagnostics: true },
    });
    const evidence = {
      issue: {
        title: issue.title,
        description: issue.description,
        severity: issue.severity,
        source: issue.source,
        evidence: issue.evidence,
      },
      website: issue.website,
      relevantTools: issue.toolIds,
      executor: agent ? "connected_wordpress_agent" : "none",
    };
    const diagnosticData = agent?.diagnostics && typeof agent.diagnostics === "object" && !Array.isArray(agent.diagnostics)
      ? agent.diagnostics as Prisma.JsonObject
      : {};
    const diagnosticSite = diagnosticData.site && typeof diagnosticData.site === "object" && !Array.isArray(diagnosticData.site)
      ? diagnosticData.site as Prisma.JsonObject
      : {};
    const issueEvidence = issue.evidence && typeof issue.evidence === "object" && !Array.isArray(issue.evidence)
      ? { ...(issue.evidence as Prisma.JsonObject), editablePages: Array.isArray(diagnosticData.editablePages) ? diagnosticData.editablePages : [], environmentType: diagnosticSite.environmentType, ...(replacementUrl ? { requestedReplacementUrl: replacementUrl } : {}) }
      : issue.evidence;
    const repairPlan = boundedRepairPlan({ fingerprint: issue.fingerprint, title: issue.title, description: issue.description }, issueEvidence);
    const proposal = !agent && repairPlan.candidate ? {
      ...repairPlan.proposal,
      manualGuidance: [
        "The WordPress agent is disconnected, so this app cannot execute or verify the staged operation.",
        `${repairPlan.candidate.description} The staging comparison is evidence for review, not proof that production has the same state.`,
        "Use a host-level database and files backup, apply the change locally through WordPress, then reconnect the agent and rerun diagnostics and central browser verification.",
      ],
    } : repairPlan.proposal;
    const instructions = agent ? repairPlan.instructions : { steps: [], rollbackPlan: [], requiresApproval: true as const };
    const risk = instructions.steps.length > 0
      ? determineRepairRisk(instructions.steps.map((step) => step.operation))
      : "high";
    const operationIds = instructions.steps.map((step) => step.operation);
    const repair = await db.$transaction(async (transaction) => {
      await transaction.$queryRaw`WITH advisory_lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(hashtext(${issue.websiteId}))) SELECT 1 FROM advisory_lock`;
      const existing = await transaction.repairProposal.findFirst({ where: { issueId: issue.id, status: { in: ["pending_approval", "approved", "executing", "in_progress"] } }, select: { id: true } });
      if (existing) return null;
      const created = await transaction.repairProposal.create({
        data: {
          websiteId: issue.websiteId,
          issueId: issue.id,
          risk,
          initiatingInterface: "dashboard",
          operationIds,
          requiredPermissions: ["manage_options"],
          approvalStatus: "pending",
          backupStatus: requiresRecoveryPoint(operationIds) ? "not_started" : "not_required",
          executionStatus: "not_started",
          verificationStatus: "not_started",
          rollbackStatus: "not_requested",
          proposal: {
            ...proposal,
            risk,
            instructions,
            executionAvailable: Boolean(agent && instructions.steps.length > 0),
            relevantTools: issue.toolIds,
            evidenceBacked: true,
          } as Prisma.InputJsonValue,
        },
      });
      await transaction.repairEvent.create({
        data: {
          repairId: created.id,
          eventType: "proposal_created",
          actor: "dashboard",
          details: {
            issueId: issue.id,
            websiteId: issue.websiteId,
            operationIds,
            risk,
            requiredPermissions: ["manage_options"],
            executionAvailable: Boolean(agent && instructions.steps.length > 0),
          },
        },
      });
      await transaction.auditLog.create({
        data: {
          action: "repair_proposal_created",
          actorType: "admin",
          actorId: authorization.ownerId,
          actorUserId: authorization.ownerId,
          organizationId: issue.website.organizationId,
          resourceType: "repair",
          resourceId: created.id,
          sourceHash: requestSourceHash(request),
          details: { issueId: issue.id, risk, operationIds },
        },
      });
      return created;
    });
    if (!repair) return NextResponse.json({ error: "An active repair proposal already exists for this issue." }, { status: 409 });
    const autoApproved = await applyStandingRepairAuthorization({ repairId: repair.id, websiteId: issue.websiteId, organizationId: issue.website.organizationId, operationIds, risk, agentId: agent?.id });
    const finalRepair = autoApproved ? await db.repairProposal.findUnique({ where: { id: repair.id } }) : repair;
    return NextResponse.json(redactApiValue(finalRepair), { status: 201, headers: { "cache-control": "no-store" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Repair proposal failed.";
    return NextResponse.json({ error: message }, { status: 503 });
  }
}
