import { NextResponse } from "next/server";
import { Prisma } from "@prisma/client";
import { z } from "zod";
import { authenticateAgent } from "@/lib/agent-auth";
import { db } from "@/lib/db";
import { determineRepairRisk } from "@/lib/ai/orchestrator";
import { boundedRepairPlan, requiresRecoveryPoint } from "@/lib/repair-policy";
import { readBoundedJson } from "@/lib/request-json";
import { redactApiValue } from "@/lib/redaction";
import { requestSourceHash } from "@/lib/rate-limit";
import { applyStandingRepairAuthorization } from "@/lib/repair-authorization";

export const runtime = "nodejs";
const inputSchema = z.object({ issueId: z.string().min(1).max(64) });

export async function POST(request: Request, { params }: { params: Promise<{ agentId: string }> }) {
  const { agentId } = await params;
  const auth = await authenticateAgent(request, agentId);
  if ("response" in auth) return auth.response;
  if (auth.agent.id !== agentId) return NextResponse.json({ error: "Agent identity mismatch." }, { status: 403 });
  const parsed = inputSchema.safeParse(await readBoundedJson(request, 4096));
  if (!parsed.success) return NextResponse.json({ error: "A valid issue ID is required." }, { status: 400 });
  const issue = await db.issue.findFirst({ where: { id: parsed.data.issueId, websiteId: auth.agent.websiteId }, include: { website: { select: { id: true, name: true, url: true, organizationId: true } } } });
  if (!issue) return NextResponse.json({ error: "Issue not found for this WordPress site." }, { status: 404 });
  if (await db.repairProposal.findFirst({ where: { issueId: issue.id, status: { in: ["pending_approval", "approved", "executing", "in_progress"] } }, select: { id: true } })) return NextResponse.json({ error: "An active repair proposal already exists for this issue." }, { status: 409 });
  try {
    const evidence = { issue: { title: issue.title, description: issue.description, severity: issue.severity, source: issue.source, evidence: issue.evidence }, website: issue.website, relevantTools: issue.toolIds, executor: "connected_wordpress_agent" };
    const agentState = await db.wordPressAgent.findUnique({ where: { id: agentId }, select: { diagnostics: true } });
    const diagnosticData = agentState?.diagnostics && typeof agentState.diagnostics === "object" && !Array.isArray(agentState.diagnostics)
      ? agentState.diagnostics as Prisma.JsonObject
      : {};
    const diagnosticSite = diagnosticData.site && typeof diagnosticData.site === "object" && !Array.isArray(diagnosticData.site)
      ? diagnosticData.site as Prisma.JsonObject
      : {};
    const issueEvidence = issue.evidence && typeof issue.evidence === "object" && !Array.isArray(issue.evidence)
      ? { ...(issue.evidence as Prisma.JsonObject), editablePages: Array.isArray(diagnosticData.editablePages) ? diagnosticData.editablePages : [], environmentType: diagnosticSite.environmentType }
      : issue.evidence;
    const repairPlan = boundedRepairPlan({ fingerprint: issue.fingerprint, title: issue.title, description: issue.description }, issueEvidence);
    const { proposal, instructions } = repairPlan;
    const risk = instructions.steps.length ? determineRepairRisk(instructions.steps.map((step) => step.operation)) : "high";
    const operationIds = instructions.steps.map((step) => step.operation);
    const repair = await db.$transaction(async (transaction) => {
      await transaction.$queryRaw`WITH advisory_lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(hashtext(${issue.websiteId}))) SELECT 1 FROM advisory_lock`;
      const existing = await transaction.repairProposal.findFirst({ where: { issueId: issue.id, status: { in: ["pending_approval", "approved", "executing", "in_progress"] } }, select: { id: true } });
      if (existing) return null;
      const created = await transaction.repairProposal.create({ data: { websiteId: issue.websiteId, issueId: issue.id, risk, initiatingInterface: "wordpress_plugin", operationIds, requiredPermissions: ["manage_options"], approvalStatus: "pending", backupStatus: requiresRecoveryPoint(operationIds) ? "not_started" : "not_required", executionStatus: "not_started", verificationStatus: "not_started", rollbackStatus: "not_requested", proposal: { ...proposal, risk, instructions, executionAvailable: instructions.steps.length > 0, relevantTools: issue.toolIds, evidenceBacked: true } as Prisma.InputJsonValue } });
      await transaction.repairEvent.create({ data: { repairId: created.id, eventType: "proposal_created", actor: "wordpress-admin", details: { issueId: issue.id, websiteId: issue.websiteId, operationIds, risk, initiatingInterface: "wordpress_plugin" } } });
      await transaction.auditLog.create({ data: { action: "repair_proposal_created", actorType: "wordpress_agent", actorId: agentId, organizationId: issue.website.organizationId, resourceType: "repair", resourceId: created.id, sourceHash: requestSourceHash(request), details: { issueId: issue.id, risk, operationIds } } });
      return created;
    });
    if (!repair) return NextResponse.json({ error: "An active repair proposal already exists for this issue." }, { status: 409 });
    const autoApproved = await applyStandingRepairAuthorization({ repairId: repair.id, websiteId: issue.websiteId, organizationId: issue.website.organizationId, operationIds, risk, agentId });
    const finalRepair = autoApproved ? await db.repairProposal.findUnique({ where: { id: repair.id } }) : repair;
    return NextResponse.json(redactApiValue(finalRepair), { status: 201, headers: { "cache-control": "no-store" } });
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "Repair proposal failed." }, { status: 503 });
  }
}
