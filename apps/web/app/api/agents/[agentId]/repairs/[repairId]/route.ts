import { NextResponse } from "next/server";
import { z } from "zod";
import { Prisma } from "@prisma/client";
import { authenticateAgent } from "@/lib/agent-auth";
import { db } from "@/lib/db";
import { readBoundedJson } from "@/lib/request-json";
import { requestSourceHash } from "@/lib/rate-limit";
import { authorizeRepairExecution, createRepairAuthorizationGrant, findActiveRepairConflict } from "@/lib/repair-authorization";
import { isHostingRepairProposal } from "@/lib/hosting-proposal-policy";

export const runtime = "nodejs";
const decisionSchema = z.object({ decision: z.enum(["approve", "reject"]) });

export async function PATCH(request: Request, { params }: { params: Promise<{ agentId: string; repairId: string }> }) {
  const { agentId, repairId } = await params;
  const auth = await authenticateAgent(request, agentId);
  if ("response" in auth) return auth.response;
  if (auth.agent.id !== agentId) return NextResponse.json({ error: "Agent identity mismatch." }, { status: 403 });
  const parsed = decisionSchema.safeParse(await readBoundedJson(request, 4096));
  if (!parsed.success) return NextResponse.json({ error: "Choose approve or reject." }, { status: 400 });
  const repair = await db.repairProposal.findFirst({ where: { id: repairId, websiteId: auth.agent.websiteId }, select: { id: true, status: true, issueId: true, proposal: true, operationIds: true, website: { select: { organizationId: true } } } });
  if (!repair) return NextResponse.json({ error: "Repair proposal not found." }, { status: 404 });
  if (isHostingRepairProposal(repair.proposal)) {
    return NextResponse.json({ error: "Hosting proposals are review-only and cannot be approved by a WordPress agent." }, { status: 409 });
  }
  const nextStatus = parsed.data.decision === "approve" ? "approved" : "rejected";
  if (parsed.data.decision === "approve") {
    const decision = await authorizeRepairExecution({ repairId, websiteId: auth.agent.websiteId, mode: "explicit" });
    if (decision.outcome !== "REQUIRES_APPROVAL") return NextResponse.json({ error: `${decision.outcome}: ${decision.reason}` }, { status: 409 });
  }
  const updated = await db.$transaction(async (transaction) => {
    if (parsed.data.decision === "approve") {
      await transaction.$queryRaw`WITH advisory_lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(hashtext(${auth.agent.websiteId}))) SELECT 1 FROM advisory_lock`;
      const conflict = await findActiveRepairConflict(auth.agent.websiteId, repairId, repair.proposal, repair.operationIds);
      if (conflict) return { ok: false, conflict };
    }
    const claimed = await transaction.repairProposal.updateMany({ where: { id: repairId, websiteId: auth.agent.websiteId, status: "pending_approval" }, data: parsed.data.decision === "approve" ? { status: nextStatus, approvalStatus: nextStatus, approvedAt: new Date(), approvedBy: "wordpress-admin" } : { status: nextStatus, approvalStatus: nextStatus } });
    if (claimed.count !== 1) return { ok: false, conflict: null };
    if (parsed.data.decision === "approve") await createRepairAuthorizationGrant(transaction, { repairId, proposal: repair.proposal, operationIds: repair.operationIds, websiteId: auth.agent.websiteId, issueId: repair.issueId, method: "wordpress_admin", scope: { kind: "repair", repairId, operationIds: repair.operationIds, proposal: repair.proposal as Prisma.InputJsonValue } });
    else await transaction.repairApproval.create({ data: { repairId, decision: parsed.data.decision, comment: "Recorded from the connected WordPress plugin." } });
    await transaction.repairEvent.create({ data: { repairId, eventType: nextStatus, actor: "wordpress-admin", details: { decision: parsed.data.decision, agentId } } });
    await transaction.auditLog.create({ data: { action: `repair_${nextStatus}`, actorType: "wordpress_agent", actorId: agentId, organizationId: repair.website.organizationId, resourceType: "repair", resourceId: repairId, sourceHash: requestSourceHash(request) } });
    return { ok: true, conflict: null };
  });
  if (!updated.ok) return NextResponse.json({ error: updated.conflict ? `This repair overlaps active proposal ${updated.conflict}. Complete or reject that proposal before approving this repair.` : "Only pending proposals can be approved or rejected." }, { status: 409 });
  return NextResponse.json({ id: repairId, status: nextStatus, execution: parsed.data.decision === "approve" ? "awaiting_local_executor" : "none" });
}
