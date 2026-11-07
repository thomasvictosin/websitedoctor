import { NextResponse } from "next/server";
import { Prisma } from "@prisma/client";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { ownedRepairWhere } from "@/lib/ownership";
import { readBoundedJson } from "@/lib/request-json";
import { requestSourceHash } from "@/lib/rate-limit";
import { authorizeRepairExecution, createRepairAuthorizationGrant, findActiveRepairConflict, proposalIsExecutable } from "@/lib/repair-authorization";
import { isHostingRepairProposal } from "@/lib/hosting-proposal-policy";

export const runtime = "nodejs";
const decisionSchema = z.object({ decision: z.enum(["approve", "approve_and_apply", "reject"]) });

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ repairId: string }> },
) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const { repairId } = await params;
  const body = await readBoundedJson(request, 4096);
  const parsed = decisionSchema.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "Choose approve or reject." }, { status: 400 });
  const proposal = await db.repairProposal.findFirst({
    where: ownedRepairWhere(authorization.ownerId, repairId),
    select: { id: true, status: true, websiteId: true, issueId: true, operationIds: true, proposal: true, website: { select: { organizationId: true, wordpressAgent: { select: { revokedAt: true, lastSeenAt: true } } } } },
  });
  if (!proposal) return NextResponse.json({ error: "Repair proposal not found." }, { status: 404 });
  const proposalData = proposal.proposal && typeof proposal.proposal === "object" && !Array.isArray(proposal.proposal)
    ? proposal.proposal as Record<string, unknown>
    : {};
  const isHostingProposal = isHostingRepairProposal(proposalData);
  if (parsed.data.decision === "approve_and_apply" && isHostingProposal) {
    return NextResponse.json({ error: "Hosting repair execution is disabled. Approval can only record review of this proposal." }, { status: 501 });
  }
  if (parsed.data.decision === "approve_and_apply" && !proposalIsExecutable(proposal.proposal, proposal.operationIds)) {
    return NextResponse.json({ error: "This proposal has no unambiguous executable allowlisted operation. Review the manual guidance instead." }, { status: 400 });
  }
  if (parsed.data.decision === "approve_and_apply") {
    const decision = await authorizeRepairExecution({ repairId, websiteId: proposal.websiteId, requesterUserId: authorization.ownerId, mode: "explicit" });
    if (decision.outcome !== "REQUIRES_APPROVAL") return NextResponse.json({ error: `${decision.outcome}: ${decision.reason}` }, { status: decision.outcome === "DENIED" ? 403 : 409 });
  }
  if (parsed.data.decision === "approve_and_apply" && (!proposal.website.wordpressAgent || proposal.website.wordpressAgent.revokedAt
    || proposal.website.wordpressAgent.lastSeenAt.getTime() < Date.now() - 15 * 60_000)) {
    return NextResponse.json({ error: "The connected WordPress executor is offline or stale. Reconnect the plugin and refresh diagnostics before queuing this repair." }, { status: 409 });
  }
  if (parsed.data.decision === "approve_and_apply") {
    const conflict = await findActiveRepairConflict(proposal.websiteId, repairId, proposal.proposal, proposal.operationIds);
    if (conflict) return NextResponse.json({ error: `This repair overlaps active proposal ${conflict}. Complete or reject that proposal before queuing this repair.` }, { status: 409 });
  }
  const decision = parsed.data.decision === "approve_and_apply" ? "approve" : parsed.data.decision;
  const queueExecution = parsed.data.decision === "approve_and_apply";
  const updated = await db.$transaction(async (transaction) => {
    if (queueExecution) {
      await transaction.$queryRaw`WITH advisory_lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(hashtext(${proposal.websiteId}))) SELECT 1 FROM advisory_lock`;
      const lockedConflict = await findActiveRepairConflict(proposal.websiteId, repairId, proposal.proposal, proposal.operationIds);
      if (lockedConflict) return { count: 0, conflictId: lockedConflict };
    }
    const result = await transaction.repairProposal.updateMany({
      where: { ...ownedRepairWhere(authorization.ownerId, repairId), status: "pending_approval" },
      data: decision === "approve"
        ? { status: "approved", approvalStatus: "approved", approvedAt: new Date(), approvedBy: "local-admin",
            ...(queueExecution ? { proposal: { ...proposalData, executionRequest: { mode: "apply_on_site_poll", requestedAt: new Date().toISOString() } } as Prisma.InputJsonValue } : {}) }
        : { status: "rejected", approvalStatus: "rejected" },
    });
    if (result.count !== 1) return { ...result, conflictId: null };
    if (queueExecution) {
      const finalProposal: Record<string, unknown> = { ...proposalData, executionRequest: { mode: "apply_on_site_poll", requestedAt: new Date().toISOString() } };
      await transaction.repairProposal.update({ where: { id: repairId }, data: { proposal: finalProposal as Prisma.InputJsonObject } });
      await createRepairAuthorizationGrant(transaction, { repairId, proposal: finalProposal, operationIds: proposal.operationIds, websiteId: proposal.websiteId, issueId: proposal.issueId, userId: authorization.ownerId, method: "individual", scope: { kind: "repair", repairId, operationIds: proposal.operationIds, parameters: finalProposal.instructions } as Prisma.InputJsonValue });
    }
    else await transaction.repairApproval.create({ data: { repairId, actorUserId: authorization.ownerId, decision } });
    await transaction.repairEvent.create({
      data: {
        repairId,
        eventType: queueExecution ? "execution_queued" : (decision === "approve" ? "approved" : "rejected"),
        actor: "local-admin",
        details: { decision, ...(queueExecution ? { executionMode: "apply_on_site_poll" } : {}) },
      },
    });
    await transaction.auditLog.create({
      data: {
        action: queueExecution ? "repair_approved_and_queued" : (decision === "approve" ? "repair_approved" : "repair_rejected"),
        actorType: "admin",
        actorId: authorization.ownerId,
        actorUserId: authorization.ownerId,
        organizationId: proposal.website.organizationId,
        resourceType: "repair",
        resourceId: repairId,
        sourceHash: requestSourceHash(request),
      },
    });
    return { ...result, conflictId: null };
  });
  if (updated.count !== 1) {
    const exists = await db.repairProposal.findFirst({
      where: ownedRepairWhere(authorization.ownerId, repairId),
      select: { id: true },
    });
    if (!exists) return NextResponse.json({ error: "Repair proposal not found." }, { status: 404 });
    return NextResponse.json({ error: updated.conflictId ? `This repair overlaps active proposal ${updated.conflictId}. Complete or reject that proposal before queuing this repair.` : "Only pending proposals can be approved or rejected." }, { status: 409 });
  }
  return NextResponse.json({
    id: repairId,
    status: decision === "approve" ? "approved" : "rejected",
    execution: queueExecution ? "queued_for_site_poll" : (decision === "approve" && !isHostingProposal ? "awaiting_local_executor" : "none"),
    message: queueExecution
      ? "Approved and queued. The connected WordPress plugin will apply it on its next poll (WordPress Cron runs when the site receives traffic)."
      : decision === "approve"
      ? isHostingProposal
        ? "Review acknowledged and recorded. Hosting repair execution is disabled; no remote change was made."
        : "Approved and recorded. A connected WordPress administrator can apply it from the plugin."
      : "Proposal rejected.",
  });
}
