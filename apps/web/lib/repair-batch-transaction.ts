import type { Prisma } from "@prisma/client";
import { createRepairAuthorizationGrant } from "./repair-grant-policy.ts";

type BatchRepair = {
  id: string;
  websiteId: string;
  issueId: string | null;
  organizationId: string;
  operationIds: string[];
  proposal: unknown;
};

export async function commitRepairBatch(tx: Prisma.TransactionClient, input: {
  repairs: BatchRepair[];
  userId: string;
  batchId: string;
  now: Date;
  sourceHash: string;
  findConflict: (repair: BatchRepair, selectedIds: string[]) => Promise<string | null>;
}) {
  const websiteIds = [...new Set(input.repairs.map((repair) => repair.websiteId))].sort();
  for (const websiteId of websiteIds) await tx.$queryRaw`WITH advisory_lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(hashtext(${websiteId}))) SELECT 1 FROM advisory_lock`;
  const selectedIds = input.repairs.map((repair) => repair.id);
  for (const repair of input.repairs) {
    const conflict = await input.findConflict(repair, selectedIds);
    if (conflict) throw new Error(`Repair ${repair.id} now overlaps active proposal ${conflict}. No batch approvals were committed.`);
  }
  for (const repair of input.repairs) {
    const proposal = repair.proposal && typeof repair.proposal === "object" && !Array.isArray(repair.proposal) ? repair.proposal as Record<string, unknown> : {};
    const claimed = await tx.repairProposal.updateMany({
      where: { id: repair.id, status: "pending_approval", operationIds: { equals: repair.operationIds } },
      data: { status: "approved", approvalStatus: "approved", approvedAt: input.now, approvedBy: input.userId,
        proposal: { ...proposal, executionRequest: { mode: "apply_on_site_poll", requestedAt: input.now.toISOString(), batchApproved: true, batchId: input.batchId } } as Prisma.InputJsonObject },
    });
    if (claimed.count !== 1) throw new Error("A selected repair changed while the batch was being approved. No batch approvals were committed.");
    const finalProposal: Record<string, unknown> = { ...proposal, executionRequest: { mode: "apply_on_site_poll", requestedAt: input.now.toISOString(), batchApproved: true, batchId: input.batchId } };
    const instructions = finalProposal.instructions && typeof finalProposal.instructions === "object" ? finalProposal.instructions : {};
    await createRepairAuthorizationGrant(tx, { repairId: repair.id, proposal: finalProposal, operationIds: repair.operationIds, websiteId: repair.websiteId, issueId: repair.issueId, userId: input.userId, method: "batch", batchId: input.batchId, scope: { kind: "reviewed_batch", batchId: input.batchId, repairIds: selectedIds, operationIds: repair.operationIds, parameters: instructions } });
    await tx.repairEvent.create({ data: { repairId: repair.id, eventType: "batch_execution_queued", actor: input.userId, details: { executionMode: "apply_on_site_poll", batchSize: input.repairs.length, batchId: input.batchId } } });
    await tx.auditLog.create({ data: { action: "repair_batch_approved_and_queued", actorType: "admin", actorId: input.userId, actorUserId: input.userId, organizationId: repair.organizationId, resourceType: "repair", resourceId: repair.id, sourceHash: input.sourceHash, details: { operationIds: repair.operationIds, batchSize: input.repairs.length, batchId: input.batchId } } });
  }
}
