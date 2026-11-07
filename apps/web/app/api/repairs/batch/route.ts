import { NextResponse } from "next/server";
import { z } from "zod";
import { randomUUID } from "node:crypto";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { ownedRepairWhere } from "@/lib/ownership";
import { authorizeRepairExecution, createRepairAuthorizationGrant, findActiveRepairConflict, proposalIsExecutable } from "@/lib/repair-authorization";
import { readBoundedJson } from "@/lib/request-json";
import { requestSourceHash } from "@/lib/rate-limit";
import { commitRepairBatch } from "@/lib/repair-batch-transaction";
import { isHostingRepairProposal } from "@/lib/hosting-proposal-policy";

export const runtime = "nodejs";
const inputSchema = z.object({ repairIds: z.array(z.string().min(1).max(64)).min(1).max(25) }).strict()
  .refine((input) => new Set(input.repairIds).size === input.repairIds.length, "Each repair can be selected only once.");

export async function POST(request: Request) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const parsed = inputSchema.safeParse(await readBoundedJson(request, 8192));
  if (!parsed.success) return NextResponse.json({ error: parsed.error.issues[0]?.message ?? "Select up to 25 repair proposals." }, { status: 400 });
  const repairs = await db.repairProposal.findMany({
    where: { ...ownedRepairWhere(authorization.ownerId), id: { in: parsed.data.repairIds } },
    include: { website: { select: { id: true, organizationId: true, wordpressAgent: { select: { id: true, revokedAt: true, lastSeenAt: true } } } } },
  });
  if (repairs.length !== parsed.data.repairIds.length) return NextResponse.json({ error: "One or more proposals were not found in your organization." }, { status: 404 });
  for (const repair of repairs) {
    const agent = repair.website.wordpressAgent;
    if (isHostingRepairProposal(repair.proposal)) {
      return NextResponse.json({ error: "Hosting proposals cannot be batch-authorized; review them individually. Remote execution is disabled." }, { status: 409 });
    }
    if (repair.status !== "pending_approval" || !agent || agent.revokedAt || agent.lastSeenAt.getTime() < Date.now() - 15 * 60_000
      || !proposalIsExecutable(repair.proposal, repair.operationIds)) {
      return NextResponse.json({ error: `Repair ${repair.id} is not currently eligible for batch execution. Review or refresh the proposals and select executable repairs only.` }, { status: 409 });
    }
    const decision = await authorizeRepairExecution({ repairId: repair.id, websiteId: repair.websiteId, requesterUserId: authorization.ownerId, mode: "batch", batchId: null });
    if (decision.outcome !== "REQUIRES_APPROVAL") return NextResponse.json({ error: `Repair ${repair.id}: ${decision.outcome}: ${decision.reason}` }, { status: decision.outcome === "DENIED" ? 403 : 409 });
  }
  const batchConflicts: string[] = [];
  const targetKeys = new Map<string, string>();
  for (const repair of repairs) {
    const data = repair.proposal && typeof repair.proposal === "object" && !Array.isArray(repair.proposal) ? repair.proposal as Record<string, unknown> : {};
    const instructions = data.instructions && typeof data.instructions === "object" && !Array.isArray(data.instructions) ? data.instructions as Record<string, unknown> : {};
    const step = Array.isArray(instructions.steps) ? instructions.steps[0] as { operation?: string; parameters?: Record<string, string> } : null;
    if (!step?.operation || !step.parameters) continue;
    const params = step.parameters;
    const riskySiteOperation = step.operation === "disable_plugin" || step.operation === "switch_theme";
    if (riskySiteOperation && repairs.some((other) => other.id !== repair.id && other.websiteId === repair.websiteId)) {
      batchConflicts.push(`${repair.id}: plugin/theme activation changes cannot be combined with another repair for the same website because they may alter page behavior used by its verification.`);
    }
    const target = step.operation === "replace_post_link" ? `post:${params.postId}`
      : step.operation === "update_setting" ? `setting:${params.option}`
        : step.operation === "disable_plugin" ? `plugin:${params.plugin}`
          : step.operation === "switch_theme" ? "active-theme" : step.operation;
    const key = `${repair.websiteId}:${target}`;
    const previous = targetKeys.get(key);
    if (previous) batchConflicts.push(`${repair.id}: overlaps target scope with repair ${previous} (${target}). Select only one of these repairs in this batch.`);
    else targetKeys.set(key, repair.id);
  }
  if (batchConflicts.length) return NextResponse.json({ error: "The selected batch contains overlapping or incompatible repairs.", conflicts: batchConflicts }, { status: 409 });
  const now = new Date();
  const batchId = randomUUID();
  try {
    await db.$transaction((tx) => commitRepairBatch(tx, {
      repairs: repairs.map((repair) => ({ ...repair, organizationId: repair.website.organizationId })),
      userId: authorization.ownerId,
      batchId,
      now,
      sourceHash: requestSourceHash(request),
      findConflict: (repair, selectedIds) => findActiveRepairConflict(repair.websiteId, repair.id, repair.proposal, repair.operationIds, selectedIds),
    }));
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "The batch could not be approved." }, { status: 409 });
  }
  return NextResponse.json({ approved: repairs.length, batchId, repairIds: repairs.map((repair) => repair.id), execution: "queued_for_site_poll", results: repairs.map((repair) => ({ repairId: repair.id, websiteId: repair.websiteId, issueId: repair.issueId, operationIds: repair.operationIds, risk: repair.risk, status: "queued" })) }, { headers: { "cache-control": "no-store" } });
}
