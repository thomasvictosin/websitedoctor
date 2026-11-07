import { NextResponse } from "next/server";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { getRepairAuthorization } from "@/lib/repair-authorization";
import { readBoundedJson } from "@/lib/request-json";
import { requestSourceHash } from "@/lib/rate-limit";

export const runtime = "nodejs";
const inputSchema = z.object({
  mode: z.enum(["manual", "auto_eligible"]),
  allowedOperations: z.array(z.enum(["disable_plugin", "switch_theme", "update_setting", "replace_post_link"])).max(4),
  maxRisk: z.enum(["low", "medium", "high"]),
  maxRepairsPerBatch: z.number().int().min(1).max(25).default(10),
  requireRecoveryPoint: z.literal(true).default(true),
  requireVerification: z.literal(true).default(true),
  paused: z.boolean().default(false),
}).strict().refine((value) => value.mode !== "auto_eligible" || value.allowedOperations.length > 0, "Select at least one operation before enabling automatic execution.");

export async function GET(_request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const authorization = await authorizeOwnerRequest();
  if ("response" in authorization) return authorization.response;
  const { siteId } = await params;
  const website = await db.website.findFirst({ where: ownedWebsiteWhere(authorization.ownerId, siteId), select: { id: true } });
  if (!website) return NextResponse.json({ error: "Website not found." }, { status: 404 });
  return NextResponse.json(await getRepairAuthorization(siteId), { headers: { "cache-control": "no-store" } });
}

export async function PUT(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const { siteId } = await params;
  const website = await db.website.findFirst({ where: ownedWebsiteWhere(authorization.ownerId, siteId), select: { id: true, organizationId: true } });
  if (!website) return NextResponse.json({ error: "Website not found." }, { status: 404 });
  const membership = await db.organizationMember.findUnique({ where: { organizationId_userId: { organizationId: website.organizationId, userId: authorization.ownerId } }, select: { role: true } });
  if (!membership || !["owner", "admin"].includes(membership.role)) return NextResponse.json({ error: "Only organization owners and administrators can change repair permissions." }, { status: 403 });
  const parsed = inputSchema.safeParse(await readBoundedJson(request, 4096));
  if (!parsed.success) return NextResponse.json({ error: parsed.error.issues[0]?.message ?? "Invalid repair authorization policy." }, { status: 400 });
  const value = { ...parsed.data, allowedOperations: [...new Set(parsed.data.allowedOperations)] };
  await db.$transaction(async (tx) => {
    await tx.$queryRaw`WITH advisory_lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(hashtext(${siteId}))) SELECT 1 FROM advisory_lock`;
    const authorizationRecord = await tx.repairAuthorization.upsert({
      where: { websiteId: siteId },
      create: { websiteId: siteId, ownerId: authorization.ownerId, mode: value.mode === "auto_eligible" ? "automatic" : "manual", maxRisk: value.maxRisk, requireRecoveryPoint: value.requireRecoveryPoint, requireVerification: value.requireVerification, maxRepairsPerBatch: value.maxRepairsPerBatch, pausedAt: value.paused ? new Date() : null },
      update: { ownerId: authorization.ownerId, mode: value.mode === "auto_eligible" ? "automatic" : "manual", maxRisk: value.maxRisk, requireRecoveryPoint: value.requireRecoveryPoint, requireVerification: value.requireVerification, maxRepairsPerBatch: value.maxRepairsPerBatch, pausedAt: value.paused ? new Date() : null },
      select: { id: true },
    });
    const operations = ["disable_plugin", "switch_theme", "update_setting", "replace_post_link"];
    for (const operation of operations) {
      const enabled = value.allowedOperations.includes(operation as typeof value.allowedOperations[number]);
      await tx.repairPermission.upsert({
        where: { websiteId_operation: { websiteId: siteId, operation } },
        create: { authorizationId: authorizationRecord.id, ownerId: authorization.ownerId, websiteId: siteId, operation, authorizationMode: enabled && value.mode === "auto_eligible" ? "standing" : "approval", enabled, maxRisk: value.maxRisk, requiredSafetyConditions: { connectedAgentFresh: true, exactSingleOperation: true, operationSpecificRecovery: true, independentVerification: true } },
        update: { authorizationId: authorizationRecord.id, ownerId: authorization.ownerId, authorizationMode: enabled && value.mode === "auto_eligible" ? "standing" : "approval", enabled, maxRisk: value.maxRisk, requiredSafetyConditions: { connectedAgentFresh: true, exactSingleOperation: true, operationSpecificRecovery: true, independentVerification: true } },
      });
    }
    const queued = await tx.repairProposal.findMany({ where: { websiteId: siteId, status: "approved" }, select: { id: true, proposal: true } });
    for (const repair of queued) {
      const proposal = repair.proposal && typeof repair.proposal === "object" && !Array.isArray(repair.proposal) ? repair.proposal as Record<string, unknown> : {};
      const auth = proposal.authorization && typeof proposal.authorization === "object" && !Array.isArray(proposal.authorization) ? proposal.authorization as Record<string, unknown> : {};
      if (auth.mode !== "standing_policy") continue;
      const dispatched = await tx.repairApproval.findFirst({ where: { repairId: repair.id, consumedAt: { not: null }, executionResult: "task_dispatched" }, select: { id: true } });
      if (dispatched) continue;
      await tx.repairProposal.updateMany({ where: { id: repair.id, status: "approved" }, data: { status: "pending_approval", approvalStatus: "pending", approvedAt: null, approvedBy: null } });
      await tx.repairEvent.create({ data: { repairId: repair.id, eventType: "standing_authorization_revoked", actor: authorization.ownerId, details: { paused: value.paused, mode: value.mode } } });
      await tx.auditLog.create({ data: { action: "standing_repair_queue_revoked", actorType: "admin", actorId: authorization.ownerId, actorUserId: authorization.ownerId, organizationId: website.organizationId, resourceType: "repair", resourceId: repair.id, sourceHash: requestSourceHash(request) } });
    }
    await tx.auditLog.create({ data: { action: "repair_authorization_updated", actorType: "admin", actorId: authorization.ownerId, actorUserId: authorization.ownerId, organizationId: website.organizationId, resourceType: "website", resourceId: siteId, sourceHash: requestSourceHash(request), details: value } });
  });
  return NextResponse.json(value, { headers: { "cache-control": "no-store" } });
}
