import { NextResponse } from "next/server";
import { authenticateAgent } from "@/lib/agent-auth";
import { db } from "@/lib/db";
import { downloadRepairSnapshotFromDrive } from "@/lib/google-drive";
import { repairParametersFromProposal, validateWordPressRecoverySnapshot } from "@/lib/wordpress-recovery-snapshot";
import { requestSourceHash } from "@/lib/rate-limit";

export const runtime = "nodejs";

export async function GET(
  request: Request,
  { params }: { params: Promise<{ agentId: string; backupId: string }> },
) {
  const { agentId, backupId } = await params;
  const auth = await authenticateAgent(request, agentId);
  if ("response" in auth) return auth.response;
  if (auth.agent.id !== agentId) return NextResponse.json({ error: "Agent identity mismatch." }, { status: 403 });
  const backup = await db.backup.findFirst({
    where: {
      externalId: backupId,
      agentId,
      websiteId: auth.agent.websiteId,
      backupType: "wordpress_repair_snapshot",
      status: "created",
      storageProvider: "google_drive",
      restoreStatus: "requested",
    },
    select: {
      id: true,
      repair: { select: { proposal: true, operationIds: true, website: { select: { organizationId: true } } } },
    },
  });
  if (!backup?.repair) return NextResponse.json({ error: "A pending, site-scoped recovery request was not found." }, { status: 404 });
  const operation = repairParametersFromProposal(backup.repair.proposal);
  if (!operation || backup.repair.operationIds.length !== 1 || backup.repair.operationIds[0] !== operation.operation) {
    return NextResponse.json({ error: "The saved repair no longer has one supported recovery operation." }, { status: 409 });
  }
  try {
    const snapshot = await downloadRepairSnapshotFromDrive({
      organizationId: backup.repair.website.organizationId,
      backupId: backup.id,
    });
    const validated = validateWordPressRecoverySnapshot({
      backupId,
      repairOperation: operation.operation,
      repairParameters: operation.parameters,
      snapshot,
    });
    if (!validated.ok) return NextResponse.json({ error: validated.message }, { status: 409 });
    await db.auditLog.create({
      data: {
        action: "wordpress_recovery_point_restore_downloaded",
        actorType: "wordpress_agent",
        actorId: agentId,
        organizationId: backup.repair.website.organizationId,
        resourceType: "backup",
        resourceId: backup.id,
        sourceHash: requestSourceHash(request),
        details: { websiteId: auth.agent.websiteId, backupId, restoreScope: "one_wordpress_repair_operation" },
      },
    });
    return NextResponse.json({ backupId, recoveryPoint: validated.snapshot }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    return NextResponse.json({
      error: error instanceof Error ? error.message : "The Google Drive recovery point could not be downloaded.",
    }, { status: 502 });
  }
}
