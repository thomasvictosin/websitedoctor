import { NextResponse } from "next/server";
import { Prisma } from "@prisma/client";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { findAdminWebsite } from "@/lib/google-drive-authorization";
import { requestSourceHash } from "@/lib/rate-limit";

export const runtime = "nodejs";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ backupId: string }> },
) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const { backupId } = await params;
  const backup = await db.backup.findFirst({
    where: {
      id: backupId,
      backupType: "wordpress_repair_snapshot",
      status: "created",
      storageProvider: "google_drive",
    },
    select: {
      id: true,
      websiteId: true,
      repairId: true,
      externalId: true,
      restoreStatus: true,
      website: { select: { name: true, organizationId: true } },
    },
  });
  if (!backup || !backup.repairId || !backup.externalId) {
    return NextResponse.json({ error: "A restorable Google Drive recovery point was not found." }, { status: 404 });
  }
  const website = await findAdminWebsite(authorization.ownerId, backup.websiteId);
  if (!website) return NextResponse.json({ error: "Website not found or administrator access is required." }, { status: 404 });
  if (!await db.googleDriveConnection.findUnique({ where: { organizationId: website.organizationId }, select: { id: true } })) {
    return NextResponse.json({ error: "Google Drive is not connected for this website." }, { status: 409 });
  }
  const agent = await db.wordPressAgent.findUnique({
    where: { websiteId: website.id },
    select: { id: true, revokedAt: true },
  });
  if (!agent || agent.revokedAt) return NextResponse.json({ error: "Reconnect the WordPress plugin before requesting a restore." }, { status: 409 });

  const claimed = await db.backup.updateMany({
    where: { id: backup.id, status: "created", restoreStatus: { in: ["not_requested", "failed"] } },
    data: {
      restoreStatus: "requested",
      restoreRequestedAt: new Date(),
      restoreRequestedBy: authorization.ownerId,
      restoreCompletedAt: null,
      restoreResult: Prisma.DbNull,
    },
  });
  if (claimed.count !== 1) {
    return NextResponse.json({ error: "This backup already has a pending or completed restore request." }, { status: 409 });
  }
  await db.auditLog.create({
    data: {
      action: "wordpress_recovery_point_restore_requested",
      actorType: "admin",
      actorId: authorization.ownerId,
      actorUserId: authorization.ownerId,
      organizationId: website.organizationId,
      resourceType: "backup",
      resourceId: backup.id,
      sourceHash: requestSourceHash(request),
      details: { websiteId: website.id, repairId: backup.repairId, backupId: backup.externalId, restoreScope: "one_wordpress_repair_operation" },
    },
  });
  return NextResponse.json({
    id: backup.id,
    status: "requested",
    message: "Restore request queued for this website. A WordPress administrator must confirm it in the paired plugin.",
  }, { status: 202, headers: { "cache-control": "no-store" } });
}
