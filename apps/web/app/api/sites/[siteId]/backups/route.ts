import { NextResponse } from "next/server";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { findAdminWebsite } from "@/lib/google-drive-authorization";

export const runtime = "nodejs";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ siteId: string }> },
) {
  const authorization = await authorizeOwnerRequest();
  if ("response" in authorization) return authorization.response;
  const { siteId } = await params;
  const website = await findAdminWebsite(authorization.ownerId, siteId);
  if (!website) return NextResponse.json({ error: "Website not found or administrator access is required." }, { status: 404 });

  const [drive, backups] = await Promise.all([
    db.googleDriveConnection.findUnique({
      where: { organizationId: website.organizationId },
      select: { accountEmail: true },
    }),
    db.backup.findMany({
      where: { websiteId: website.id, backupType: "wordpress_repair_snapshot" },
      orderBy: { createdAt: "desc" },
      take: 100,
      select: {
        id: true,
        repairId: true,
        externalId: true,
        backupType: true,
        status: true,
        storageProvider: true,
        sha256: true,
        metadata: true,
        createdAt: true,
        restoreStatus: true,
        restoreCompletedAt: true,
        restoreResult: true,
      },
    }),
  ]);
  return NextResponse.json({
    website: { id: website.id, name: website.name },
    drive: drive ? { connected: true, accountEmail: drive.accountEmail } : { connected: false, accountEmail: null },
    backups: backups.map((backup) => ({
      id: backup.id,
      repairId: backup.repairId,
      backupId: backup.externalId,
      backupType: backup.backupType,
      status: backup.status,
      storageProvider: backup.storageProvider,
      sha256: backup.sha256,
      metadata: backup.metadata,
      createdAt: backup.createdAt,
      restorable: backup.status === "created" && backup.storageProvider === "google_drive",
      restoreStatus: backup.restoreStatus,
      restoreCompletedAt: backup.restoreCompletedAt,
      restoreResult: backup.restoreResult,
    })),
  }, { headers: { "cache-control": "no-store" } });
}
