import { createHash } from "node:crypto";
import { NextResponse } from "next/server";
import { Prisma } from "@prisma/client";
import { authenticateAgent } from "@/lib/agent-auth";
import { db } from "@/lib/db";
import { requestSourceHash } from "@/lib/rate-limit";
import { readBoundedJson } from "@/lib/request-json";
import { repairParametersFromProposal, validateWordPressRecoverySnapshot } from "@/lib/wordpress-recovery-snapshot";
import { uploadRepairSnapshotToDrive } from "@/lib/google-drive";

export const runtime = "nodejs";
const MAX_BACKUP_REQUEST_BYTES = 600_000;

export async function POST(request: Request, { params }: { params: Promise<{ agentId: string }> }) {
  const { agentId } = await params;
  const auth = await authenticateAgent(request, agentId, MAX_BACKUP_REQUEST_BYTES);
  if ("response" in auth) return auth.response;
  if (auth.agent.id !== agentId) return NextResponse.json({ error: "Agent identity mismatch." }, { status: 403 });

  const body = await readBoundedJson(request, MAX_BACKUP_REQUEST_BYTES);
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return NextResponse.json({ error: "A bounded WordPress recovery point is required." }, { status: 400 });
  }
  const input = body as Record<string, unknown>;
  if (typeof input.repairId !== "string" || input.repairId.length > 64
    || typeof input.backupId !== "string" || input.backupId.length > 64
    || !Object.hasOwn(input, "recoveryPoint")) {
    return NextResponse.json({ error: "The repair and recovery point identifiers are required." }, { status: 400 });
  }
  const repair = await db.repairProposal.findFirst({
    where: {
      id: input.repairId,
      websiteId: auth.agent.websiteId,
      status: "approved",
      executions: { none: { agentId } },
    },
    select: {
      id: true,
      websiteId: true,
      operationIds: true,
      proposal: true,
      website: { select: { name: true, organizationId: true } },
    },
  });
  if (!repair) return NextResponse.json({ error: "An approved, not-yet-executed repair for this WordPress site is required." }, { status: 409 });
  const operation = repairParametersFromProposal(repair.proposal);
  if (!operation || repair.operationIds.length !== 1 || repair.operationIds[0] !== operation.operation) {
    return NextResponse.json({ error: "The approved repair does not contain one supported exact operation." }, { status: 409 });
  }
  const validated = validateWordPressRecoverySnapshot({
    backupId: input.backupId,
    repairOperation: operation.operation,
    repairParameters: operation.parameters,
    snapshot: input.recoveryPoint,
  });
  if (!validated.ok) return NextResponse.json({ error: validated.message }, { status: 400 });

  let serializedSnapshot: string;
  try {
    serializedSnapshot = JSON.stringify(validated.snapshot);
  } catch {
    return NextResponse.json({ error: "The recovery point could not be serialized." }, { status: 400 });
  }
  if (Buffer.byteLength(serializedSnapshot, "utf8") > 512_000) {
    return NextResponse.json({ error: "The recovery point exceeds the 512 KB limit." }, { status: 413 });
  }
  const snapshotDigest = createHash("sha256").update(serializedSnapshot).digest("hex");
  const existing = await db.backup.findUnique({
    where: { repairId_externalId: { repairId: repair.id, externalId: input.backupId } },
    select: { id: true, status: true, sha256: true, storageFileId: true, storageFolderId: true, metadata: true },
  });
  if (existing?.status === "created" && existing.storageFileId && existing.storageFolderId) {
    const metadata = existing.metadata && typeof existing.metadata === "object" && !Array.isArray(existing.metadata)
      ? existing.metadata as Record<string, unknown>
      : {};
    if (metadata.snapshotSha256 !== snapshotDigest) {
      return NextResponse.json({ error: "This backup identifier was already used for a different recovery point." }, { status: 409 });
    }
    return NextResponse.json({
      backupId: input.backupId,
      status: "created",
      sha256: existing.sha256,
    }, { headers: { "cache-control": "no-store" } });
  }
  if (existing?.status === "uploading") {
    return NextResponse.json({ error: "This recovery point is already being uploaded." }, { status: 409 });
  }

  const metadata = {
    operation: operation.operation,
    target: validated.target,
    snapshotSha256: snapshotDigest,
    restoreScope: "one_wordpress_repair_operation",
  } satisfies Prisma.InputJsonObject;
  const backupRecord = existing
    ? await db.backup.update({
        where: { repairId_externalId: { repairId: repair.id, externalId: input.backupId } },
        data: { status: "uploading", metadata, storageProvider: "google_drive" },
        select: { id: true },
      })
    : await db.backup.create({
        data: {
          websiteId: repair.websiteId,
          repairId: repair.id,
          agentId,
          externalId: input.backupId,
          backupType: "wordpress_repair_snapshot",
          status: "uploading",
          storageProvider: "google_drive",
          metadata,
        },
        select: { id: true },
      });

  try {
    const uploaded = await uploadRepairSnapshotToDrive({
      organizationId: repair.website.organizationId,
      websiteId: repair.websiteId,
      websiteName: repair.website.name,
      repairId: repair.id,
      pluginBackupId: input.backupId,
      snapshot: validated.snapshot,
    });
    await db.backup.update({
      where: { id: backupRecord.id },
      data: {
        status: "created",
        storageProvider: "google_drive",
        storageFileId: uploaded.fileId,
        storageFolderId: uploaded.folderId,
        sha256: uploaded.sha256,
        metadata: { ...metadata, driveSnapshotFormat: "encrypted_gzip_json_v1" },
      },
    });
    await db.auditLog.create({
      data: {
        action: "wordpress_recovery_point_synced",
        actorType: "wordpress_agent",
        actorId: agentId,
        organizationId: repair.website.organizationId,
        resourceType: "backup",
        resourceId: backupRecord.id,
        sourceHash: requestSourceHash(request),
        details: { websiteId: repair.websiteId, repairId: repair.id, operation: operation.operation, target: validated.target, storageProvider: "google_drive" },
      },
    });
    return NextResponse.json({ backupId: input.backupId, status: "created", sha256: uploaded.sha256 }, {
      status: existing ? 200 : 201,
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    await db.backup.update({ where: { id: backupRecord.id }, data: { status: "failed" } });
    await db.auditLog.create({
      data: {
        action: "wordpress_recovery_point_sync_failed",
        actorType: "wordpress_agent",
        actorId: agentId,
        organizationId: repair.website.organizationId,
        resourceType: "backup",
        resourceId: backupRecord.id,
        sourceHash: requestSourceHash(request),
        details: { websiteId: repair.websiteId, repairId: repair.id, operation: operation.operation, target: validated.target, storageProvider: "google_drive" },
      },
    });
    return NextResponse.json({
      error: error instanceof Error ? error.message : "The recovery point could not be synced to Google Drive. No repair should be applied.",
    }, { status: 502 });
  }
}
