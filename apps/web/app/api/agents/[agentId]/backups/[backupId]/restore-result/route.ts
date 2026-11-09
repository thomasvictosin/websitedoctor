import { NextResponse } from "next/server";
import { z } from "zod";
import { authenticateAgent } from "@/lib/agent-auth";
import { db } from "@/lib/db";
import { readBoundedJson } from "@/lib/request-json";
import { requestSourceHash } from "@/lib/rate-limit";

export const runtime = "nodejs";
const resultSchema = z.object({
  status: z.enum(["restored", "failed"]),
  message: z.string().min(1).max(2000),
}).strict();

export async function POST(
  request: Request,
  { params }: { params: Promise<{ agentId: string; backupId: string }> },
) {
  const { agentId, backupId } = await params;
  const auth = await authenticateAgent(request, agentId);
  if ("response" in auth) return auth.response;
  const parsed = resultSchema.safeParse(await readBoundedJson(request, 4096));
  if (!parsed.success) return NextResponse.json({ error: "A valid restore result is required." }, { status: 400 });
  const backup = await db.backup.findFirst({
    where: {
      externalId: backupId,
      agentId,
      websiteId: auth.agent.websiteId,
      status: "created",
      restoreStatus: "requested",
      storageProvider: "google_drive",
    },
    select: { id: true, repairId: true, website: { select: { organizationId: true } } },
  });
  if (!backup) return NextResponse.json({ error: "No pending restore request exists for this website and recovery point." }, { status: 404 });
  const nextStatus = parsed.data.status;
  const updated = await db.backup.updateMany({
    where: { id: backup.id, restoreStatus: "requested" },
    data: {
      restoreStatus: nextStatus,
      restoreCompletedAt: new Date(),
      restoreResult: { status: nextStatus, message: parsed.data.message.slice(0, 2000) },
    },
  });
  if (updated.count !== 1) return NextResponse.json({ error: "The restore request has already been completed." }, { status: 409 });
  await db.auditLog.create({
    data: {
      action: `wordpress_recovery_point_${nextStatus}`,
      actorType: "wordpress_agent",
      actorId: agentId,
      organizationId: backup.website.organizationId,
      resourceType: "backup",
      resourceId: backup.id,
      sourceHash: requestSourceHash(request),
      details: { websiteId: auth.agent.websiteId, repairId: backup.repairId, backupId, message: parsed.data.message.slice(0, 2000) },
    },
  });
  return NextResponse.json({ backupId, status: nextStatus }, { headers: { "cache-control": "no-store" } });
}
