import { NextResponse } from "next/server";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { requestSourceHash } from "@/lib/rate-limit";

export const runtime = "nodejs";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ agentId: string }> },
) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const { agentId } = await params;
  const where = {
      id: agentId,
      revokedAt: null,
      website: { organization: { members: { some: { userId: authorization.ownerId } } } },
    };
  const agent = await db.wordPressAgent.findFirst({
    where,
    select: { id: true, website: { select: { organizationId: true } } },
  });
  if (!agent) return NextResponse.json({ error: "Connected agent not found." }, { status: 404 });
  const result = await db.$transaction(async (transaction) => {
    const revokedAt = new Date();
    const updated = await transaction.wordPressAgent.updateMany({
      where: { id: agent.id, revokedAt: null },
      data: { revokedAt },
    });
    if (updated.count !== 1) return updated;
    await transaction.installationCredential.updateMany({
      where: { agentId: agent.id, revokedAt: null },
      data: { revokedAt },
    });
    await transaction.auditLog.create({
      data: {
        action: "wordpress_agent_revoked",
        actorType: "admin",
        actorId: authorization.ownerId,
        actorUserId: authorization.ownerId,
        organizationId: agent.website.organizationId,
        resourceType: "wordpress_agent",
        resourceId: agent.id,
        sourceHash: requestSourceHash(request),
      },
    });
    return updated;
  });
  if (result.count === 0) return NextResponse.json({ error: "Connected agent not found." }, { status: 404 });
  return NextResponse.json({ ok: true });
}
