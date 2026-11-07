import { NextResponse } from "next/server";
import { authenticateAgent } from "@/lib/agent-auth";
import { db } from "@/lib/db";
import { requestSourceHash } from "@/lib/rate-limit";

export const runtime = "nodejs";

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ agentId: string }> },
) {
  const { agentId } = await params;
  const auth = await authenticateAgent(request, agentId);
  if ("response" in auth) return auth.response;
  if (auth.agent.id !== agentId) return NextResponse.json({ error: "Agent identity mismatch." }, { status: 403 });
  await db.$transaction(async (transaction) => {
    const revokedAt = new Date();
    await transaction.wordPressAgent.update({
      where: { id: agentId },
      data: { revokedAt },
    });
    await transaction.installationCredential.updateMany({
      where: { agentId, revokedAt: null },
      data: { revokedAt },
    });
    await transaction.auditLog.create({
      data: {
        action: "wordpress_agent_revoked",
        actorType: "wordpress_agent",
        actorId: auth.agent.id,
        resourceType: "wordpress_agent",
        resourceId: auth.agent.id,
        sourceHash: requestSourceHash(request),
      },
    });
  });
  return NextResponse.json({ ok: true });
}
