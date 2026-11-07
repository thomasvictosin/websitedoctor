import { NextResponse } from "next/server";
import { authenticateAgent } from "@/lib/agent-auth";
import { db } from "@/lib/db";
import { redactApiValue } from "@/lib/redaction";

export const runtime = "nodejs";

export async function GET(request: Request, { params }: { params: Promise<{ agentId: string }> }) {
  const { agentId } = await params;
  const auth = await authenticateAgent(request, agentId);
  if ("response" in auth) return auth.response;
  if (auth.agent.id !== agentId) return NextResponse.json({ error: "Agent identity mismatch." }, { status: 403 });
  const [agent, issues, latestScan, latestCheck] = await Promise.all([
    db.wordPressAgent.findUnique({ where: { id: agentId }, select: { diagnostics: true, lastSeenAt: true, wpVersion: true, phpVersion: true, pluginVersion: true } }),
    db.issue.findMany({
      where: { websiteId: auth.agent.websiteId, source: "wordpress_plugin" },
      orderBy: [{ status: "asc" }, { lastSeenAt: "desc" }],
      take: 50,
      include: {
        repairs: { orderBy: { createdAt: "desc" }, take: 20, include: { events: { orderBy: { createdAt: "asc" } }, approvals: { orderBy: { createdAt: "asc" } }, verificationResults: { orderBy: { createdAt: "asc" } }, executions: { where: { agentId }, take: 1 } } },
      },
    }),
    db.scanSession.findFirst({ where: { websiteId: auth.agent.websiteId, scanType: "wordpress" }, orderBy: { startedAt: "desc" }, select: { id: true, status: true, startedAt: true, completedAt: true } }),
    db.siteCheck.findFirst({ where: { websiteId: auth.agent.websiteId }, orderBy: { checkedAt: "desc" }, select: { available: true, checkedAt: true, statusCode: true } }),
  ]);
  return NextResponse.json(redactApiValue({ diagnostics: agent?.diagnostics ?? null, lastSeenAt: agent?.lastSeenAt ?? null, wpVersion: agent?.wpVersion ?? null, phpVersion: agent?.phpVersion ?? null, pluginVersion: agent?.pluginVersion ?? null, latestScan, latestCheck, issues }), { headers: { "cache-control": "no-store" } });
}
