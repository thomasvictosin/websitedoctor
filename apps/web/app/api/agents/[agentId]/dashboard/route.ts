import { NextResponse } from "next/server";
import { authenticateAgent } from "@/lib/agent-auth";
import { db } from "@/lib/db";
import { redactApiValue } from "@/lib/redaction";

export const runtime = "nodejs";

// The plugin rejects responses over 100 KB (limit_response_size), and a
// truncated body is indistinguishable from an outage, so it showed the
// central app as offline once integrity evidence made issues large. This
// response therefore carries only what the plugin dashboard renders: no
// echoed diagnostics (the plugin has them locally) and no issue evidence.
const RESPONSE_BUDGET_BYTES = 90_000;

export async function GET(request: Request, { params }: { params: Promise<{ agentId: string }> }) {
  const { agentId } = await params;
  const auth = await authenticateAgent(request, agentId);
  if ("response" in auth) return auth.response;
  if (auth.agent.id !== agentId) return NextResponse.json({ error: "Agent identity mismatch." }, { status: 403 });
  const [agent, issues, latestScan, latestCheck] = await Promise.all([
    db.wordPressAgent.findUnique({ where: { id: agentId }, select: { diagnostics: true, lastSeenAt: true, wpVersion: true, phpVersion: true, pluginVersion: true } }),
    db.issue.findMany({
      // Plugin findings plus the outside security probe, which is the evidence a compromised site cannot hide.
      where: { websiteId: auth.agent.websiteId, source: { in: ["wordpress_plugin", "security_probe", "vulnerability_feed"] } },
      orderBy: [{ status: "asc" }, { lastSeenAt: "desc" }],
      take: 50,
      select: {
        id: true, fingerprint: true, title: true, description: true, severity: true, status: true, source: true, lastSeenAt: true, resolvedAt: true, diagnosis: true,
        repairs: {
          orderBy: { createdAt: "desc" }, take: 5,
          select: {
            id: true, status: true, risk: true, operationIds: true, approvalStatus: true, executionStatus: true, verificationStatus: true, rollbackStatus: true, proposal: true, createdAt: true,
            events: { orderBy: { createdAt: "asc" }, take: 20, select: { eventType: true, actor: true, createdAt: true } },
            approvals: { orderBy: { createdAt: "asc" }, take: 5, select: { decision: true, comment: true, createdAt: true } },
            verificationResults: { orderBy: { createdAt: "asc" }, take: 5, select: { status: true, method: true, result: true, createdAt: true } },
            executions: { where: { agentId }, take: 1, select: { status: true, completedAt: true } },
          },
        },
      },
    }),
    db.scanSession.findFirst({ where: { websiteId: auth.agent.websiteId, scanType: "wordpress" }, orderBy: { startedAt: "desc" }, select: { id: true, status: true, startedAt: true, completedAt: true } }),
    db.siteCheck.findFirst({ where: { websiteId: auth.agent.websiteId }, orderBy: { checkedAt: "desc" }, select: { available: true, checkedAt: true, statusCode: true } }),
  ]);
  const diagnostics = agent?.diagnostics && typeof agent.diagnostics === "object" && !Array.isArray(agent.diagnostics)
    ? { collectedAt: (agent.diagnostics as { collectedAt?: unknown }).collectedAt ?? null }
    : null;
  const build = (items: unknown[]) => redactApiValue({ diagnostics, lastSeenAt: agent?.lastSeenAt ?? null, wpVersion: agent?.wpVersion ?? null, phpVersion: agent?.phpVersion ?? null, pluginVersion: agent?.pluginVersion ?? null, latestScan, latestCheck, issues: items });
  let payload = build(issues);
  if (JSON.stringify(payload).length > RESPONSE_BUDGET_BYTES) {
    // Drop the bulkiest optional detail first, then fall back to fewer issues.
    const lean = issues.map((issue) => ({ ...issue, diagnosis: null, repairs: issue.repairs.map(({ proposal: _proposal, verificationResults, ...repair }) => ({ ...repair, proposal: null, verificationResults: verificationResults.map(({ result: _result, ...rest }) => rest) })) }));
    payload = build(lean);
    for (let count = lean.length; JSON.stringify(payload).length > RESPONSE_BUDGET_BYTES && count > 0; count -= 5) payload = build(lean.slice(0, count));
  }
  return NextResponse.json(payload, { headers: { "cache-control": "no-store" } });
}
