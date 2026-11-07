import { NextResponse } from "next/server";
import { authenticateAgent } from "@/lib/agent-auth";
import { CleanupError, cleanupReportSchema, recordCleanupReport } from "@/lib/cleanup-service";
import { readBoundedJson } from "@/lib/request-json";

export const runtime = "nodejs";
// Verification runs the outside security check before answering.
export const maxDuration = 60;

export async function POST(request: Request, { params }: { params: Promise<{ agentId: string }> }) {
  const { agentId } = await params;
  const auth = await authenticateAgent(request, agentId);
  if ("response" in auth) return auth.response;
  if (auth.agent.id !== agentId) return NextResponse.json({ error: "Agent identity mismatch." }, { status: 403 });
  const parsed = cleanupReportSchema.safeParse(await readBoundedJson(request, 120_000));
  if (!parsed.success) return NextResponse.json({ error: "Cleanup report is invalid." }, { status: 400 });
  try {
    const result = await recordCleanupReport({ id: auth.agent.id, websiteId: auth.agent.websiteId }, parsed.data);
    return NextResponse.json(result, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    if (error instanceof CleanupError) return NextResponse.json({ error: error.message }, { status: error.status });
    throw error;
  }
}
