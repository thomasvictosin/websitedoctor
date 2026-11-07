import { NextResponse } from "next/server";
import { z } from "zod";
import { authenticateAgent } from "@/lib/agent-auth";
import { CleanupError, dispatchCleanupTasks, startIssueFix } from "@/lib/cleanup-service";
import { db } from "@/lib/db";
import { readBoundedJson } from "@/lib/request-json";

export const runtime = "nodejs";
export const maxDuration = 60;

const schema = z.object({ issueId: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/), confirm: z.literal(true) }).strict();

/** A WordPress administrator clicked Fix in the plugin: approve and return the task to run now. */
export async function POST(request: Request, { params }: { params: Promise<{ agentId: string }> }) {
  const { agentId } = await params;
  const auth = await authenticateAgent(request, agentId);
  if ("response" in auth) return auth.response;
  if (auth.agent.id !== agentId) return NextResponse.json({ error: "Agent identity mismatch." }, { status: 403 });
  const parsed = schema.safeParse(await readBoundedJson(request, 4096));
  if (!parsed.success) return NextResponse.json({ error: "Send issueId and confirm: true." }, { status: 400 });
  const website = await db.website.findUnique({ where: { id: auth.agent.websiteId }, select: { organizationId: true } });
  if (!website) return NextResponse.json({ error: "Registered website not found." }, { status: 404 });
  try {
    const started = await startIssueFix({ issueId: parsed.data.issueId, websiteId: auth.agent.websiteId, organizationId: website.organizationId, actor: { kind: "wordpress_admin", userId: null } });
    const [task] = await dispatchCleanupTasks(agentId, auth.agent.websiteId, started.repairId);
    if (!task) return NextResponse.json({ error: "The fix was approved but could not be dispatched; it will run on the next poll." }, { status: 409 });
    return NextResponse.json({ repairId: started.repairId, task }, { status: 201, headers: { "cache-control": "no-store" } });
  } catch (error) {
    if (error instanceof CleanupError) return NextResponse.json({ error: error.message }, { status: error.status });
    throw error;
  }
}
