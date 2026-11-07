import { NextResponse } from "next/server";
import { z } from "zod";
import { authenticateAgent } from "@/lib/agent-auth";
import { CleanupError, dispatchCleanupTasks, loadCleanupPlan, startCleanup } from "@/lib/cleanup-service";
import { db } from "@/lib/db";
import { readBoundedJson } from "@/lib/request-json";

export const runtime = "nodejs";
export const maxDuration = 60;

/** The current cleanup plan, shown in the plugin's Compromise cleanup section. */
export async function GET(request: Request, { params }: { params: Promise<{ agentId: string }> }) {
  const { agentId } = await params;
  const auth = await authenticateAgent(request, agentId);
  if ("response" in auth) return auth.response;
  if (auth.agent.id !== agentId) return NextResponse.json({ error: "Agent identity mismatch." }, { status: 403 });
  const { plan } = await loadCleanupPlan(auth.agent.websiteId);
  return NextResponse.json(plan, { headers: { "cache-control": "no-store" } });
}

const approvalSchema = z.object({
  planDigest: z.string().regex(/^[a-f0-9]{64}$/),
  include: z.array(z.string().regex(/^[a-z0-9:_@. -]{1,120}$/i)).max(60).default([]),
  confirm: z.literal(true),
}).strict();

/**
 * A WordPress administrator approved the plan in the plugin: record the
 * approval and hand the task back immediately for local execution.
 */
export async function POST(request: Request, { params }: { params: Promise<{ agentId: string }> }) {
  const { agentId } = await params;
  const auth = await authenticateAgent(request, agentId);
  if ("response" in auth) return auth.response;
  if (auth.agent.id !== agentId) return NextResponse.json({ error: "Agent identity mismatch." }, { status: 403 });
  const parsed = approvalSchema.safeParse(await readBoundedJson(request, 8192));
  if (!parsed.success) return NextResponse.json({ error: "Approve the displayed cleanup plan (planDigest, include, confirm: true)." }, { status: 400 });
  const website = await db.website.findUnique({ where: { id: auth.agent.websiteId }, select: { organizationId: true } });
  if (!website) return NextResponse.json({ error: "Registered website not found." }, { status: 404 });
  try {
    const started = await startCleanup({ websiteId: auth.agent.websiteId, organizationId: website.organizationId, planDigest: parsed.data.planDigest, include: parsed.data.include, actor: { kind: "wordpress_admin", userId: null } });
    const [task] = await dispatchCleanupTasks(agentId, auth.agent.websiteId, started.repairId);
    if (!task) return NextResponse.json({ error: "The cleanup was approved but could not be dispatched; it will run on the next poll." }, { status: 409 });
    return NextResponse.json({ repairId: started.repairId, task }, { status: 201, headers: { "cache-control": "no-store" } });
  } catch (error) {
    if (error instanceof CleanupError) return NextResponse.json({ error: error.message }, { status: error.status });
    throw error;
  }
}
