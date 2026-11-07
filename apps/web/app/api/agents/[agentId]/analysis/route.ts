import { NextResponse } from "next/server";
import { Prisma } from "@prisma/client";
import { z } from "zod";
import { authenticateAgent } from "@/lib/agent-auth";
import { analyzeFinding } from "@/lib/ai/orchestrator";
import { db } from "@/lib/db";
import { readBoundedJson } from "@/lib/request-json";
import { redactApiValue } from "@/lib/redaction";

export const runtime = "nodejs";
const inputSchema = z.object({ issueId: z.string().min(1).max(64) });

export async function POST(request: Request, { params }: { params: Promise<{ agentId: string }> }) {
  const { agentId } = await params;
  const auth = await authenticateAgent(request, agentId);
  if ("response" in auth) return auth.response;
  if (auth.agent.id !== agentId) return NextResponse.json({ error: "Agent identity mismatch." }, { status: 403 });
  const parsed = inputSchema.safeParse(await readBoundedJson(request, 4096));
  if (!parsed.success) return NextResponse.json({ error: "A valid issue ID is required." }, { status: 400 });
  const issue = await db.issue.findFirst({ where: { id: parsed.data.issueId, websiteId: auth.agent.websiteId, source: "wordpress_plugin" }, include: { website: { select: { name: true, url: true } } } });
  if (!issue) return NextResponse.json({ error: "Issue not found for this WordPress site." }, { status: 404 });
  const evidence = issue.evidence && typeof issue.evidence === "object" && !Array.isArray(issue.evidence) ? issue.evidence as Record<string, unknown> : {};
  const analysis = await analyzeFinding({ website: issue.website, source: "wordpress_agent", finding: { fingerprint: issue.fingerprint, title: issue.title, description: issue.description, severity: issue.severity as "low" | "medium" | "high" | "critical" }, evidence });
  const stored = { status: analysis.aiStatus, error: analysis.aiError, diagnosis: analysis.diagnosis as Prisma.InputJsonValue | null, analyzedAt: new Date().toISOString(), relevantTools: analysis.relevantTools } satisfies Prisma.InputJsonObject;
  await db.$transaction([
    db.issue.update({ where: { id: issue.id }, data: { severity: analysis.severity, confidence: analysis.confidence, diagnosis: stored, toolIds: analysis.relevantTools.map((tool) => tool.id) } }),
    db.aiDiagnosis.create({ data: { issueId: issue.id, provider: process.env.AI_PROVIDER ?? "ollama", model: process.env.OLLAMA_MODEL ?? null, status: analysis.aiStatus, result: stored, error: analysis.aiError } }),
  ]);
  return NextResponse.json(redactApiValue({ issueId: issue.id, aiStatus: analysis.aiStatus, aiError: analysis.aiError, diagnosis: analysis.diagnosis }), { headers: { "cache-control": "no-store" } });
}
