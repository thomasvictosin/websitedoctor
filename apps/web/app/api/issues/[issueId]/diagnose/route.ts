import { NextResponse } from "next/server";
import { Prisma } from "@prisma/client";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { analyzeFinding } from "@/lib/ai/orchestrator";
import { db } from "@/lib/db";
import { ownedIssueWhere } from "@/lib/ownership";
import { redactApiValue } from "@/lib/redaction";
import { readBoundedJson } from "@/lib/request-json";
import { deterministicIssueDiagnosis } from "@/lib/repair-policy";

export const runtime = "nodejs";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ issueId: string }> },
) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const body = await readBoundedJson(request, 1024);
  const options = z.object({ withAi: z.boolean().default(false) }).safeParse(body ?? {});
  if (!options.success) return NextResponse.json({ error: "Invalid diagnosis options." }, { status: 400 });
  const { issueId } = await params;
  const issue = await db.issue.findFirst({
    where: ownedIssueWhere(authorization.ownerId, issueId),
    include: { website: { select: { id: true, name: true, url: true } } },
  });
  if (!issue) return NextResponse.json({ error: "Issue not found." }, { status: 404 });

  const source = issue.source === "availability_check"
    ? "availability_check"
    : issue.source === "browser_monitor" || issue.source === "browser_test" ? "browser_test" : "wordpress_agent";
  const rawEvidence = issue.evidence && typeof issue.evidence === "object" && !Array.isArray(issue.evidence)
    ? issue.evidence as Record<string, unknown>
    : {};
  const deterministicDiagnosis = deterministicIssueDiagnosis({
    website: { name: issue.website.name, url: issue.website.url },
    fingerprint: issue.fingerprint,
    title: issue.title,
    description: issue.description,
    severity: issue.severity,
    evidence: rawEvidence,
  });
  let analysis: Awaited<ReturnType<typeof analyzeFinding>> | null = null;
  if (options.data.withAi) {
    try { analysis = await analyzeFinding({
    website: { name: issue.website.name, url: issue.website.url },
    source,
    finding: {
      fingerprint: issue.fingerprint,
      title: issue.title,
      description: issue.description,
      severity: issue.severity as "low" | "medium" | "high" | "critical",
    },
    evidence: rawEvidence,
    }); } catch (error) {
      const aiError = error instanceof Error ? error.message : "AI provider is unavailable.";
      analysis = {
        diagnosis: null,
        severity: deterministicDiagnosis.severity as "low" | "medium" | "high" | "critical",
        confidence: null,
        relevantTools: [],
        aiStatus: "unavailable",
        aiError,
      };
    }
  }
  const storedDiagnosis = {
    status: analysis?.aiStatus ?? "deterministic",
    error: analysis?.aiError ?? null,
    diagnosis: (analysis?.diagnosis ?? deterministicDiagnosis) as unknown as Prisma.InputJsonValue,
    analyzedAt: new Date().toISOString(),
    relevantTools: analysis?.relevantTools ?? [],
  } satisfies Prisma.InputJsonObject;
  const updated = await db.issue.updateMany({
    where: ownedIssueWhere(authorization.ownerId, issueId),
    data: {
      severity: analysis?.severity ?? deterministicDiagnosis.severity,
      confidence: analysis?.confidence ?? null,
      diagnosis: storedDiagnosis,
      toolIds: analysis?.relevantTools.map((tool) => tool.id) ?? [],
    },
  });
  if (updated.count !== 1) return NextResponse.json({ error: "Issue not found." }, { status: 404 });
  if (analysis) await db.aiDiagnosis.create({
    data: {
      issueId: issue.id,
      provider: process.env.AI_PROVIDER ?? "ollama",
      model: process.env.OLLAMA_MODEL ?? null,
      status: analysis.aiStatus,
      result: storedDiagnosis,
      error: analysis.aiError,
    },
  });
  return NextResponse.json(redactApiValue({
    issueId: issue.id,
    title: issue.title,
    severity: analysis?.severity ?? deterministicDiagnosis.severity,
    confidence: analysis?.confidence ?? null,
    diagnosis: analysis?.diagnosis ?? deterministicDiagnosis,
    relevantTools: analysis?.relevantTools ?? [],
    aiStatus: analysis?.aiStatus ?? "not_requested",
    aiError: analysis?.aiError ?? null,
  }), { headers: { "cache-control": "no-store" } });
}
