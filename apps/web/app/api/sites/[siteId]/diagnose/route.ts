import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { analyzeFinding } from "@/lib/ai/orchestrator";
import { deriveEvidenceSignals, selectRelevantTools } from "@/lib/ai/tool-registry";
import { Prisma } from "@prisma/client";
import { redactApiValue } from "@/lib/redaction";

export const runtime = "nodejs";

export async function POST(
  _request: Request,
  { params }: { params: Promise<{ siteId: string }> },
) {
  const authorization = await authorizeOwnerRequest(_request, true);
  if ("response" in authorization) return authorization.response;
  const { siteId } = await params;
  const website = await db.website.findFirst({
    where: ownedWebsiteWhere(authorization.ownerId, siteId),
    include: { checks: { orderBy: { checkedAt: "desc" }, take: 1 } },
  });
  if (!website) return NextResponse.json({ error: "Website not found." }, { status: 404 });
  const check = website.checks[0];
  if (!check) return NextResponse.json({ error: "Run a website check before requesting a diagnosis." }, { status: 409 });

  const evidence = {
    available: check.available,
    statusCode: check.statusCode,
    responseTime: check.responseTime,
    error: check.error,
    checkedAt: check.checkedAt.toISOString(),
    checkId: check.id,
  };
  const title = check.available
    ? `Response time ${check.responseTime ?? "unknown"} ms`
    : `Availability failure${check.statusCode ? ` (HTTP ${check.statusCode})` : ""}`;
  const analysis = await analyzeFinding({
    website: { name: website.name, url: website.url },
    source: "availability_check",
    finding: {
      fingerprint: "availability",
      title,
      description: check.error ?? "The latest availability request completed successfully.",
      severity: check.available ? "low" : "high",
    },
    evidence,
  });
  const tools = selectRelevantTools(deriveEvidenceSignals("availability_check", evidence));
  const diagnosisRecord = {
    status: analysis.aiStatus,
    error: analysis.aiError,
    diagnosis: analysis.diagnosis as Prisma.InputJsonValue | null,
    analyzedAt: new Date().toISOString(),
    relevantTools: tools,
  } satisfies Prisma.InputJsonObject;
  const issue = await db.issue.upsert({
    where: { websiteId_fingerprint: { websiteId: website.id, fingerprint: "availability" } },
    create: {
      websiteId: website.id,
      fingerprint: "availability",
      title,
      description: check.error ?? "The latest availability request completed successfully.",
      severity: analysis.severity,
      source: "availability_check",
      confidence: analysis.confidence,
      evidence,
      diagnosis: diagnosisRecord,
      toolIds: tools.map((tool) => tool.id),
      status: check.available ? "resolved" : "open",
      resolvedAt: check.available ? new Date() : null,
    },
    update: {
      title,
      description: check.error ?? "The latest availability request completed successfully.",
      severity: analysis.severity,
      confidence: analysis.confidence,
      evidence,
      diagnosis: diagnosisRecord,
      toolIds: tools.map((tool) => tool.id),
      lastSeenAt: new Date(),
      status: check.available ? "resolved" : "open",
      resolvedAt: check.available ? new Date() : null,
    },
  });
  await db.aiDiagnosis.create({
    data: {
      issueId: issue.id,
      provider: process.env.AI_PROVIDER ?? "ollama",
      model: process.env.OLLAMA_MODEL ?? null,
      status: analysis.aiStatus,
      result: diagnosisRecord,
      error: analysis.aiError,
    },
  });
  return NextResponse.json(redactApiValue({
    issueId: issue.id,
    diagnosis: analysis.diagnosis as Prisma.InputJsonValue | null,
    severity: analysis.severity,
    confidence: analysis.confidence,
    relevantTools: tools,
    aiStatus: analysis.aiStatus,
    aiError: analysis.aiError,
  }), { headers: { "cache-control": "no-store" } });
}
