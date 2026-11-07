import { NextResponse } from "next/server";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { getAiEngine } from "@/lib/ai";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { readBoundedJson } from "@/lib/request-json";
import { enforceRateLimit } from "@/lib/rate-limit";
import { redactApiValue } from "@/lib/redaction";

export const runtime = "nodejs";

const questionSchema = z.object({
  question: z.string().trim().min(1).max(1000),
}).strict();

export async function POST(
  request: Request,
  { params }: { params: Promise<{ siteId: string }> },
) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;

  const limited = await enforceRateLimit({
    namespace: "website-assistant",
    subject: authorization.ownerId,
    limit: 20,
    windowMs: 15 * 60_000,
  });
  if (limited) return limited;

  const body = await readBoundedJson(request, 4096);
  const parsed = questionSchema.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "Enter a question up to 1,000 characters." }, { status: 400 });

  const { siteId } = await params;
  const website = await db.website.findFirst({
    where: ownedWebsiteWhere(authorization.ownerId, siteId),
    select: {
      id: true,
      name: true,
      url: true,
      checks: { orderBy: { checkedAt: "desc" }, take: 20 },
      issues: {
        orderBy: { lastSeenAt: "desc" },
        take: 30,
        select: {
          title: true,
          description: true,
          severity: true,
          status: true,
          source: true,
          lastSeenAt: true,
          evidence: true,
          diagnosis: true,
        },
      },
      wordpressAgent: {
        select: {
          wpVersion: true,
          phpVersion: true,
          diagnostics: true,
          lastSeenAt: true,
          revokedAt: true,
        },
      },
    },
  });
  if (!website) return NextResponse.json({ error: "Website not found." }, { status: 404 });

  const storedEvidence = redactApiValue({
    website: { name: website.name, url: website.url },
    recentChecks: website.checks.map((check) => ({
      checkedAt: check.checkedAt.toISOString(),
      available: check.available,
      statusCode: check.statusCode,
      responseTime: check.responseTime,
      error: check.error,
    })),
    storedIssues: website.issues.map((issue) => ({
      title: issue.title,
      description: issue.description,
      severity: issue.severity,
      status: issue.status,
      source: issue.source,
      lastSeenAt: issue.lastSeenAt.toISOString(),
      evidence: issue.evidence,
      diagnosis: issue.diagnosis,
    })),
    wordpress: website.wordpressAgent ? {
      connected: website.wordpressAgent.revokedAt === null,
      lastSeenAt: website.wordpressAgent.lastSeenAt.toISOString(),
      wpVersion: website.wordpressAgent.wpVersion,
      phpVersion: website.wordpressAgent.phpVersion,
      diagnostics: website.wordpressAgent.diagnostics,
    } : null,
  });

  try {
    const result = await getAiEngine().answerWebsiteQuestion(parsed.data.question, storedEvidence);
    return NextResponse.json(redactApiValue(result), { headers: { "cache-control": "no-store" } });
  } catch {
    return NextResponse.json({
      error: "The local AI assistant is unavailable or returned an answer that failed evidence validation. No answer was accepted.",
    }, { status: 503, headers: { "cache-control": "no-store" } });
  }
}
