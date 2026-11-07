import { NextResponse } from "next/server";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { ownedIssueWhere } from "@/lib/ownership";
import { deterministicIssueRecommendation } from "@/lib/repair-policy";
import { redactApiValue } from "@/lib/redaction";

export const runtime = "nodejs";

export async function GET(_request: Request, { params }: { params: Promise<{ issueId: string }> }) {
  const authorization = await authorizeOwnerRequest();
  if ("response" in authorization) return authorization.response;
  const { issueId } = await params;
  const issue = await db.issue.findFirst({
    where: ownedIssueWhere(authorization.ownerId, issueId),
    select: { id: true, fingerprint: true, title: true, description: true, evidence: true, severity: true, website: { select: { name: true, url: true, environmentType: true } } },
  });
  if (!issue) return NextResponse.json({ error: "Issue not found." }, { status: 404 });
  const recommendation = deterministicIssueRecommendation(issue, issue.evidence);
  return NextResponse.json(redactApiValue({ issueId: issue.id, website: issue.website, severity: issue.severity, recommendation }), { headers: { "cache-control": "no-store" } });
}
