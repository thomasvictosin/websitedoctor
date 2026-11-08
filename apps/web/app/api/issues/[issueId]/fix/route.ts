import { NextResponse } from "next/server";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { CleanupError, startIssueFix } from "@/lib/cleanup-service";
import { db } from "@/lib/db";
import { ownedIssueWhere } from "@/lib/ownership";
import { readBoundedJson } from "@/lib/request-json";

export const runtime = "nodejs";
export const maxDuration = 60;

/** One-click Fix from the dashboard or MCP: approve the finding's single maintenance step and queue it. */
export async function POST(request: Request, { params }: { params: Promise<{ issueId: string }> }) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const parsed = z.object({ confirm: z.literal(true), mode: z.enum(["fix", "remove"]).optional() }).strict().safeParse(await readBoundedJson(request, 1024));
  if (!parsed.success) return NextResponse.json({ error: "Send confirm: true to approve this fix." }, { status: 400 });
  const { issueId } = await params;
  const issue = await db.issue.findFirst({ where: ownedIssueWhere(authorization.ownerId, issueId), select: { id: true, websiteId: true, website: { select: { organizationId: true } } } });
  if (!issue) return NextResponse.json({ error: "Issue not found." }, { status: 404 });
  try {
    const started = await startIssueFix({ issueId: issue.id, websiteId: issue.websiteId, organizationId: issue.website.organizationId, actor: { kind: request.headers.get("x-awd-interface") === "mcp" ? "mcp" : "admin", userId: authorization.ownerId }, mode: parsed.data.mode });
    return NextResponse.json({
      repairId: started.repairId,
      steps: started.steps.map((step) => step.description),
      status: "queued_for_site_poll",
      message: "Approved and sent to the site. It usually runs within a few seconds; the files are verified against WordPress.org and the previous version is put back if anything fails.",
    }, { status: 201, headers: { "cache-control": "no-store" } });
  } catch (error) {
    if (error instanceof CleanupError) return NextResponse.json({ error: error.message }, { status: error.status });
    throw error;
  }
}
