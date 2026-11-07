import { NextResponse } from "next/server";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { ownedIssueWhere } from "@/lib/ownership";
import { db } from "@/lib/db";
import { redactApiValue } from "@/lib/redaction";
import { readBoundedJson } from "@/lib/request-json";
import { requestSourceHash } from "@/lib/rate-limit";

export const runtime = "nodejs";
const statusSchema = z.object({ status: z.enum(["open", "acknowledged", "resolved"]) });

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ issueId: string }> },
) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const { issueId } = await params;
  const body = await readBoundedJson(request, 4096);
  const parsed = statusSchema.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "Unsupported issue status." }, { status: 400 });
  const exists = await db.issue.findFirst({
    where: ownedIssueWhere(authorization.ownerId, issueId),
    select: { id: true, website: { select: { organizationId: true } } },
  });
  if (!exists) return NextResponse.json({ error: "Issue not found." }, { status: 404 });
  const updated = await db.$transaction(async (transaction) => {
    const result = await transaction.issue.updateMany({
      where: ownedIssueWhere(authorization.ownerId, issueId),
      data: {
        status: parsed.data.status,
        resolvedAt: parsed.data.status === "resolved" ? new Date() : null,
      },
    });
    if (result.count !== 1) return result;
    await transaction.auditLog.create({
      data: {
        action: "issue_status_changed",
        actorType: "admin",
        actorId: authorization.ownerId,
        actorUserId: authorization.ownerId,
        organizationId: exists.website.organizationId,
        resourceType: "issue",
        resourceId: issueId,
        sourceHash: requestSourceHash(request),
        details: { status: parsed.data.status },
      },
    });
    return result;
  });
  if (updated.count !== 1) return NextResponse.json({ error: "Issue not found." }, { status: 404 });
  const issue = await db.issue.findFirst({ where: ownedIssueWhere(authorization.ownerId, issueId) });
  if (!issue) return NextResponse.json({ error: "Issue not found." }, { status: 404 });
  return NextResponse.json(redactApiValue(issue), { headers: { "cache-control": "no-store" } });
}
