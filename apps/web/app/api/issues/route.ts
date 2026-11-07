import { NextResponse } from "next/server";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { redactApiValue } from "@/lib/redaction";

export const runtime = "nodejs";

export async function GET() {
  const authorization = await authorizeOwnerRequest();
  if ("response" in authorization) return authorization.response;
  const issues = await db.issue.findMany({
    where: {
      website: { organization: { members: { some: { userId: authorization.ownerId } } } },
    },
    orderBy: [{ status: "asc" }, { lastSeenAt: "desc" }],
    include: {
      website: { select: { id: true, name: true, url: true } },
      repairs: {
        orderBy: { createdAt: "desc" },
        include: {
          events: { orderBy: { createdAt: "asc" } },
          approvals: { orderBy: { createdAt: "asc" } },
          verificationResults: { orderBy: { createdAt: "asc" } },
          executions: { orderBy: { createdAt: "asc" } },
        },
      },
    },
  });
  return NextResponse.json(redactApiValue(issues), { headers: { "cache-control": "no-store" } });
}
