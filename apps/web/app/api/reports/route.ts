import { NextResponse } from "next/server";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { db } from "@/lib/db";
import { redactApiValue } from "@/lib/redaction";

export const runtime = "nodejs";

export async function GET() {
  const authorization = await authorizeOwnerRequest();
  if ("response" in authorization) return authorization.response;
  const websites = await db.website.findMany({
    where: ownedWebsiteWhere(authorization.ownerId),
    orderBy: { name: "asc" },
    include: {
      checks: { orderBy: { checkedAt: "desc" }, take: 100 },
      issues: { orderBy: { lastSeenAt: "desc" } },
      repairProposals: {
        orderBy: { createdAt: "desc" },
        include: {
          events: { orderBy: { createdAt: "asc" } },
          executions: { orderBy: { createdAt: "asc" } },
        },
      },
      wordpressAgent: {
        select: {
          siteName: true,
          siteUrl: true,
          wpVersion: true,
          phpVersion: true,
          diagnostics: true,
          lastSeenAt: true,
          revokedAt: true,
          executions: { orderBy: { createdAt: "desc" }, take: 20 },
        },
      },
    },
  });
  return new NextResponse(JSON.stringify(redactApiValue({
    generatedAt: new Date().toISOString(),
    websites,
  }), null, 2), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "content-disposition": `attachment; filename="website-doctor-report-${new Date().toISOString().slice(0, 10)}.json"`,
      "cache-control": "no-store",
    },
  });
}
