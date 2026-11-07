import { NextResponse } from "next/server";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { db } from "@/lib/db";

export const runtime = "nodejs";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ siteId: string }> },
) {
  const authorization = await authorizeOwnerRequest();
  if ("response" in authorization) return authorization.response;
  const { siteId } = await params;
  const website = await db.website.findFirst({
    where: ownedWebsiteWhere(authorization.ownerId, siteId),
    select: { id: true },
  });
  if (!website) return NextResponse.json({ error: "Website not found." }, { status: 404 });
  const checks = await db.siteCheck.findMany({
    where: { websiteId: siteId },
    orderBy: { checkedAt: "desc" },
    take: 100,
  });
  return NextResponse.json(checks);
}
