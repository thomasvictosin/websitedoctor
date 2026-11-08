import { NextResponse } from "next/server";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { describeRenewal } from "@/lib/renewals";

export const runtime = "nodejs";

/** Every website's renewal dates, soonest first, for the overview. */
export async function GET(request: Request) {
  const authorization = await authorizeOwnerRequest(request, false);
  if ("response" in authorization) return authorization.response;
  const sites = await db.website.findMany({ where: ownedWebsiteWhere(authorization.ownerId), select: { id: true, name: true, renewals: true } });
  const rows = sites.flatMap((site) => site.renewals.map((row) => ({ siteId: site.id, siteName: site.name, ...describeRenewal(row) })));
  rows.sort((a, b) => (a.expiresAt ? Date.parse(a.expiresAt) : Infinity) - (b.expiresAt ? Date.parse(b.expiresAt) : Infinity));
  return NextResponse.json({ renewals: rows, unchecked: sites.filter((site) => !site.renewals.length).map((site) => site.id) }, { headers: { "cache-control": "no-store" } });
}
