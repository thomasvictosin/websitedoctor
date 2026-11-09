import { NextResponse } from "next/server";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { isPendingRecheck, pendingBrowserRechecks, requestBrowserRecheck } from "@/lib/browser-recheck";
import { db } from "@/lib/db";
import { ownedWebsiteWhere } from "@/lib/ownership";

export const runtime = "nodejs";

/** Ask the browser runner to rescan this site on its next wake-up (every 30 minutes). */
export async function POST(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const website = await db.website.findFirst({ where: ownedWebsiteWhere(authorization.ownerId, (await params).siteId), select: { id: true, monitoringEnabled: true } });
  if (!website) return NextResponse.json({ error: "Website not found." }, { status: 404 });
  if (!website.monitoringEnabled) return NextResponse.json({ error: "Turn on monitoring for this website first; the browser check only scans monitored sites." }, { status: 409 });
  const existing = (await pendingBrowserRechecks([website.id])).get(website.id);
  if (!isPendingRecheck(existing)) await requestBrowserRecheck(website.id, "requested from the dashboard");
  const recheck = (await pendingBrowserRechecks([website.id])).get(website.id) ?? null;
  return NextResponse.json({ browserRecheck: recheck }, { headers: { "cache-control": "no-store" } });
}
