import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { enqueueScan, startScanQueue } from "@/lib/scan-queue";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { ownedWebsiteWhere } from "@/lib/ownership";

export const runtime = "nodejs";

export async function POST(
  _request: Request,
  { params }: { params: Promise<{ siteId: string }> },
) {
  const authorization = await authorizeOwnerRequest(_request, true);
  if ("response" in authorization) return authorization.response;
  const { siteId } = await params;
  const website = await db.website.findFirst({ where: ownedWebsiteWhere(authorization.ownerId, siteId), select: { id: true, organizationId: true } });
  if (!website) return NextResponse.json({ error: "Website not found." }, { status: 404 });
  const queued = await enqueueScan({ websiteId: website.id, organizationId: website.organizationId, initiatedBy: "admin" });
  if (!queued.queued) return NextResponse.json({ error: queued.reason === "scan_limit" ? "This organization already has two scans queued or running." : "This organization has reached its scan limit of six scans per 15 minutes." }, { status: 429, headers: { "retry-after": "30", "cache-control": "no-store" } });
  startScanQueue();
  return NextResponse.json({ status: "queued", jobId: queued.jobId, scanSessionId: queued.scanSessionId }, { status: 202, headers: { "cache-control": "no-store" } });
}
