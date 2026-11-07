import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { runAndStoreSecurityCheck } from "@/lib/monitoring-service";
import { ownedWebsiteWhere } from "@/lib/ownership";

export const runtime = "nodejs";
export const maxDuration = 60;

/**
 * Run the plain-HTTP compromise probe now and return its findings. Unlike a
 * queued scan this needs no background worker or browser runtime.
 */
export async function POST(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const { siteId } = await params;
  const website = await db.website.findFirst({ where: ownedWebsiteWhere(authorization.ownerId, siteId), select: { id: true, url: true } });
  if (!website) return NextResponse.json({ error: "Website not found." }, { status: 404 });
  const recent = await db.scanSession.count({ where: { websiteId: website.id, scanType: "security", startedAt: { gte: new Date(Date.now() - 60_000) } } });
  if (recent >= 2) return NextResponse.json({ error: "A security check ran for this website in the last minute; try again shortly." }, { status: 429, headers: { "retry-after": "60" } });
  const result = await runAndStoreSecurityCheck(website, "admin");
  return NextResponse.json({
    scanSessionId: result.scanSessionId,
    checkedAt: result.probe.checkedAt,
    completedChecks: result.probe.completedChecks,
    findings: result.probe.findings.map(({ fingerprint, title, severity, description }) => ({ fingerprint, title, severity, description })),
    issueIds: result.issueIds,
    resolvedCount: result.resolvedCount,
    samples: result.probe.samples,
    robots: result.probe.robots,
    sitemap: result.probe.sitemap,
    errors: result.probe.errors,
    limitations: result.probe.limitations,
  }, { headers: { "cache-control": "no-store" } });
}
