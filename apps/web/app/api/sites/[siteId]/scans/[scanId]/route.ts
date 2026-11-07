import { NextResponse } from "next/server";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { db } from "@/lib/db";

export const runtime = "nodejs";

export async function GET(request: Request, { params }: { params: Promise<{ siteId: string; scanId: string }> }) {
  const authorization = await authorizeOwnerRequest();
  if ("response" in authorization) return authorization.response;
  const { siteId, scanId } = await params;
  const session = await db.scanSession.findFirst({
    where: { id: scanId, website: ownedWebsiteWhere(authorization.ownerId, siteId) },
    select: { id: true, status: true, startedAt: true, completedAt: true, jobId: true },
  });
  if (!session) return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  const job = session.jobId ? await db.backgroundJob.findUnique({ where: { id: session.jobId }, select: { status: true, attempts: true, maxAttempts: true, lastError: true, runAt: true } }) : null;
  return NextResponse.json({ ...session, job }, { headers: { "cache-control": "no-store" } });
}
