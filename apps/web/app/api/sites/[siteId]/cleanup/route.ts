import { NextResponse } from "next/server";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { CleanupError, isCleanupProposal, loadCleanupPlan, startCleanup, startQuarantinePurge } from "@/lib/cleanup-service";
import { db } from "@/lib/db";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { readBoundedJson } from "@/lib/request-json";

export const runtime = "nodejs";
export const maxDuration = 60;

async function ownedSite(request: Request, siteId: string, sameOrigin: boolean) {
  const authorization = await authorizeOwnerRequest(request, sameOrigin);
  if ("response" in authorization) return { response: authorization.response } as const;
  const website = await db.website.findFirst({ where: ownedWebsiteWhere(authorization.ownerId, siteId), select: { id: true, organizationId: true } });
  if (!website) return { response: NextResponse.json({ error: "Website not found." }, { status: 404 }) } as const;
  return { website, ownerId: authorization.ownerId } as const;
}

/** The cleanup plan to review, plus recent cleanup runs and their verification. */
export async function GET(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const { siteId } = await params;
  const owned = await ownedSite(request, siteId, false);
  if ("response" in owned) return owned.response;
  const { plan } = await loadCleanupPlan(owned.website.id);
  const runs = (await db.repairProposal.findMany({
    where: { websiteId: owned.website.id, proposal: { path: ["kind"], equals: "compromise_cleanup" } },
    orderBy: { createdAt: "desc" }, take: 10,
    select: { id: true, status: true, executionStatus: true, verificationStatus: true, rollbackStatus: true, createdAt: true, approvedBy: true, initiatingInterface: true, proposal: true },
  })).filter((run) => isCleanupProposal(run.proposal)).map(({ proposal, ...run }) => {
    const cleanup = (proposal as { cleanup?: { steps?: unknown[]; execution?: { steps?: unknown; verification?: unknown } } }).cleanup ?? {};
    return { ...run, title: (proposal as { issue?: string }).issue, stepCount: cleanup.steps?.length ?? 0, results: cleanup.execution?.steps ?? null, verification: cleanup.execution?.verification ?? null };
  });
  return NextResponse.json({ plan, runs }, { headers: { "cache-control": "no-store" } });
}

const startSchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("start"), planDigest: z.string().regex(/^[a-f0-9]{64}$/), include: z.array(z.string().max(120)).max(60).default([]), confirm: z.literal(true) }).strict(),
  z.object({ action: z.literal("purge"), repairId: z.string().min(1).max(64), confirm: z.literal(true) }).strict(),
]);

/** Approve the reviewed plan (one click) or approve purging a verified run's quarantine. */
export async function POST(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const { siteId } = await params;
  const owned = await ownedSite(request, siteId, true);
  if ("response" in owned) return owned.response;
  const parsed = startSchema.safeParse(await readBoundedJson(request, 8192));
  if (!parsed.success) return NextResponse.json({ error: "Send action \"start\" with the reviewed planDigest, or \"purge\" with a repairId, and confirm: true." }, { status: 400 });
  const actor = { kind: request.headers.get("x-awd-interface") === "mcp" ? "mcp" as const : "admin" as const, userId: owned.ownerId };
  try {
    const started = parsed.data.action === "start"
      ? await startCleanup({ websiteId: owned.website.id, organizationId: owned.website.organizationId, planDigest: parsed.data.planDigest, include: parsed.data.include, actor })
      : await startQuarantinePurge({ websiteId: owned.website.id, organizationId: owned.website.organizationId, repairId: parsed.data.repairId, actor });
    return NextResponse.json({
      repairId: started.repairId,
      stepCount: started.steps.length,
      status: "queued_for_site_poll",
      message: "Approved. The WordPress plugin runs it on its next poll (WP-Cron, usually within 5 minutes; an administrator can also run it immediately from the plugin). Follow the repair status until it is verified.",
    }, { status: 201, headers: { "cache-control": "no-store" } });
  } catch (error) {
    if (error instanceof CleanupError) return NextResponse.json({ error: error.message }, { status: error.status });
    throw error;
  }
}
