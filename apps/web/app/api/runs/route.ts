import { NextResponse } from "next/server";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { expireStaleRuns } from "@/lib/cleanup-service";
import { db } from "@/lib/db";

export const runtime = "nodejs";

/** Cleanups, fixes, updates, protection changes and restores across the organization's websites. */
export async function GET() {
  const authorization = await authorizeOwnerRequest();
  if ("response" in authorization) return authorization.response;
  const scope = { website: { organization: { members: { some: { userId: authorization.ownerId } } } }, proposal: { path: ["kind"], equals: "compromise_cleanup" } };
  const active = await db.repairProposal.findMany({ where: { ...scope, status: { in: ["approved", "executing"] } }, distinct: ["websiteId"], select: { websiteId: true } });
  for (const { websiteId } of active) await expireStaleRuns(websiteId);
  const runs = await db.repairProposal.findMany({
    where: scope,
    orderBy: { createdAt: "desc" },
    take: 200,
    select: { id: true, status: true, verificationStatus: true, rollbackStatus: true, initiatingInterface: true, approvedBy: true, createdAt: true, operationIds: true, proposal: true, website: { select: { id: true, name: true } } },
  });
  return NextResponse.json({
    runs: runs.map((run) => {
      const proposal = (run.proposal ?? {}) as { issue?: string; cleanup?: { mode?: string; steps?: Array<{ operation?: string; description?: string }>; purgedAt?: string; execution?: { steps?: Array<{ index: number; operation?: string; status: string; message: string }>; verification?: { reasons?: string[] } } } };
      const cleanup = proposal.cleanup ?? {};
      const results = cleanup.execution?.steps ?? null;
      return {
        id: run.id,
        site: run.website,
        title: proposal.issue ?? "Site change",
        mode: cleanup.mode ?? "compromise",
        operations: run.operationIds,
        status: run.status,
        verificationStatus: run.verificationStatus,
        rollbackStatus: run.rollbackStatus,
        startedBy: run.initiatingInterface,
        createdAt: run.createdAt,
        plannedSteps: (cleanup.steps ?? []).map((step) => step.description ?? step.operation ?? ""),
        results,
        applied: results?.filter((step) => step.status === "applied").length ?? 0,
        failed: results?.filter((step) => step.status === "failed").length ?? 0,
        reasons: cleanup.execution?.verification?.reasons ?? [],
        purgedAt: cleanup.purgedAt ?? null,
      };
    }),
  }, { headers: { "cache-control": "no-store" } });
}
