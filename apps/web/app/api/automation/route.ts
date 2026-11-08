import { NextResponse } from "next/server";
import { Prisma } from "@prisma/client";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { getProtectionSettings, saveProtectionSettings } from "@/lib/protection";
import { getRepairAuthorization } from "@/lib/repair-authorization";
import { readBoundedJson } from "@/lib/request-json";

export const runtime = "nodejs";

/**
 * Every automatic action per website in one place: self-healing, automatic
 * plugin/theme updates, and automatic link repairs (the only standing
 * repair that can run without a person: updating links that permanently
 * redirect). "Pause all" stops all three on every site; "Resume all" lifts
 * the pause without changing which responses are switched on.
 */
async function ownedSites(ownerId: string) {
  return db.website.findMany({
    where: { organization: { members: { some: { userId: ownerId } } } },
    orderBy: { name: "asc" },
    select: { id: true, name: true, organizationId: true },
  });
}

async function siteAutomation(site: { id: string; name: string }) {
  const [protection, legacy] = await Promise.all([getProtectionSettings(site.id), getRepairAuthorization(site.id)]);
  return {
    siteId: site.id,
    name: site.name,
    selfHealing: protection.selfHealing,
    autoUpdates: protection.autoUpdates,
    linkRepairs: legacy.mode === "auto_eligible" && legacy.allowedOperations.includes("replace_post_link"),
    paused: protection.paused || legacy.paused,
  };
}

export async function GET() {
  const authorization = await authorizeOwnerRequest();
  if ("response" in authorization) return authorization.response;
  const sites = await ownedSites(authorization.ownerId);
  return NextResponse.json({ sites: await Promise.all(sites.map(siteAutomation)) }, { headers: { "cache-control": "no-store" } });
}

const changeSchema = z.union([
  z.object({ action: z.enum(["pause_all", "resume_all"]) }).strict(),
  z.object({ siteId: z.string().min(1).max(64), selfHealing: z.boolean().optional(), autoUpdates: z.boolean().optional(), linkRepairs: z.boolean().optional() }).strict(),
]);

async function setLegacy(websiteId: string, ownerId: string, changes: { linkRepairs?: boolean; paused?: boolean }) {
  const current = await getRepairAuthorization(websiteId);
  const allowed = changes.linkRepairs === undefined ? current.allowedOperations
    : changes.linkRepairs ? [...new Set([...current.allowedOperations.filter((operation) => operation === "replace_post_link" || operation === "update_setting"), "replace_post_link"])]
      : current.allowedOperations.filter((operation) => operation !== "replace_post_link");
  // Plugin isolation and theme switching are high risk and never run without approval, so they are not standing permissions.
  const standing = allowed.filter((operation) => operation === "replace_post_link" || operation === "update_setting");
  const mode = standing.length ? "automatic" : "manual";
  const paused = changes.paused ?? current.paused;
  await db.$transaction(async (tx) => {
    await tx.$queryRaw`WITH advisory_lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(hashtext(${websiteId}))) SELECT 1 FROM advisory_lock`;
    const record = await tx.repairAuthorization.upsert({
      where: { websiteId },
      create: { websiteId, ownerId, mode, maxRisk: standing.includes("update_setting") ? "medium" : "low", requireRecoveryPoint: true, requireVerification: true, maxRepairsPerBatch: current.maxRepairsPerBatch, pausedAt: paused ? new Date() : null },
      update: { mode, maxRisk: standing.includes("update_setting") ? "medium" : "low", pausedAt: paused ? new Date() : null },
      select: { id: true },
    });
    for (const operation of ["disable_plugin", "switch_theme", "update_setting", "replace_post_link"]) {
      const enabled = (standing as string[]).includes(operation);
      await tx.repairPermission.upsert({
        where: { websiteId_operation: { websiteId, operation } },
        create: { authorizationId: record.id, ownerId, websiteId, operation, authorizationMode: enabled ? "standing" : "approval", enabled, maxRisk: operation === "update_setting" ? "medium" : "low", requiredSafetyConditions: { connectedAgentFresh: true, exactSingleOperation: true, operationSpecificRecovery: true, independentVerification: true } },
        update: { authorizationId: record.id, authorizationMode: enabled ? "standing" : "approval", enabled },
      });
    }
  });
}

/** Put queued automatic work back to "needs approval" (standing repairs) or cancel it (automatic runs not yet picked up). */
async function stopQueuedAutomation(websiteIds: string[], ownerId: string) {
  const queued = await db.repairProposal.findMany({ where: { websiteId: { in: websiteIds }, status: "approved" }, select: { id: true, initiatingInterface: true, proposal: true } });
  for (const repair of queued) {
    const proposal = repair.proposal && typeof repair.proposal === "object" && !Array.isArray(repair.proposal) ? repair.proposal as Record<string, unknown> : {};
    const standing = (proposal.authorization as { mode?: string } | undefined)?.mode === "standing_policy";
    const automaticRun = proposal.kind === "compromise_cleanup" && (repair.initiatingInterface === "self_healing" || repair.initiatingInterface === "auto_update");
    if (!standing && !automaticRun) continue;
    const dispatched = await db.repairApproval.findFirst({ where: { repairId: repair.id, consumedAt: { not: null } }, select: { id: true } });
    if (dispatched) continue;
    await db.repairProposal.updateMany({
      where: { id: repair.id, status: "approved" },
      data: automaticRun ? { status: "rejected", approvalStatus: "rejected" } : { status: "pending_approval", approvalStatus: "pending", approvedAt: null, approvedBy: null },
    });
    await db.repairEvent.create({ data: { repairId: repair.id, eventType: "automation_paused", actor: ownerId, details: { automaticRun } as Prisma.InputJsonValue } });
  }
}

export async function POST(request: Request) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const parsed = changeSchema.safeParse(await readBoundedJson(request, 2048));
  if (!parsed.success) return NextResponse.json({ error: "Send { action: \"pause_all\" | \"resume_all\" } or { siteId, selfHealing?, autoUpdates?, linkRepairs? }." }, { status: 400 });
  const sites = await ownedSites(authorization.ownerId);
  const memberships = await db.organizationMember.findMany({ where: { userId: authorization.ownerId, role: { in: ["owner", "admin"] } }, select: { organizationId: true } });
  const manageable = new Set(memberships.map((membership) => membership.organizationId));
  if ("action" in parsed.data) {
    const paused = parsed.data.action === "pause_all";
    const targets = sites.filter((site) => manageable.has(site.organizationId));
    for (const site of targets) {
      await saveProtectionSettings(site.id, site.organizationId, { paused }, authorization.ownerId);
      await setLegacy(site.id, authorization.ownerId, { paused });
    }
    if (paused) await stopQueuedAutomation(targets.map((site) => site.id), authorization.ownerId);
    return NextResponse.json({ sites: await Promise.all(sites.map(siteAutomation)), message: paused ? `Automation paused on ${targets.length} website(s). Queued automatic work that had not started was stopped.` : `Automation resumed on ${targets.length} website(s).` });
  }
  const site = sites.find((item) => item.id === (parsed.data as { siteId: string }).siteId);
  if (!site) return NextResponse.json({ error: "Website not found." }, { status: 404 });
  if (!manageable.has(site.organizationId)) return NextResponse.json({ error: "Only organization owners and administrators can change automation." }, { status: 403 });
  const { selfHealing, autoUpdates, linkRepairs } = parsed.data as { selfHealing?: boolean; autoUpdates?: boolean; linkRepairs?: boolean };
  if (selfHealing !== undefined || autoUpdates !== undefined) await saveProtectionSettings(site.id, site.organizationId, { ...(selfHealing === undefined ? {} : { selfHealing }), ...(autoUpdates === undefined ? {} : { autoUpdates }) }, authorization.ownerId);
  if (linkRepairs !== undefined) await setLegacy(site.id, authorization.ownerId, { linkRepairs });
  return NextResponse.json({ site: await siteAutomation(site), message: "Saved." });
}
