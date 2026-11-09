import type { Prisma } from "@prisma/client";
import { z } from "zod";
import { db } from "./db.ts";
import { REPEAT_WINDOW_MS, SALT_ROTATION_COOLDOWN_MS, allUpdateSteps, repeatKey, buildCleanupPlan, cleanupStepSchema, cleanupStepsDigest, compareVersions, fetchOfficialChecksums, fixPlanForIssue, pluginUpdateSteps, selectCleanupSteps, type CleanupPlan, type CleanupStep } from "./cleanup-plan.ts";
import { requestBrowserRecheck } from "./browser-recheck.ts";
import { checkWebsite } from "./monitor.ts";
import { runAndStoreSecurityCheck } from "./monitoring-service.ts";
import { notifySite } from "./protection.ts";

/**
 * Cleanup runs are stored as repair proposals with proposal.kind
 * "compromise_cleanup". They never enter the single-operation repair path:
 * their operations are outside REPAIR_OPERATIONS, so authorizeRepairExecution
 * reports them UNSUPPORTED, and they carry executionAvailable: false. Their
 * grant is a separate one-time RepairApproval with authorizationMethod
 * "compromise_cleanup", bound to the digest of the exact step list.
 */

export const CLEANUP_KIND = "compromise_cleanup";
export type CleanupActor = { kind: "admin" | "wordpress_admin" | "mcp" | "standing"; userId: string | null; interface?: "self_healing" | "auto_update" };
const GRANT_TTL_MS = 2 * 60 * 60_000;
const ACTIVE_STATUSES = ["approved", "executing"];

type Json = Record<string, unknown>;
const record = (value: unknown): Json => value && typeof value === "object" && !Array.isArray(value) ? value as Json : {};
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export function isCleanupProposal(proposal: unknown) {
  return record(proposal).kind === CLEANUP_KIND;
}

export class CleanupError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

/** Steps that cleanups and one-click fixes on this site applied within the repeat window. */
async function recentlyAppliedSteps(websiteId: string, now: Date) {
  const runs = await db.repairProposal.findMany({
    where: { websiteId, createdAt: { gte: new Date(now.getTime() - REPEAT_WINDOW_MS) }, executionStatus: { in: ["completed", "partial"] }, proposal: { path: ["kind"], equals: CLEANUP_KIND } },
    orderBy: { createdAt: "desc" },
    take: 30,
    select: { createdAt: true, proposal: true },
  });
  const applied: Array<{ at: Date; step: CleanupStep }> = [];
  for (const run of runs) {
    const cleanup = record(record(run.proposal).cleanup);
    const steps = Array.isArray(cleanup.steps) ? cleanup.steps : [];
    const execution = record(cleanup.execution);
    const at = typeof execution.completedAt === "string" && !Number.isNaN(Date.parse(execution.completedAt)) ? new Date(execution.completedAt) : run.createdAt;
    for (const reported of Array.isArray(execution.steps) ? execution.steps.map(record) : []) {
      if (reported.status !== "applied" || typeof reported.index !== "number") continue;
      const parsed = cleanupStepSchema.safeParse(steps[reported.index]);
      if (parsed.success) applied.push({ at, step: parsed.data });
    }
  }
  return applied;
}

export async function loadCleanupPlan(websiteId: string, now = new Date()) {
  const [agent, issues, lastRotation, recentlyApplied] = await Promise.all([
    db.wordPressAgent.findFirst({ where: { websiteId, revokedAt: null }, select: { id: true, diagnostics: true, lastSeenAt: true } }),
    db.issue.findMany({ where: { websiteId, status: { in: ["open", "acknowledged"] } }, select: { id: true, fingerprint: true, severity: true, title: true } }),
    db.repairProposal.findFirst({ where: { websiteId, operationIds: { has: "rotate_salts" }, executionStatus: "completed", createdAt: { gte: new Date(now.getTime() - SALT_ROTATION_COOLDOWN_MS) } }, orderBy: { createdAt: "desc" }, select: { createdAt: true } }),
    recentlyAppliedSteps(websiteId, now),
  ]);
  const diagnostics = record(agent?.diagnostics);
  const core = record(record(diagnostics.integrity).core);
  const checksums = typeof core.version === "string" && core.version
    ? await fetchOfficialChecksums(core.version, typeof core.locale === "string" ? core.locale : "en_US")
    : null;
  const plan = buildCleanupPlan({ diagnostics: agent?.diagnostics ?? null, openIssues: issues, officialChecksums: checksums, now, saltsRotatedAt: lastRotation?.createdAt ?? null, recentlyApplied });
  if (!agent) plan.blockers.unshift("No WordPress plugin is connected to this website.");
  else if (agent.lastSeenAt.getTime() < now.getTime() - 15 * 60_000) plan.blockers.push("The WordPress plugin has not checked in for 15 minutes; it must be online to run the cleanup.");
  return { plan, agent, issues };
}

export async function startCleanup(input: {
  websiteId: string;
  organizationId: string;
  planDigest: string;
  include: string[];
  actor: CleanupActor;
  /** Pre-built steps for follow-up runs (purge); otherwise built from the current plan. */
  explicit?: { steps: CleanupStep[]; title: string; relatedRepairId?: string; issueId?: string; mode?: "compromise" | "maintenance" };
}) {
  let plan: CleanupPlan | null = null;
  let steps: CleanupStep[];
  let anchorIssueId: string | null = null;
  if (input.explicit) {
    steps = input.explicit.steps;
    const related = input.explicit.relatedRepairId ? await db.repairProposal.findUnique({ where: { id: input.explicit.relatedRepairId }, select: { issueId: true } }) : null;
    anchorIssueId = input.explicit.issueId ?? related?.issueId ?? null;
  } else {
    const loaded = await loadCleanupPlan(input.websiteId);
    plan = loaded.plan;
    if (plan.blockers.length) throw new CleanupError(plan.blockers.join(" "), 409);
    if (plan.planDigest !== input.planDigest) throw new CleanupError("The cleanup plan changed since it was reviewed (new scan results arrived). Review the updated plan and approve again.", 409);
    try { steps = selectCleanupSteps(plan, input.include); } catch (error) { throw new CleanupError(error instanceof Error ? error.message : "Invalid selection.", 400); }
    const anchor = loaded.issues
      .filter((issue) => /^(?:wp:)?(?:security|integrity):/.test(issue.fingerprint))
      .sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0))[0];
    anchorIssueId = anchor?.id ?? null;
  }
  if (!steps.length) throw new CleanupError("There is nothing to clean up.", 400);
  await expireStaleRuns(input.websiteId);
  if (!steps.every((step) => cleanupStepSchema.safeParse(step).success)) throw new CleanupError("A cleanup step failed validation.", 400);
  const digest = cleanupStepsDigest(steps);
  const operationIds = [...new Set(steps.map((step) => step.operation))];
  const approvedBy = input.actor.kind === "standing" ? `standing-policy:${input.actor.interface ?? "automatic"}` : input.actor.kind === "wordpress_admin" ? "wordpress-admin" : input.actor.userId ?? "local-admin";

  const created = await db.$transaction(async (tx) => {
    await tx.$queryRaw`WITH advisory_lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(hashtext(${input.websiteId}))) SELECT 1 FROM advisory_lock`;
    const active = await tx.repairProposal.findFirst({
      where: { websiteId: input.websiteId, status: { in: ACTIVE_STATUSES }, createdAt: { gte: new Date(Date.now() - GRANT_TTL_MS) }, proposal: { path: ["kind"], equals: CLEANUP_KIND } },
      select: { id: true, proposal: true },
    });
    if (active) throw new CleanupError(`The site is still working on “${String(record(active.proposal).issue ?? "another change")}”. It handles one change at a time; try again when that finishes (usually within seconds).`, 409);
    const now = new Date();
    const repair = await tx.repairProposal.create({
      data: {
        websiteId: input.websiteId,
        issueId: anchorIssueId,
        status: "approved",
        risk: "high",
        initiatingInterface: input.actor.interface ?? (input.actor.kind === "wordpress_admin" ? "wordpress_plugin" : input.actor.kind === "mcp" ? "mcp" : "dashboard"),
        operationIds,
        requiredPermissions: ["manage_options"],
        approvalStatus: "approved",
        backupStatus: "not_started",
        executionStatus: "queued",
        verificationStatus: "not_started",
        rollbackStatus: "not_requested",
        approvedAt: now,
        approvedBy,
        proposal: {
          kind: CLEANUP_KIND,
          issue: input.explicit?.title ?? "Compromise cleanup",
          rationale: plan?.summary ?? input.explicit?.title ?? "Compromise cleanup",
          proposedChanges: steps.map((step) => step.description),
          manualGuidance: plan?.manual ?? [],
          warnings: plan?.warnings ?? [],
          risk: "high",
          requiresApproval: true,
          executionAvailable: false,
          instructions: { steps: [], rollbackPlan: ["Every changed or removed file, the previous .htaccess and wp-config.php, and demoted users' roles are kept in the plugin's quarantine. Restore the run from the plugin's Compromise cleanup section; targets changed since the cleanup are kept."], requiresApproval: true },
          verificationPlan: input.explicit?.mode === "maintenance" ? [
            "Packages come only from downloads.wordpress.org and every installed file must match the official WordPress.org checksums.",
            "The plugin loads the home page after each change; if the site breaks, the previous version is put back automatically.",
            "The central app confirms the site is available and that no new PHP fatal error was reported after the change.",
          ] : [
            "The plugin re-verifies every target digest before changing it and verifies each result.",
            "The plugin reruns the integrity scan and syncs it; no critical or high integrity finding may remain.",
            "The central app re-checks the site from outside as a browser, Googlebot and a search visitor; no cloaking, redirect, blank page or spam sitemap may remain.",
            "A failed verification keeps the changes (rolling back would reinstall malware) and reports what remains.",
          ],
          cleanup: { mode: input.explicit?.mode ?? "compromise", steps, stepsDigest: digest, planDigest: input.planDigest, include: input.include, generatedAt: plan?.generatedAt ?? now.toISOString(), relatedRepairId: input.explicit?.relatedRepairId ?? null },
        } as Prisma.InputJsonValue,
      },
    });
    const grant = await tx.repairApproval.create({
      data: {
        repairId: repair.id, actorUserId: input.actor.userId, decision: "authorized",
        comment: "One-time cleanup authorization bound to the digest of the approved step list.",
        authorizationMethod: CLEANUP_KIND, authorizationScope: { kind: CLEANUP_KIND, stepsDigest: digest, stepCount: steps.length, approvedVia: input.actor.kind } as Prisma.InputJsonValue,
        operationDigest: digest, expiresAt: new Date(now.getTime() + GRANT_TTL_MS),
        executionWebsiteId: input.websiteId, executionIssueId: anchorIssueId, executionProposalId: repair.id,
      },
    });
    await tx.repairEvent.create({ data: { repairId: repair.id, eventType: "cleanup_approved", actor: approvedBy, details: { stepCount: steps.length, operationIds, stepsDigest: digest, via: input.actor.kind } } });
    const website = await tx.website.findUnique({ where: { id: input.websiteId }, select: { organizationId: true } });
    await tx.auditLog.create({
      data: {
        action: input.actor.kind === "standing" ? "cleanup_started_by_policy" : "cleanup_approved", actorType: input.actor.kind === "wordpress_admin" ? "wordpress_agent" : input.actor.kind, actorId: input.actor.userId ?? approvedBy,
        actorUserId: input.actor.userId, organizationId: website?.organizationId ?? input.organizationId, resourceType: "repair", resourceId: repair.id,
        details: { stepCount: steps.length, operationIds } as Prisma.InputJsonValue,
      },
    });
    return { repairId: repair.id, grantId: grant.id, expiresAt: grant.expiresAt!, steps };
  });
  // The plugin's own approvals run immediately; everything else wakes the site instead of waiting for WP-Cron.
  if (input.actor.kind !== "wordpress_admin") await wakeSite(input.websiteId);
  return created;
}

/** Ask the plugin (0.6.1+) to check in now. Best effort: failure just means the next WP-Cron poll picks it up. */
export async function wakeSite(websiteId: string) {
  const website = await db.website.findUnique({ where: { id: websiteId }, select: { url: true } });
  if (!website) return false;
  try {
    const response = await fetch(new URL("/wp-json/ai-website-doctor/v1/wake", website.url), { method: "POST", headers: { "user-agent": "AI-Website-Doctor/1.0 (wake)" }, redirect: "follow", signal: AbortSignal.timeout(6_000) });
    return response.status === 202;
  } catch {
    return false;
  }
}

/** Claim approved cleanup runs for the agent; each grant can be dispatched exactly once. */
export async function dispatchCleanupTasks(agentId: string, websiteId: string, onlyRepairId?: string) {
  await expireStaleRuns(websiteId);
  const candidates = await db.repairProposal.findMany({
    where: { websiteId, status: "approved", proposal: { path: ["kind"], equals: CLEANUP_KIND }, ...(onlyRepairId ? { id: onlyRepairId } : {}) },
    orderBy: { approvedAt: "asc" },
    take: 3,
    select: { id: true, approvedBy: true, proposal: true },
  });
  const tasks = [];
  for (const candidate of candidates) {
    const cleanup = record(record(candidate.proposal).cleanup);
    const parsed = z.array(cleanupStepSchema).min(1).max(120).safeParse(cleanup.steps);
    if (!parsed.success) continue;
    const digest = cleanupStepsDigest(parsed.data);
    if (digest !== cleanup.stepsDigest) continue;
    const now = new Date();
    const claimed = await db.$transaction(async (tx) => {
      await tx.$queryRaw`WITH advisory_lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(hashtext(${websiteId}))) SELECT 1 FROM advisory_lock`;
      const grant = await tx.repairApproval.findFirst({
        where: { repairId: candidate.id, authorizationMethod: CLEANUP_KIND, operationDigest: digest, consumedAt: null, expiresAt: { gt: now }, decision: "authorized", executionWebsiteId: websiteId, executionProposalId: candidate.id },
        orderBy: { createdAt: "desc" },
      });
      if (!grant) return null;
      const consumed = await tx.repairApproval.updateMany({ where: { id: grant.id, consumedAt: null }, data: { consumedAt: now, decision: "consumed", executionResult: "task_dispatched" } });
      if (consumed.count !== 1) return null;
      const moved = await tx.repairProposal.updateMany({ where: { id: candidate.id, status: "approved" }, data: { status: "executing", executionStatus: "running" } });
      if (moved.count !== 1) return null;
      await tx.agentExecution.upsert({
        where: { agentId_repairId: { agentId, repairId: candidate.id } },
        create: { agentId, repairId: candidate.id, status: "dispatched", startedAt: now },
        update: { status: "dispatched", startedAt: now },
      });
      await tx.repairEvent.create({ data: { repairId: candidate.id, eventType: "cleanup_dispatched", actor: "central", details: { grantId: grant.id, agentId } } });
      return grant;
    });
    if (!claimed) continue;
    tasks.push({
      kind: CLEANUP_KIND,
      repairId: candidate.id,
      authorizationGrantId: claimed.id,
      authorizationExpiresAt: claimed.expiresAt!.toISOString(),
      executeOnPoll: true,
      steps: parsed.data,
    });
  }
  return tasks;
}

export const cleanupReportSchema = z.object({
  event: z.enum(["executed", "restored", "purged"]),
  repairId: z.string().min(1).max(64),
  authorizationGrantId: z.string().min(1).max(64).optional(),
  runId: z.string().regex(/^[a-z0-9-]{8,64}$/),
  startedAt: z.string().datetime({ offset: true }).optional(),
  completedAt: z.string().datetime({ offset: true }),
  diagnosticsSynced: z.boolean().optional(),
  steps: z.array(z.object({
    index: z.number().int().min(-1).max(200),
    operation: z.string().max(40).optional(),
    status: z.enum(["applied", "failed", "skipped", "not_attempted", "restored", "conflict"]),
    message: z.string().max(500),
  })).max(130),
});

/** Record an execution or restore report from the plugin and verify executions from outside the site. */
export async function recordCleanupReport(agent: { id: string; websiteId: string }, report: z.infer<typeof cleanupReportSchema>, probe = runAndStoreSecurityCheck) {
  const repair = await db.repairProposal.findFirst({ where: { id: report.repairId, websiteId: agent.websiteId }, select: { id: true, status: true, proposal: true, website: { select: { id: true, url: true } } } });
  if (!repair || !isCleanupProposal(repair.proposal)) throw new CleanupError("Cleanup run not found for this website.", 404);
  const proposal = record(repair.proposal);
  const cleanup = record(proposal.cleanup);

  if (report.event === "purged") {
    await db.repairProposal.update({ where: { id: repair.id }, data: { proposal: { ...proposal, cleanup: { ...cleanup, purgedAt: report.completedAt } } as Prisma.InputJsonValue } });
    await db.repairEvent.create({ data: { repairId: repair.id, eventType: "quarantine_purged", actor: "wordpress-admin", details: { runId: report.runId } } });
    return { status: "purged" };
  }
  if (report.event === "restored") {
    const restored = report.steps.filter((step) => step.status === "restored").length;
    const kept = report.steps.filter((step) => step.status !== "restored").length;
    await db.repairProposal.update({
      where: { id: repair.id },
      data: { status: "rolled_back", rollbackStatus: kept ? "partial" : "completed", proposal: { ...proposal, cleanup: { ...cleanup, restore: { at: report.completedAt, steps: report.steps } } } as Prisma.InputJsonValue },
    });
    await db.repairEvent.create({ data: { repairId: repair.id, eventType: "cleanup_restored", actor: "wordpress-admin", details: { runId: report.runId, restored, kept } } });
    return { status: "rolled_back", restored, kept };
  }

  const grant = report.authorizationGrantId
    ? await db.repairApproval.findFirst({ where: { id: report.authorizationGrantId, repairId: repair.id, authorizationMethod: CLEANUP_KIND, consumedAt: { not: null } }, select: { id: true } })
    : null;
  if (!grant) throw new CleanupError("The report does not match the dispatched cleanup authorization.", 403);
  const lateReport = repair.status === "failed" && record(cleanup.execution).lost === true;
  if (repair.status !== "executing" && !lateReport) throw new CleanupError("This cleanup run is not awaiting a result.", 409);

  if (cleanup.mode === "maintenance") return recordMaintenanceReport(agent, repair, proposal, cleanup, report);
  const failed = report.steps.filter((step) => step.status === "failed");
  const notAttempted = report.steps.filter((step) => step.status === "not_attempted");
  const applied = report.steps.filter((step) => step.status === "applied");
  const reasons: string[] = [];
  for (const step of failed.slice(0, 10)) reasons.push(`Step ${step.index + 1} (${step.operation ?? "step"}) failed: ${step.message}`);
  if (notAttempted.length) reasons.push(`${notAttempted.length} step(s) were not attempted within the time budget; run a new cleanup for the rest.`);

  // Inside view: integrity findings after the plugin's post-cleanup sync.
  const remainingIntegrity = await db.issue.findMany({
    where: { websiteId: agent.websiteId, status: { in: ["open", "acknowledged"] }, fingerprint: { startsWith: "wp:integrity:" }, severity: { in: ["critical", "high"] } },
    select: { title: true, fingerprint: true },
  });
  if (!report.diagnosticsSynced) reasons.push("The plugin could not sync a fresh integrity scan after the cleanup.");
  const ranSteps = Array.isArray(cleanup.steps) ? (cleanup.steps as unknown[]).map(record) : [];
  const touched = (fingerprint: string) => applied.some((step) => {
    const parameters = record(ranSteps[step.index]?.parameters);
    if (fingerprint === "wp:integrity:uploads-php") return step.operation === "quarantine_file" && /(^|\/)uploads\//.test(String(parameters.path ?? ""));
    const plugin = /^wp:integrity:plugin-modified:(.+)$/.exec(fingerprint);
    if (plugin) return step.operation === "reinstall_plugin" && String(parameters.plugin ?? "").split("/")[0] === plugin[1];
    const theme = /^wp:integrity:theme-modified:(.+)$/.exec(fingerprint);
    if (theme) return step.operation === "reinstall_theme" && parameters.stylesheet === theme[1];
    return false;
  });
  for (const issue of remainingIntegrity) {
    reasons.push(touched(issue.fingerprint)
      ? `Came back right after this cleanup removed it: ${issue.title}. Something on the site recreates it: usually a plugin rebuilding its own cache or guard file (harmless), sometimes a hidden backdoor. Check what the file contains before cleaning it again.`
      : `Still detected inside the site: ${issue.title}`);
  }

  // Outside view: what visitors and search engines receive now.
  let outside: { completed: string[]; findings: Array<{ fingerprint: string; severity: string; title: string }> } | null = null;
  try {
    const result = await probe({ id: repair.website.id, url: repair.website.url }, "cleanup_verification");
    outside = { completed: result.probe.completedChecks, findings: result.probe.findings.map(({ fingerprint, severity, title }) => ({ fingerprint, severity, title })) };
  } catch (error) {
    reasons.push(`The outside security check could not run: ${error instanceof Error ? error.message : "unknown error"}`);
  }
  const outsideSevere = outside?.findings.filter((finding) => finding.severity === "critical" || finding.severity === "high") ?? [];
  for (const finding of outsideSevere) reasons.push(`Still visible from outside: ${finding.title}`);
  const outsideComplete = Boolean(outside?.completed.includes("homepage"));
  if (outside && !outsideComplete) reasons.push("The outside check could not load the home page, so the result is inconclusive.");

  const verificationStatus = reasons.length === 0 && outsideComplete && report.diagnosticsSynced
    ? "verified"
    : !outsideComplete || !report.diagnosticsSynced ? "inconclusive" : "failed";
  const status = verificationStatus === "verified" ? "verified" : "failed";
  const execution = { runId: report.runId, startedAt: report.startedAt, completedAt: report.completedAt, steps: report.steps, verification: { status: verificationStatus, reasons, outside, remainingIntegrity: remainingIntegrity.map((issue) => issue.title) } };
  await db.repairProposal.update({
    where: { id: repair.id },
    data: {
      status,
      executionStatus: failed.length || notAttempted.length ? (applied.length ? "partial" : "failed") : "completed",
      verificationStatus,
      backupStatus: applied.length ? "created" : "not_required",
      proposal: { ...proposal, cleanup: { ...cleanup, execution } } as Prisma.InputJsonValue,
    },
  });
  const agentExecution = await db.agentExecution.update({
    where: { agentId_repairId: { agentId: agent.id, repairId: repair.id } },
    data: { status: failed.length ? "completed_with_failures" : "completed", completedAt: new Date(report.completedAt), result: execution as Prisma.InputJsonValue },
  });
  await db.verificationResult.create({ data: { repairId: repair.id, executionId: agentExecution.id, status: verificationStatus, method: "integrity_rescan_and_outside_security_check", result: execution.verification as Prisma.InputJsonValue } });
  await db.repairEvent.create({ data: { repairId: repair.id, eventType: `cleanup_${verificationStatus}`, actor: "central", details: { applied: applied.length, failed: failed.length, notAttempted: notAttempted.length, reasons: reasons.slice(0, 10) } } });
  await notifySite(agent.websiteId, "security", verificationStatus === "verified" ? "Cleanup verified" : `Cleanup ${verificationStatus}`, verificationStatus === "verified"
    ? `${applied.length} change(s) applied. Visitors, Googlebot and search visitors now receive the same page and no critical or high integrity finding remains.`
    : `${applied.length} change(s) applied, ${failed.length} failed. Still to resolve:\n${reasons.slice(0, 10).map((reason) => `- ${reason}`).join("\n")}`);
  return { status, verificationStatus, applied: applied.length, failed: failed.length, notAttempted: notAttempted.length, reasons };
}

/** Offer permanent deletion of a verified run's quarantine as its own one-step cleanup. */
export async function startQuarantinePurge(input: { websiteId: string; organizationId: string; repairId: string; actor: { kind: "admin" | "mcp"; userId: string | null } }) {
  const repair = await db.repairProposal.findFirst({ where: { id: input.repairId, websiteId: input.websiteId }, select: { status: true, proposal: true } });
  if (!repair || !isCleanupProposal(repair.proposal)) throw new CleanupError("Cleanup run not found.", 404);
  const runId = record(record(record(repair.proposal).cleanup).execution).runId;
  if (typeof runId !== "string") throw new CleanupError("This run has not reported a quarantine yet.", 409);
  if (repair.status === "rolled_back") throw new CleanupError("This run was restored; its quarantine is already back on the site.", 409);
  if (record(record(repair.proposal).cleanup).purgedAt) throw new CleanupError("This run's quarantine was already deleted.", 409);
  if (!["verified", "failed"].includes(repair.status)) throw new CleanupError("Wait until the run has finished before deleting its quarantine.", 409);
  return startCleanup({
    websiteId: input.websiteId, organizationId: input.organizationId, planDigest: "purge", include: [], actor: input.actor,
    explicit: { title: "Permanently delete quarantined files", relatedRepairId: input.repairId, mode: "maintenance", steps: [{ description: "Permanently delete the files this run quarantined. After this it can no longer be restored.", operation: "purge_quarantine", parameters: { runId } }] },
  });
}

/** Put a finished run's quarantined files and changes back on the site. */
export async function startRunRestore(input: { websiteId: string; organizationId: string; repairId: string; actor: CleanupActor }) {
  const repair = await db.repairProposal.findFirst({ where: { id: input.repairId, websiteId: input.websiteId }, select: { status: true, proposal: true } });
  if (!repair || !isCleanupProposal(repair.proposal)) throw new CleanupError("Run not found.", 404);
  const cleanup = record(record(repair.proposal).cleanup);
  const runId = record(cleanup.execution).runId;
  if (typeof runId !== "string") throw new CleanupError("This run has not reported a quarantine yet.", 409);
  if (repair.status === "rolled_back") throw new CleanupError("This run was already restored.", 409);
  if (cleanup.purgedAt) throw new CleanupError("This run's quarantine was permanently deleted; it can no longer be restored.", 409);
  return startCleanup({
    websiteId: input.websiteId, organizationId: input.organizationId, planDigest: "restore", include: [], actor: input.actor,
    explicit: { title: "Restore an earlier run", relatedRepairId: input.repairId, mode: "maintenance", steps: [{ description: "Put back everything the earlier run changed or quarantined, except targets that changed since.", operation: "restore_run", parameters: { runId } }] },
  });
}

/** Verification for update/reinstall runs: every step applied, site available, no new PHP fatal error. */
async function recordMaintenanceReport(
  agent: { id: string; websiteId: string },
  repair: { id: string; website: { id: string; url: string } },
  proposal: Json, cleanup: Json, report: z.infer<typeof cleanupReportSchema>,
) {
  const failed = report.steps.filter((step) => step.status === "failed");
  const notAttempted = report.steps.filter((step) => step.status === "not_attempted");
  const applied = report.steps.filter((step) => step.status === "applied");
  const reasons: string[] = failed.slice(0, 10).map((step) => `Step ${step.index + 1} (${step.operation ?? "step"}): ${step.message}`);
  if (notAttempted.length) reasons.push(`${notAttempted.length} step(s) were not attempted within the time budget; run the update again for the rest.`);
  if (!report.diagnosticsSynced) reasons.push("The plugin could not sync fresh diagnostics after the change.");
  const availability = await checkWebsite(repair.website.url);
  if (!availability.available) reasons.push(`The site is not available after the change: ${availability.error ?? `HTTP ${availability.statusCode}`}`);
  const since = report.startedAt ? new Date(report.startedAt) : new Date(Date.now() - 15 * 60_000);
  const newFatals = await db.issue.findMany({ where: { websiteId: agent.websiteId, fingerprint: { startsWith: "wp:php-fatal:" }, status: "open", firstSeenAt: { gte: since } }, select: { title: true, description: true } });
  for (const fatal of newFatals) reasons.push(`New PHP fatal error after the change: ${fatal.description.slice(0, 200)}`);
  const verificationStatus = !report.diagnosticsSynced ? "inconclusive" : reasons.length === 0 ? "verified" : "failed";
  const status = verificationStatus === "verified" ? "verified" : "failed";
  const execution = { runId: report.runId, startedAt: report.startedAt, completedAt: report.completedAt, steps: report.steps, verification: { status: verificationStatus, reasons, availability } };
  await db.repairProposal.update({
    where: { id: repair.id },
    data: {
      status,
      executionStatus: failed.length || notAttempted.length ? (applied.length ? "partial" : "failed") : "completed",
      verificationStatus,
      backupStatus: applied.length ? "created" : "not_required",
      rollbackStatus: failed.some((step) => /put back/.test(step.message)) ? "completed" : "not_requested",
      proposal: { ...proposal, cleanup: { ...cleanup, execution } } as Prisma.InputJsonValue,
    },
  });
  const agentExecution = await db.agentExecution.update({
    where: { agentId_repairId: { agentId: agent.id, repairId: repair.id } },
    data: { status: failed.length ? "completed_with_failures" : "completed", completedAt: new Date(report.completedAt), result: execution as Prisma.InputJsonValue },
  });
  await db.verificationResult.create({ data: { repairId: repair.id, executionId: agentExecution.id, status: verificationStatus, method: "checksums_site_health_and_availability", result: execution.verification as Prisma.InputJsonValue } });
  await db.repairEvent.create({ data: { repairId: repair.id, eventType: `maintenance_${verificationStatus}`, actor: "central", details: { applied: applied.length, failed: failed.length, reasons: reasons.slice(0, 10) } } });
  // Uploaded packages: record whether the install went through (the next sync then shows the new version).
  const plannedSteps = (record(cleanup).steps as Array<{ operation: string; parameters: Record<string, string> }> | undefined) ?? [];
  for (const [index, step] of plannedSteps.entries()) {
    if (step.operation !== "install_package") continue;
    const outcome = report.steps.find((item) => item.index === index);
    await db.softwarePackage.updateMany({ where: { id: step.parameters.packageId, status: "installing" }, data: { status: outcome?.status === "applied" && verificationStatus !== "failed" ? "installed" : "failed" } });
  }
  // Accessibility fixes are confirmed only by a browser: ask the runner to rescan this site soon,
  // also when the fix was already on (the finding may simply predate it).
  const a11yOn = plannedSteps.some((step, index) => step.operation === "set_performance" && step.parameters.state === "on" && step.parameters.measure.startsWith("a11y_")
    && ["applied", "skipped"].includes(report.steps.find((item) => item.index === index)?.status ?? ""));
  if (a11yOn && verificationStatus !== "failed") await requestBrowserRecheck(agent.websiteId, "accessibility fix switched on");
  for (const step of report.steps.filter((item) => item.status === "applied" && (item.operation === "restore_run" || item.operation === "purge_quarantine"))) {
    const runId = (record(cleanup).steps as Array<{ operation: string; parameters: Record<string, string> }> | undefined)?.[step.index]?.parameters?.runId;
    if (!runId) continue;
    const original = await db.repairProposal.findFirst({ where: { websiteId: agent.websiteId, proposal: { path: ["cleanup", "execution", "runId"], equals: runId } }, select: { id: true, proposal: true } });
    if (!original) continue;
    const originalProposal = record(original.proposal);
    const originalCleanup = record(originalProposal.cleanup);
    await db.repairProposal.update({
      where: { id: original.id },
      data: step.operation === "restore_run"
        ? { status: "rolled_back", rollbackStatus: "completed", proposal: { ...originalProposal, cleanup: { ...originalCleanup, restore: { at: report.completedAt, viaRepairId: repair.id } } } as Prisma.InputJsonValue }
        : { proposal: { ...originalProposal, cleanup: { ...originalCleanup, purgedAt: report.completedAt } } as Prisma.InputJsonValue },
    });
  }
  if (verificationStatus !== "verified") await notifySite(agent.websiteId, "maintenance", `Update ${verificationStatus}`, `${applied.length} change(s) applied, ${failed.length} failed:\n${reasons.slice(0, 10).map((reason) => `- ${reason}`).join("\n")}`);
  return { status, verificationStatus, applied: applied.length, failed: failed.length, notAttempted: notAttempted.length, reasons };
}

/** One-click fix for a finding (plugin update or reinstall). */
export async function startIssueFix(input: { issueId: string; websiteId: string; organizationId: string; actor: CleanupActor; mode?: "fix" | "remove" }) {
  const [issue, agent] = await Promise.all([
    db.issue.findFirst({ where: { id: input.issueId, websiteId: input.websiteId }, select: { id: true, fingerprint: true, status: true, evidence: true } }),
    db.wordPressAgent.findFirst({ where: { websiteId: input.websiteId, revokedAt: null }, select: { diagnostics: true, lastSeenAt: true } }),
  ]);
  if (!issue) throw new CleanupError("Issue not found.", 404);
  if (issue.status === "resolved") throw new CleanupError("This issue is already resolved.", 409);
  await requireMaintenancePlugin(agent);
  if (/^(?:wp:theme-update:|wp:integrity:theme-modified:|vuln:theme-)/.test(issue.fingerprint)) {
    const version = record(record(agent!.diagnostics).site).pluginVersion;
    const [major, minor] = typeof version === "string" ? version.split(".").map(Number) : [0, 0];
    if (!(major > 0 || minor >= 7)) throw new CleanupError(`Theme fixes need AI Website Doctor 0.7.0 or later on the site (it reports ${typeof version === "string" ? version : "an older version"}).`, 409);
  }
  const fix = input.mode === "remove" ? removalPlanForIssue(issue.fingerprint, agent!.diagnostics) : fixPlanForIssue(issue.fingerprint, { ...record(agent!.diagnostics), __issueEvidence: issue.evidence });
  if (!fix) throw new CleanupError("This finding has no one-click fix; follow its recommendation instead.", 400);
  if (!fix.steps.length) throw new CleanupError(fix.skipped.join(" ") || "There is nothing to fix.", 409);
  if (input.mode !== "remove") {
    const now = new Date();
    const done = new Map((await recentlyAppliedSteps(input.websiteId, now)).map((entry) => [repeatKey(entry.step), entry.at]));
    const repeat = fix.steps.map((step) => ({ step, at: done.get(repeatKey(step)) })).find((item) => repeatKey(item.step) && item.at);
    if (repeat?.at) {
      throw new CleanupError(`This exact fix already ran at ${repeat.at.toISOString().slice(0, 16).replace("T", " ")} UTC and the finding came straight back, so running it again will not make it stick. The plugin usually recreates the file itself (a harmless guard or cache file). Update AI Website Doctor on the site to 0.8.1, which reads such files and ignores harmless ones; the finding then clears on the next scan.`, 409);
    }
  }
  return startCleanup({ websiteId: input.websiteId, organizationId: input.organizationId, planDigest: "fix", include: [], actor: input.actor, explicit: { steps: fix.steps, title: fix.title, issueId: issue.id, mode: "maintenance" } });
}

/**
 * "Remove until fixed" for a vulnerable plugin or theme (for example a premium
 * plugin whose fixed version must come from the vendor): deactivate it and
 * keep it in the quarantine, from where it can be restored.
 */
export function removalPlanForIssue(fingerprint: string, diagnostics: unknown) {
  const data = record(diagnostics);
  const plugin = /^vuln:plugin-([a-z0-9-]+):/.exec(fingerprint);
  if (plugin) {
    const installed = (Array.isArray(data.plugins) ? data.plugins.map(record) : []).find((item) => typeof item.file === "string" && item.file.split("/")[0] === plugin[1]);
    if (!installed || typeof installed.file !== "string") return { steps: [], title: "Remove plugin", skipped: ["The plugin is no longer installed."] };
    const step = { description: `Deactivate ${String(installed.name)} ${String(installed.version)} and move it to the quarantine until a fixed version is installed.`, operation: "quarantine_plugin" as const, parameters: { plugin: installed.file, expectedVersion: String(installed.version ?? "") } };
    return cleanupStepSchema.safeParse(step).success ? { steps: [step], title: `Remove vulnerable ${String(installed.name)} until fixed`, skipped: [] } : { steps: [], title: "Remove plugin", skipped: ["The plugin cannot be removed automatically."] };
  }
  const theme = /^vuln:theme-([a-z0-9_-]+):/.exec(fingerprint);
  if (theme) {
    const installed = (Array.isArray(data.themes) ? data.themes.map(record) : []).find((item) => item.stylesheet === theme[1]);
    if (!installed) return { steps: [], title: "Remove theme", skipped: ["The theme is no longer installed."] };
    if (installed.active || installed.parentOfActive) return { steps: [], title: "Remove theme", skipped: ["This is the active theme (or its parent); switch to another theme before removing it."] };
    const step = { description: `Move the unused ${String(installed.name)} theme to the quarantine until a fixed version is installed.`, operation: "quarantine_theme" as const, parameters: { stylesheet: String(installed.stylesheet), expectedVersion: String(installed.version ?? "") } };
    return cleanupStepSchema.safeParse(step).success ? { steps: [step], title: `Remove vulnerable ${String(installed.name)} theme`, skipped: [] } : { steps: [], title: "Remove theme", skipped: ["The theme cannot be removed automatically."] };
  }
  return null;
}

/** One-click update of WordPress.org plugins with available updates (all, or the listed files). */
export async function startPluginUpdates(input: { websiteId: string; organizationId: string; plugins?: string[]; actor: CleanupActor }) {
  const agent = await db.wordPressAgent.findFirst({ where: { websiteId: input.websiteId, revokedAt: null }, select: { diagnostics: true, lastSeenAt: true } });
  await requireMaintenancePlugin(agent);
  // Without a selection, "Update all" covers WordPress.org plugins and themes.
  const updates = input.plugins ? pluginUpdateSteps(agent!.diagnostics, input.plugins) : allUpdateSteps(agent!.diagnostics);
  if (!updates.steps.length) throw new CleanupError(updates.skipped.join(" ") || "No WordPress.org plugin or theme has an update available.", 409);
  const started = await startCleanup({ websiteId: input.websiteId, organizationId: input.organizationId, planDigest: "update_plugins", include: [], actor: input.actor, explicit: { steps: updates.steps, title: updates.title, mode: "maintenance" } });
  return { ...started, skipped: updates.skipped };
}

async function requireMaintenancePlugin(agent: { diagnostics: unknown; lastSeenAt: Date } | null) {
  if (!agent) throw new CleanupError("No WordPress plugin is connected to this website.", 409);
  if (agent.lastSeenAt.getTime() < Date.now() - 15 * 60_000) throw new CleanupError("The WordPress plugin has not checked in for 15 minutes; it must be online to apply the fix.", 409);
  const version = record(record(agent.diagnostics).site).pluginVersion;
  const [major, minor] = typeof version === "string" ? version.split(".").map(Number) : [0, 0];
  if (!(major > 0 || minor >= 4)) throw new CleanupError(`One-click plugin fixes need AI Website Doctor 0.4.0 or later on the site (it reports ${typeof version === "string" ? version : "an older version"}).`, 409);
}

/** Summary of one-click maintenance available for a site (shown next to the cleanup plan). */
export function maintenanceSummary(diagnostics: unknown) {
  const updates = allUpdateSteps(diagnostics);
  return { pluginUpdates: updates.steps.map((step) => ({ plugin: step.parameters.plugin ?? `theme:${step.parameters.stylesheet}`, description: step.description })), notUpdatable: updates.skipped };
}

/** Turn protection measures on or off on the site through the approved executor. */
export async function startProtectionChange(input: { websiteId: string; organizationId: string; changes: Array<{ measure: string; state: "on" | "off" }>; actor: CleanupActor }) {
  const agent = await db.wordPressAgent.findFirst({ where: { websiteId: input.websiteId, revokedAt: null }, select: { diagnostics: true, lastSeenAt: true } });
  if (!agent || agent.lastSeenAt.getTime() < Date.now() - 15 * 60_000) throw new CleanupError("The WordPress plugin must be connected and online to change protection.", 409);
  const version = record(record(agent.diagnostics).site).pluginVersion;
  const [major, minor] = typeof version === "string" ? version.split(".").map(Number) : [0, 0];
  if (!(major > 0 || minor >= 5)) throw new CleanupError(`Protection needs AI Website Doctor 0.5.0 or later on the site (it reports ${typeof version === "string" ? version : "an older version"}).`, 409);
  const steps = input.changes.map(({ measure, state }) => ({ description: `Turn ${state} protection: ${PROTECTION_MEASURE_TITLES[measure] ?? measure}.`, operation: "set_hardening" as const, parameters: { measure, state } }));
  if (!steps.length || !steps.every((step) => cleanupStepSchema.safeParse(step).success)) throw new CleanupError("Unknown protection measure.", 400);
  return startCleanup({ websiteId: input.websiteId, organizationId: input.organizationId, planDigest: "protection", include: [], actor: input.actor, explicit: { steps, title: steps.length === 1 ? steps[0].description.replace(/\.$/, "") : `Change ${steps.length} protection settings`, mode: "maintenance" } });
}

export const PROTECTION_MEASURE_TITLES: Record<string, string> = {
  block_php_uploads: "Block PHP in uploads",
  protect_sensitive_files: "Protect sensitive files",
  disable_file_editor: "Turn off the code editor",
  disable_xmlrpc: "Turn off XML-RPC",
  block_user_enumeration: "Hide usernames",
  security_headers: "Security headers",
  verified_crawlers: "Block fake crawlers and attack tools",
};

const LOST_AFTER_MS = 10 * 60_000;

/**
 * Close runs the site will never finish: picked up but no report within 10
 * minutes (PHP was stopped by a memory or time limit on a plugin older than
 * 0.6.2, which cannot report that itself), or never picked up before the
 * grant expired. Otherwise one lost run would block the site indefinitely.
 */
export async function expireStaleRuns(websiteId: string) {
  const now = Date.now();
  const candidates = await db.repairProposal.findMany({
    where: { websiteId, status: { in: ACTIVE_STATUSES }, proposal: { path: ["kind"], equals: CLEANUP_KIND } },
    select: { id: true, status: true, createdAt: true, proposal: true, executions: { select: { id: true, agentId: true, startedAt: true }, take: 1, orderBy: { createdAt: "desc" } } },
  });
  for (const run of candidates) {
    const execution = run.executions[0];
    const lost = run.status === "executing" && execution?.startedAt && now - execution.startedAt.getTime() > LOST_AFTER_MS;
    const neverPickedUp = run.status === "approved" && now - run.createdAt.getTime() > GRANT_TTL_MS;
    if (!lost && !neverPickedUp) continue;
    const reason = lost
      ? `The site picked up this change at ${execution!.startedAt!.toISOString()} but never reported back. PHP on the site was most likely stopped by its memory or time limit before it finished. Plugin 0.6.2 and later raise the limit and report such failures themselves. Check the plugin's Quarantine section for anything left there, then try again.`
      : "The site never picked up this change (the plugin was offline or WP-Cron did not run). Nothing was changed; approve it again when the plugin is back online.";
    const proposal = record(run.proposal);
    const cleanup = record(proposal.cleanup);
    const updated = await db.repairProposal.updateMany({
      where: { id: run.id, status: run.status },
      data: {
        status: "failed", executionStatus: lost ? "unknown" : "not_started", verificationStatus: "inconclusive",
        proposal: { ...proposal, cleanup: { ...cleanup, execution: { lost: true, steps: null, verification: { status: "inconclusive", reasons: [reason] } } } } as Prisma.InputJsonValue,
      },
    });
    if (!updated.count) continue;
    if (execution) await db.agentExecution.update({ where: { id: execution.id }, data: { status: lost ? "lost" : "expired", completedAt: new Date() } });
    await db.repairEvent.create({ data: { repairId: run.id, eventType: lost ? "cleanup_lost" : "cleanup_expired", actor: "central", details: { reason } } });
    await notifySite(websiteId, "maintenance", `${String(proposal.issue ?? "Change")} did not finish`, reason);
  }
}

export const PERFORMANCE_MEASURE_TITLES: Record<string, string> = {
  page_cache: "Page caching",
  compression: "Text compression",
  browser_caching: "Browser caching",
  defer_scripts: "Defer non-critical JavaScript",
  font_display_swap: "Show text while fonts load",
  trim_extras: "Remove unused WordPress extras",
  lazy_load: "Lazy-load images and videos",
  webp_uploads: "WebP for new uploads",
  a11y_zoom: "Allow zooming on phones",
  a11y_names: "Name icon-only links and buttons",
  a11y_form_labels: "Label form fields",
};

/** Latest WordPress.org version of a plugin (for installing a cache plugin). */
async function latestWordPressOrgVersion(slug: string, fetcher: typeof fetch = fetch) {
  const response = await fetcher(`https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bslug%5D=${encodeURIComponent(slug)}&request%5Bfields%5D%5Bsections%5D=0`, { signal: AbortSignal.timeout(10_000) });
  const body = record(await response.json().catch(() => ({})));
  return typeof body.version === "string" ? body.version : null;
}

/**
 * Turn performance measures on or off through the approved executor
 * (plugin 0.8.0+). Page caching uses the cache plugin already active; when
 * there is none, LiteSpeed Cache (LiteSpeed servers) or Cache Enabler is
 * installed from WordPress.org first, verified against official checksums.
 */
export async function startPerformanceChange(input: { websiteId: string; organizationId: string; changes: Array<{ measure: string; state: "on" | "off" }>; actor: CleanupActor; fetcher?: typeof fetch }) {
  const agent = await db.wordPressAgent.findFirst({ where: { websiteId: input.websiteId, revokedAt: null }, select: { diagnostics: true, lastSeenAt: true } });
  if (!agent || agent.lastSeenAt.getTime() < Date.now() - 15 * 60_000) throw new CleanupError("The WordPress plugin must be connected and online to change performance settings.", 409);
  const version = String(record(record(agent.diagnostics).site).pluginVersion ?? "0");
  if (compareVersions(version, "0.8.0") < 0) throw new CleanupError(`Performance fixes need AI Website Doctor 0.8.0 or later on the site (it reports ${version}).`, 409);
  if (input.changes.some(({ measure }) => measure.startsWith("a11y_")) && compareVersions(version, "0.9.0") < 0) {
    throw new CleanupError(`Accessibility fixes need AI Website Doctor 0.9.0 or later on the site (it reports ${version}). Upload the new plugin zip with "Replace current with uploaded".`, 409);
  }
  const performance = record(record(agent.diagnostics).performance);
  const steps: CleanupStep[] = [];
  for (const { measure, state } of input.changes) {
    if (measure === "page_cache" && state === "on" && !(Array.isArray(performance.cachePlugins) && performance.cachePlugins.length)) {
      const slug = /litespeed/i.test(String(performance.server ?? "")) ? "litespeed-cache" : "cache-enabler";
      const installed = (Array.isArray(record(agent.diagnostics).plugins) ? (record(agent.diagnostics).plugins as unknown[]).map(record) : []).some((plugin) => typeof plugin.file === "string" && plugin.file.startsWith(`${slug}/`));
      if (!installed) {
        const latest = await latestWordPressOrgVersion(slug, input.fetcher);
        if (!latest) throw new CleanupError(`WordPress.org could not be reached to look up ${slug}; try again.`, 502);
        steps.push({ description: `Install ${slug === "litespeed-cache" ? "LiteSpeed Cache" : "Cache Enabler"} ${latest} from WordPress.org for page caching.`, operation: "install_plugin", parameters: { slug, version: latest, activate: "yes" } });
      }
    }
    steps.push({ description: `Turn ${state} ${PERFORMANCE_MEASURE_TITLES[measure] ?? measure}.`, operation: "set_performance", parameters: { measure, state } });
  }
  if (!steps.length || !steps.every((step) => cleanupStepSchema.safeParse(step).success)) throw new CleanupError("Unknown performance measure.", 400);
  const changes = steps.filter((step) => step.operation === "set_performance");
  return startCleanup({ websiteId: input.websiteId, organizationId: input.organizationId, planDigest: "performance", include: [], actor: input.actor, explicit: { steps, title: changes.length === 1 ? changes[0].description.replace(/\.$/, "") : `Apply ${changes.length} speed fixes`, mode: "maintenance" } });
}
