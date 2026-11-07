import type { Prisma } from "@prisma/client";
import { z } from "zod";
import { db } from "./db.ts";
import { buildCleanupPlan, cleanupStepSchema, cleanupStepsDigest, fetchOfficialChecksums, fixPlanForIssue, pluginUpdateSteps, selectCleanupSteps, type CleanupPlan, type CleanupStep } from "./cleanup-plan.ts";
import { checkWebsite } from "./monitor.ts";
import { runAndStoreSecurityCheck } from "./monitoring-service.ts";

/**
 * Cleanup runs are stored as repair proposals with proposal.kind
 * "compromise_cleanup". They never enter the single-operation repair path:
 * their operations are outside REPAIR_OPERATIONS, so authorizeRepairExecution
 * reports them UNSUPPORTED, and they carry executionAvailable: false. Their
 * grant is a separate one-time RepairApproval with authorizationMethod
 * "compromise_cleanup", bound to the digest of the exact step list.
 */

export const CLEANUP_KIND = "compromise_cleanup";
const GRANT_TTL_MS = 2 * 60 * 60_000;
const ACTIVE_STATUSES = ["approved", "executing"];

type Json = Record<string, unknown>;
const record = (value: unknown): Json => value && typeof value === "object" && !Array.isArray(value) ? value as Json : {};
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export function isCleanupProposal(proposal: unknown) {
  return record(proposal).kind === CLEANUP_KIND;
}

export class CleanupError extends Error {
  constructor(message: string, readonly status: number) { super(message); }
}

export async function loadCleanupPlan(websiteId: string, now = new Date()) {
  const [agent, issues] = await Promise.all([
    db.wordPressAgent.findFirst({ where: { websiteId, revokedAt: null }, select: { id: true, diagnostics: true, lastSeenAt: true } }),
    db.issue.findMany({ where: { websiteId, status: { in: ["open", "acknowledged"] } }, select: { id: true, fingerprint: true, severity: true, title: true } }),
  ]);
  const diagnostics = record(agent?.diagnostics);
  const core = record(record(diagnostics.integrity).core);
  const checksums = typeof core.version === "string" && core.version
    ? await fetchOfficialChecksums(core.version, typeof core.locale === "string" ? core.locale : "en_US")
    : null;
  const plan = buildCleanupPlan({ diagnostics: agent?.diagnostics ?? null, openIssues: issues, officialChecksums: checksums, now });
  if (!agent) plan.blockers.unshift("No WordPress plugin is connected to this website.");
  else if (agent.lastSeenAt.getTime() < now.getTime() - 15 * 60_000) plan.blockers.push("The WordPress plugin has not checked in for 15 minutes; it must be online to run the cleanup.");
  return { plan, agent, issues };
}

export async function startCleanup(input: {
  websiteId: string;
  organizationId: string;
  planDigest: string;
  include: string[];
  actor: { kind: "admin" | "wordpress_admin" | "mcp"; userId: string | null };
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
  if (!steps.every((step) => cleanupStepSchema.safeParse(step).success)) throw new CleanupError("A cleanup step failed validation.", 400);
  const digest = cleanupStepsDigest(steps);
  const operationIds = [...new Set(steps.map((step) => step.operation))];
  const approvedBy = input.actor.kind === "wordpress_admin" ? "wordpress-admin" : input.actor.userId ?? "local-admin";

  return db.$transaction(async (tx) => {
    await tx.$queryRaw`WITH advisory_lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(hashtext(${input.websiteId}))) SELECT 1 FROM advisory_lock`;
    const active = await tx.repairProposal.findFirst({
      where: { websiteId: input.websiteId, status: { in: ACTIVE_STATUSES }, createdAt: { gte: new Date(Date.now() - GRANT_TTL_MS) }, proposal: { path: ["kind"], equals: CLEANUP_KIND } },
      select: { id: true },
    });
    if (active) throw new CleanupError(`Cleanup ${active.id} is already queued or running for this website.`, 409);
    const now = new Date();
    const repair = await tx.repairProposal.create({
      data: {
        websiteId: input.websiteId,
        issueId: anchorIssueId,
        status: "approved",
        risk: "high",
        initiatingInterface: input.actor.kind === "wordpress_admin" ? "wordpress_plugin" : input.actor.kind === "mcp" ? "mcp" : "dashboard",
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
        action: "cleanup_approved", actorType: input.actor.kind === "wordpress_admin" ? "wordpress_agent" : input.actor.kind, actorId: input.actor.userId ?? approvedBy,
        actorUserId: input.actor.userId, organizationId: website?.organizationId ?? input.organizationId, resourceType: "repair", resourceId: repair.id,
        details: { stepCount: steps.length, operationIds } as Prisma.InputJsonValue,
      },
    });
    return { repairId: repair.id, grantId: grant.id, expiresAt: grant.expiresAt!, steps };
  });
}

/** Claim approved cleanup runs for the agent; each grant can be dispatched exactly once. */
export async function dispatchCleanupTasks(agentId: string, websiteId: string, onlyRepairId?: string) {
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
  event: z.enum(["executed", "restored"]),
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
  if (repair.status !== "executing") throw new CleanupError("This cleanup run is not awaiting a result.", 409);

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
    select: { title: true },
  });
  if (!report.diagnosticsSynced) reasons.push("The plugin could not sync a fresh integrity scan after the cleanup.");
  for (const issue of remainingIntegrity) reasons.push(`Still detected inside the site: ${issue.title}`);

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
  return { status, verificationStatus, applied: applied.length, failed: failed.length, notAttempted: notAttempted.length, reasons };
}

/** Offer permanent deletion of a verified run's quarantine as its own one-step cleanup. */
export async function startQuarantinePurge(input: { websiteId: string; organizationId: string; repairId: string; actor: { kind: "admin" | "mcp"; userId: string | null } }) {
  const repair = await db.repairProposal.findFirst({ where: { id: input.repairId, websiteId: input.websiteId }, select: { status: true, proposal: true } });
  if (!repair || !isCleanupProposal(repair.proposal)) throw new CleanupError("Cleanup run not found.", 404);
  const runId = record(record(record(repair.proposal).cleanup).execution).runId;
  if (repair.status !== "verified" || typeof runId !== "string") throw new CleanupError("Only a verified cleanup's quarantine can be purged; restore or re-run unverified cleanups first.", 409);
  return startCleanup({
    websiteId: input.websiteId, organizationId: input.organizationId, planDigest: "purge", include: [], actor: input.actor,
    explicit: { title: "Permanently delete quarantined files", relatedRepairId: input.repairId, steps: [{ description: "Permanently delete the files quarantined by the verified cleanup. After this the cleanup can no longer be restored.", operation: "purge_quarantine", parameters: { runId } }] },
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
  return { status, verificationStatus, applied: applied.length, failed: failed.length, notAttempted: notAttempted.length, reasons };
}

/** One-click fix for a finding (plugin update or reinstall). */
export async function startIssueFix(input: { issueId: string; websiteId: string; organizationId: string; actor: { kind: "admin" | "wordpress_admin" | "mcp"; userId: string | null } }) {
  const [issue, agent] = await Promise.all([
    db.issue.findFirst({ where: { id: input.issueId, websiteId: input.websiteId }, select: { id: true, fingerprint: true, status: true } }),
    db.wordPressAgent.findFirst({ where: { websiteId: input.websiteId, revokedAt: null }, select: { diagnostics: true, lastSeenAt: true } }),
  ]);
  if (!issue) throw new CleanupError("Issue not found.", 404);
  if (issue.status === "resolved") throw new CleanupError("This issue is already resolved.", 409);
  await requireMaintenancePlugin(agent);
  const fix = fixPlanForIssue(issue.fingerprint, agent!.diagnostics);
  if (!fix) throw new CleanupError("This finding has no one-click fix; follow its recommendation instead.", 400);
  if (!fix.steps.length) throw new CleanupError(fix.skipped.join(" ") || "There is nothing to fix.", 409);
  return startCleanup({ websiteId: input.websiteId, organizationId: input.organizationId, planDigest: "fix", include: [], actor: input.actor, explicit: { steps: fix.steps, title: fix.title, issueId: issue.id, mode: "maintenance" } });
}

/** One-click update of WordPress.org plugins with available updates (all, or the listed files). */
export async function startPluginUpdates(input: { websiteId: string; organizationId: string; plugins?: string[]; actor: { kind: "admin" | "wordpress_admin" | "mcp"; userId: string | null } }) {
  const agent = await db.wordPressAgent.findFirst({ where: { websiteId: input.websiteId, revokedAt: null }, select: { diagnostics: true, lastSeenAt: true } });
  await requireMaintenancePlugin(agent);
  const updates = pluginUpdateSteps(agent!.diagnostics, input.plugins);
  if (!updates.steps.length) throw new CleanupError(updates.skipped.join(" ") || "No WordPress.org plugin has an update available.", 409);
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
  const updates = pluginUpdateSteps(diagnostics);
  return { pluginUpdates: updates.steps.map((step) => ({ plugin: step.parameters.plugin, description: step.description })), notUpdatable: updates.skipped };
}
