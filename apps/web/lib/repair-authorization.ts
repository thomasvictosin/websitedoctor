import type { Prisma } from "@prisma/client";
import { db } from "./db.ts";
import { isHostingRepairProposal } from "./hosting-proposal-policy.ts";
import { boundedRepairPlan, repairRiskForOperations, repairStepSchema, requiresRecoveryPoint } from "./repair-policy.ts";
import { consumeRepairGrant, createRepairAuthorizationGrant, hasExpiredRepairGrant, matchRepairGrant, repairOperationDigest } from "./repair-grant-policy.ts";
export { createRepairAuthorizationGrant } from "./repair-grant-policy.ts";

export type RepairAuthorizationPolicy = {
  mode: "manual" | "auto_eligible";
  allowedOperations: string[];
  maxRisk: "low" | "medium" | "high";
  maxRepairsPerBatch: number;
  requireRecoveryPoint: true;
  requireVerification: true;
  paused: boolean;
};

export const DEFAULT_REPAIR_AUTHORIZATION: RepairAuthorizationPolicy = {
  mode: "manual",
  allowedOperations: [],
  maxRisk: "low",
  maxRepairsPerBatch: 10,
  requireRecoveryPoint: true,
  requireVerification: true,
  paused: false,
};
const REPAIR_OPERATIONS = ["disable_plugin", "switch_theme", "update_setting", "replace_post_link", "add_scoped_css_rule"];
export type AuthorizationOutcome = "AUTHORIZED" | "REQUIRES_APPROVAL" | "DENIED" | "UNSUPPORTED" | "BLOCKED" | "EXPIRED";
export type AuthorizationDecision = { outcome: AuthorizationOutcome; reason: string; risk?: "low" | "medium" | "high"; grantId?: string };

export function classifyRepairRisk(operationIds: string[]) {
  return repairRiskForOperations(operationIds);
}

/** Single policy decision point for proposals. Risk is always derived from the controlled operation allowlist. */
export async function authorizeRepairExecution(input: {
  repairId: string; websiteId: string; requesterUserId?: string | null;
  mode: "explicit" | "standing" | "prompt" | "batch" | "executor";
  batchId?: string | null; grantId?: string | null; consume?: boolean;
}): Promise<AuthorizationDecision> {
  const repair = await db.repairProposal.findFirst({
    where: { id: input.repairId, websiteId: input.websiteId },
    include: { website: { select: { ownerId: true, wordpressAgent: { select: { revokedAt: true, lastSeenAt: true } }, repairAuthorization: { include: { permissions: { where: { enabled: true } } } } } } },
  });
  if (!repair) return { outcome: "DENIED", reason: "Site ownership or proposal could not be confirmed." };
  if (!repair.operationIds.length || repair.operationIds.some((operation) => !REPAIR_OPERATIONS.includes(operation))) return { outcome: "UNSUPPORTED", reason: "The controlled repair engine does not support this operation." };
  if (!proposalIsExecutable(repair.proposal, repair.operationIds)) return { outcome: "UNSUPPORTED", reason: "The proposal does not contain exactly one valid allowlisted operation." };
  const risk = repairRiskForOperations(repair.operationIds);
  const data = repair.proposal as Record<string, unknown>;
  const steps = ((data.instructions as Record<string, unknown>).steps as Array<{ operation: string; parameters: Record<string, string> }>);
  const operation = steps[0].operation;
  if (risk === "high" && input.mode === "standing") return { outcome: "DENIED", reason: "High-risk operations always require operation-specific approval.", risk };
  const agent = repair.website.wordpressAgent;
  if (!agent || agent.revokedAt || agent.lastSeenAt.getTime() < Date.now() - 15 * 60_000) return { outcome: "BLOCKED", reason: "A live, site-bound WordPress executor is required.", risk };
  if (!requiresRecoveryPoint(repair.operationIds) || repair.backupStatus === "failed") return { outcome: "BLOCKED", reason: "The operation does not have a reliable required recovery point.", risk };
  if (input.requesterUserId && input.requesterUserId !== repair.website.ownerId) return { outcome: "DENIED", reason: "The requesting user does not own this website authorization.", risk };

  const digest = repairOperationDigest(repair.proposal, repair.operationIds);
  if (input.mode === "standing") {
    const policy = repair.website.repairAuthorization;
    const permission = policy?.permissions.find((item) => item.operation === operation && item.enabled);
    if (!policy || policy.mode !== "automatic" || policy.pausedAt || !permission || risk === "high"
      || (risk === "medium" && permission.maxRisk !== "medium" && policy.maxRisk !== "medium")) {
      return { outcome: "REQUIRES_APPROVAL", reason: "No applicable standing permission covers this exact supported operation.", risk };
    }
    return { outcome: "AUTHORIZED", reason: "The operation matches a site permission and has exact recovery and verification support.", risk };
  }
  if (input.mode === "executor") {
    if (repair.status !== "approved") return { outcome: "DENIED", reason: "This proposal is no longer approved for execution.", risk };
    const now = new Date();
    if (input.grantId) {
      const exactGrant = await db.repairApproval.findUnique({
        where: { id: input.grantId },
        select: {
          id: true,
          repairId: true,
          decision: true,
          authorizationMethod: true,
          expiresAt: true,
          consumedAt: true,
          executionWebsiteId: true,
          executionIssueId: true,
          executionProposalId: true,
          executionResult: true,
          operationDigest: true,
        },
      });
      if (exactGrant && exactGrant.repairId === repair.id
        && exactGrant.executionWebsiteId === repair.websiteId
        && exactGrant.executionProposalId === repair.id
        && exactGrant.executionIssueId === repair.issueId
        && exactGrant.authorizationMethod
        && exactGrant.expiresAt && exactGrant.expiresAt > now
        && ((exactGrant.decision === "authorized" || exactGrant.decision === "auto_authorized")
          || (exactGrant.decision === "consumed" && exactGrant.executionResult === "task_dispatched"))) {
        if (input.consume && !exactGrant.consumedAt) {
          const claimed = await consumeRepairGrant(db.repairApproval, { id: exactGrant.id, digest, now: new Date() });
          if (claimed.count !== 1) return { outcome: "EXPIRED", reason: "This one-time authorization was already consumed or expired.", risk };
        }
        return { outcome: "AUTHORIZED", reason: "The task-issued execution grant matches this exact repair and operation.", risk, grantId: exactGrant.id };
      }
    }
    const grants = await db.repairApproval.findMany({ where: { repairId: repair.id, operationDigest: digest }, orderBy: { createdAt: "desc" } });
    const grant = matchRepairGrant(grants, { ...input, now, batchId: input.batchId ?? null, websiteId: repair.websiteId, issueId: repair.issueId, repairId: repair.id });
    if (!grant) return hasExpiredRepairGrant(grants, now)
      ? { outcome: "EXPIRED", reason: "The exact-operation authorization expired; approve this proposal again.", risk }
      : { outcome: "REQUIRES_APPROVAL", reason: "No active authorization matches this exact operation and parameters.", risk };
    if (input.consume && !grant.consumedAt) {
      const claimed = await consumeRepairGrant(db.repairApproval, { id: grant.id, digest, now: new Date() });
      if (claimed.count !== 1) return { outcome: "EXPIRED", reason: "This one-time authorization was already consumed or expired.", risk };
    }
    return { outcome: "AUTHORIZED", reason: "A current, unused authorization matches this exact operation.", risk, grantId: grant.id };
  }
  if (input.mode === "explicit" || input.mode === "batch" || input.mode === "prompt") {
    return { outcome: "REQUIRES_APPROVAL", reason: "The proposal is eligible for an exact-operation approval grant.", risk };
  }
  return { outcome: "REQUIRES_APPROVAL", reason: "An explicit approval grant must be recorded before execution.", risk };
}

function normalizePolicy(value: unknown): RepairAuthorizationPolicy {
  if (!value || typeof value !== "object" || Array.isArray(value)) return DEFAULT_REPAIR_AUTHORIZATION;
  const raw = value as Record<string, unknown>;
  return {
    mode: raw.mode === "auto_eligible" ? "auto_eligible" : "manual",
    allowedOperations: Array.isArray(raw.allowedOperations)
      ? [...new Set(raw.allowedOperations.filter((item): item is string => typeof item === "string" && REPAIR_OPERATIONS.includes(item)))]
      : [],
    maxRisk: raw.maxRisk === "high" || raw.maxRisk === "medium" ? raw.maxRisk : "low",
    maxRepairsPerBatch: typeof raw.maxRepairsPerBatch === "number" ? Math.max(1, Math.min(25, Math.floor(raw.maxRepairsPerBatch))) : 10,
    requireRecoveryPoint: true,
    requireVerification: true,
    paused: raw.paused === true,
  };
}

export async function getRepairAuthorization(websiteId: string): Promise<RepairAuthorizationPolicy> {
  const stored = await db.repairAuthorization.findUnique({ where: { websiteId }, include: { permissions: { where: { enabled: true } } } });
  if (stored) return {
    mode: stored.mode === "automatic" ? "auto_eligible" : "manual",
    allowedOperations: stored.permissions.map((permission) => permission.operation),
    maxRisk: stored.maxRisk === "high" || stored.maxRisk === "medium" ? stored.maxRisk : "low",
    maxRepairsPerBatch: stored.maxRepairsPerBatch,
    requireRecoveryPoint: true,
    requireVerification: true,
    paused: Boolean(stored.pausedAt),
  };
  const setting = await db.systemSetting.findFirst({
    where: { scope: "site", scopeId: websiteId, key: "repair_authorization" },
    select: { value: true },
  });
  return normalizePolicy(setting?.value);
}

export async function applyStandingRepairAuthorization(input: {
  repairId: string;
  websiteId: string;
  organizationId: string;
  operationIds: string[];
  risk: string;
  agentId?: string | null;
}) {
  const policy = await getRepairAuthorization(input.websiteId);
  if (policy.mode !== "auto_eligible" || policy.paused || !policy.requireVerification || !policy.requireRecoveryPoint || !input.agentId || input.operationIds.length !== 1
    || !policy.allowedOperations.includes(input.operationIds[0]) || input.risk === "high") return false;
  const riskRank = { low: 0, medium: 1, high: 2 };
  if (!(input.risk in riskRank) || riskRank[input.risk as keyof typeof riskRank] > riskRank[policy.maxRisk]) return false;
  const agent = await db.wordPressAgent.findFirst({
    where: { id: input.agentId, websiteId: input.websiteId, revokedAt: null, lastSeenAt: { gte: new Date(Date.now() - 15 * 60_000) } },
    select: { id: true },
  });
  if (!agent) return false;
  const repair = await db.repairProposal.findFirst({ where: { id: input.repairId, websiteId: input.websiteId, status: "pending_approval" }, select: { proposal: true, operationIds: true, issueId: true } });
  const data = repair?.proposal && typeof repair.proposal === "object" && !Array.isArray(repair.proposal) ? repair.proposal as Record<string, unknown> : {};
  const instructions = data.instructions && typeof data.instructions === "object" && !Array.isArray(data.instructions) ? data.instructions as Record<string, unknown> : {};
  const steps = Array.isArray(instructions.steps) ? instructions.steps : [];
  if (!repair || steps.length !== 1 || (Array.isArray(data.manualGuidance) && data.manualGuidance.length !== 0)
    || data.executionAvailable !== true || repair.operationIds.length !== 1 || repair.operationIds[0] !== input.operationIds[0]) return false;
  const parsedStep = repairStepSchema.safeParse(steps[0]);
  if (!parsedStep.success || parsedStep.data.operation !== input.operationIds[0]) return false;
  const risk = repairRiskForOperations(input.operationIds);
  if (risk !== input.risk || riskRank[risk] > riskRank[policy.maxRisk]) return false;
  if (await findActiveRepairConflict(input.websiteId, input.repairId, data, repair.operationIds)) return false;
  const now = new Date();
  try {
  const updated = await db.$transaction(async (tx) => {
    await tx.$queryRaw`WITH advisory_lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(hashtext(${input.websiteId}))) SELECT 1 FROM advisory_lock`;
    const queuedAutomaticRepairs = await tx.repairProposal.count({ where: { websiteId: input.websiteId, approvedBy: "standing_policy", status: { in: ["approved", "executing", "in_progress"] } } });
    if (queuedAutomaticRepairs >= policy.maxRepairsPerBatch) return false;
    const decision = await authorizeRepairExecution({ repairId: input.repairId, websiteId: input.websiteId, mode: "standing" });
    if (decision.outcome !== "AUTHORIZED") throw new Error("Standing repair authorization no longer applies.");
    if (await findActiveRepairConflict(input.websiteId, input.repairId, data, repair.operationIds)) return false;
    const claimed = await tx.repairProposal.updateMany({
      where: { id: input.repairId, websiteId: input.websiteId, status: "pending_approval" },
      data: {
        status: "approved", approvalStatus: "approved", approvedAt: now, approvedBy: "standing_policy",
        proposal: { ...data, authorization: { mode: "standing_policy", policy, approvedAt: now.toISOString() }, executionRequest: { mode: "apply_on_site_poll", requestedAt: now.toISOString() } } as Prisma.InputJsonObject,
      },
    });
    if (claimed.count !== 1) return false;
    const finalProposal = { ...data, authorization: { mode: "standing_policy", policy, approvedAt: now.toISOString() }, executionRequest: { mode: "apply_on_site_poll", requestedAt: now.toISOString() } };
    await tx.repairProposal.update({ where: { id: input.repairId }, data: { proposal: finalProposal as Prisma.InputJsonObject } });
    await createRepairAuthorizationGrant(tx, { repairId: input.repairId, proposal: finalProposal, operationIds: input.operationIds, websiteId: input.websiteId, issueId: repair.issueId, method: "standing", scope: { kind: "exact_operation", operationIds: input.operationIds, risk } });
    await tx.repairEvent.create({ data: { repairId: input.repairId, eventType: "auto_approved_and_queued", actor: "standing_policy", details: { mode: policy.mode, operationIds: input.operationIds, risk, maxRisk: policy.maxRisk } } });
    await tx.auditLog.create({ data: { action: "repair_auto_approved_by_policy", actorType: "system", organizationId: input.organizationId, resourceType: "repair", resourceId: input.repairId, details: { websiteId: input.websiteId, operationIds: input.operationIds, risk, policy } } });
    return true;
  });
  return updated;
  } catch { return false; }
}

export async function authorizeExplicitPromptRepair(input: { repairId: string; websiteId: string; organizationId: string; userId: string; scopePage: string | null }) {
  const repair = await db.repairProposal.findFirst({ where: { id: input.repairId, websiteId: input.websiteId, status: "pending_approval" }, include: { website: { select: { wordpressAgent: { select: { revokedAt: true, lastSeenAt: true } } } } } });
  if (!repair || repair.risk !== "low" || !repair.website.wordpressAgent || repair.website.wordpressAgent.revokedAt
    || repair.website.wordpressAgent.lastSeenAt.getTime() < Date.now() - 15 * 60_000 || !proposalIsExecutable(repair.proposal, repair.operationIds)) return false;
  const proposal = repair.proposal as Record<string, unknown>;
  const instructions = proposal.instructions as Record<string, unknown>;
  const step = (instructions.steps as Array<{ operation: string; parameters: Record<string, string> }>)[0];
  if (step.operation !== "replace_post_link" || (input.scopePage && step.parameters.pageUrl !== input.scopePage)) return false;
  if (await findActiveRepairConflict(input.websiteId, repair.id, proposal, repair.operationIds)) return false;
  const decision = await authorizeRepairExecution({ repairId: repair.id, websiteId: input.websiteId, requesterUserId: input.userId, mode: "prompt" });
  if (decision.outcome !== "REQUIRES_APPROVAL") return false;
  const now = new Date();
  return db.$transaction(async (tx) => {
    await tx.$queryRaw`WITH advisory_lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(hashtext(${input.websiteId}))) SELECT 1 FROM advisory_lock`;
    if (await findActiveRepairConflict(input.websiteId, repair.id, proposal, repair.operationIds)) return false;
    const finalProposal = { ...proposal, authorization: { mode: "explicit_prompt", userId: input.userId, approvedAt: now.toISOString(), scopePage: input.scopePage }, executionRequest: { mode: "apply_on_site_poll", requestedAt: now.toISOString() } };
    const claimed = await tx.repairProposal.updateMany({ where: { id: repair.id, status: "pending_approval" }, data: {
      status: "approved", approvalStatus: "approved", approvedAt: now, approvedBy: "prompt_authorization",
      proposal: finalProposal as Prisma.InputJsonObject,
    } });
    if (claimed.count !== 1) return false;
    await createRepairAuthorizationGrant(tx, { repairId: repair.id, proposal: finalProposal, operationIds: repair.operationIds, websiteId: input.websiteId, issueId: repair.issueId, userId: input.userId, method: "prompt", scope: { kind: "prompt_exact_operation", scopePage: input.scopePage, operationIds: repair.operationIds, parameters: step.parameters } });
    await tx.repairEvent.create({ data: { repairId: repair.id, eventType: "prompt_authorized_and_queued", actor: input.userId, details: { operationIds: repair.operationIds, scopePage: input.scopePage } } });
    await tx.auditLog.create({ data: { action: "prompt_repair_authorized", actorType: "admin", actorId: input.userId, actorUserId: input.userId, organizationId: input.organizationId, resourceType: "repair", resourceId: repair.id, details: { websiteId: input.websiteId, operationIds: repair.operationIds, scopePage: input.scopePage } } });
    return true;
  });
}

/** Convert fresh stored findings into proposals only when the site has explicitly enabled standing execution. */
export async function proposeStandingEligibleRepair(websiteId: string, issueId: string) {
  const policy = await getRepairAuthorization(websiteId);
  if (policy.mode !== "auto_eligible" || policy.paused || policy.allowedOperations.length === 0) return false;
  const issue = await db.issue.findFirst({
    where: { id: issueId, websiteId, status: { in: ["open", "acknowledged"] } },
    include: { website: { select: { id: true, name: true, url: true, organizationId: true, wordpressAgent: { select: { id: true, diagnostics: true, revokedAt: true, lastSeenAt: true } } } } },
  });
  const agent = issue?.website.wordpressAgent;
  if (!issue || !agent || agent.revokedAt || agent.lastSeenAt.getTime() < Date.now() - 15 * 60_000) return false;
  const diagnosticData = agent.diagnostics && typeof agent.diagnostics === "object" && !Array.isArray(agent.diagnostics) ? agent.diagnostics as Prisma.JsonObject : {};
  const evidence = issue.evidence && typeof issue.evidence === "object" && !Array.isArray(issue.evidence)
    ? { ...(issue.evidence as Prisma.JsonObject), editablePages: Array.isArray(diagnosticData.editablePages) ? diagnosticData.editablePages : [] }
    : issue.evidence;
  const plan = boundedRepairPlan({ fingerprint: issue.fingerprint, title: issue.title, description: issue.description }, evidence);
  if (!plan.candidate) return false;
  const operationIds = plan.instructions.steps.map((step) => step.operation);
  const risk = repairRiskForOperations(operationIds);
  const riskRank = { low: 0, medium: 1, high: 2 };
  if (operationIds.length !== 1 || !policy.allowedOperations.includes(operationIds[0]) || risk === "high" || riskRank[risk] > riskRank[policy.maxRisk]) return false;
  const created = await db.$transaction(async (tx) => {
    await tx.$queryRaw`WITH advisory_lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(hashtext(${websiteId}))) SELECT 1 FROM advisory_lock`;
    const active = await tx.repairProposal.findFirst({ where: { issueId, status: { in: ["pending_approval", "approved", "executing", "in_progress"] } }, select: { id: true } });
    if (active) return null;
    const proposal = await tx.repairProposal.create({ data: {
      websiteId, issueId, risk, initiatingInterface: "standing_policy", operationIds,
      requiredPermissions: ["manage_options"], approvalStatus: "pending",
      backupStatus: requiresRecoveryPoint(operationIds) ? "not_started" : "not_required",
      executionStatus: "not_started", verificationStatus: "not_started", rollbackStatus: "not_requested",
      proposal: { ...plan.proposal, risk, instructions: plan.instructions, executionAvailable: true, relevantTools: issue.toolIds, evidenceBacked: true } as Prisma.InputJsonObject,
    } });
    await tx.repairEvent.create({ data: { repairId: proposal.id, eventType: "standing_policy_proposal_created", actor: "standing_policy", details: { issueId, operationIds, risk } } });
    await tx.auditLog.create({ data: { action: "standing_policy_repair_proposed", actorType: "system", organizationId: issue.website.organizationId, resourceType: "repair", resourceId: proposal.id, details: { websiteId, issueId, operationIds, risk } } });
    return proposal;
  });
  if (!created) return false;
  return applyStandingRepairAuthorization({ repairId: created.id, websiteId, organizationId: issue.website.organizationId, operationIds, risk, agentId: agent.id });
}

export function proposalIsExecutable(proposal: unknown, operationIds: string[]) {
  if (operationIds.length !== 1 || !proposal || typeof proposal !== "object" || Array.isArray(proposal)) return false;
  const data = proposal as Record<string, unknown>;
  if (isHostingRepairProposal(data)) return false;
  if (data.executionAvailable !== true || (Array.isArray(data.manualGuidance) && data.manualGuidance.length > 0)) return false;
  const instructions = data.instructions && typeof data.instructions === "object" && !Array.isArray(data.instructions) ? data.instructions as Record<string, unknown> : {};
  const steps = Array.isArray(instructions.steps) ? instructions.steps : [];
  const parsed = steps.length === 1 ? repairStepSchema.safeParse(steps[0]) : null;
  return Boolean(parsed?.success && parsed.data.operation === operationIds[0]);
}

export function repairConflictKey(proposal: unknown, operationIds: string[]) {
  if (operationIds.length !== 1 || !proposal || typeof proposal !== "object" || Array.isArray(proposal)) return null;
  const data = proposal as Record<string, unknown>;
  const instructions = data.instructions && typeof data.instructions === "object" && !Array.isArray(data.instructions) ? data.instructions as Record<string, unknown> : {};
  const steps = Array.isArray(instructions.steps) ? instructions.steps : [];
  const parsed = steps.length === 1 ? repairStepSchema.safeParse(steps[0]) : null;
  if (!parsed?.success) return null;
  const { operation, parameters } = parsed.data;
  if (operation === "disable_plugin" || operation === "switch_theme") return "site-wide-component-change";
  if (operation === "replace_post_link") return `post:${parameters.postId}`;
  if (operation === "update_setting") return `setting:${parameters.option}`;
  if (operation === "add_scoped_css_rule") return `css:${parameters.selector}`;
  return `${operation}:${JSON.stringify(parameters)}`;
}

export async function findActiveRepairConflict(websiteId: string, repairId: string, proposal: unknown, operationIds: string[], ignoreRepairIds: string[] = []) {
  const key = repairConflictKey(proposal, operationIds);
  if (!key) return "The operation target could not be validated.";
  const excludedIds = [...new Set([repairId, ...ignoreRepairIds])];
  const active = await db.repairProposal.findMany({ where: { websiteId, id: { notIn: excludedIds }, status: { in: ["pending_approval", "approved", "executing", "in_progress"] } }, select: { id: true, proposal: true, operationIds: true } });
  for (const candidate of active) {
    const existingKey = repairConflictKey(candidate.proposal, candidate.operationIds);
    if (!existingKey) continue;
    if (key === "site-wide-component-change" || existingKey === "site-wide-component-change" || key === existingKey) return candidate.id;
  }
  return null;
}
