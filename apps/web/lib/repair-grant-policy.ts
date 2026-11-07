import { createHash } from "node:crypto";
import type { Prisma } from "@prisma/client";

const GRANT_TTL_MS = 30 * 60_000;

function canonicalizeJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalizeJson);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalizeJson((value as Record<string, unknown>)[key])]));
  }
  return value;
}

export type RepairGrantRecord = {
  id: string;
  authorizationMethod: string | null;
  expiresAt: Date | null;
  consumedAt: Date | null;
  decision: string;
  executionResult?: string | null;
  batchId: string | null;
  executionWebsiteId: string | null;
  executionIssueId: string | null;
  executionProposalId: string | null;
};

export function repairOperationDigest(proposal: unknown, operationIds: string[]) {
  return createHash("sha256").update(JSON.stringify(canonicalizeJson({ operationIds, proposal }))).digest("hex");
}

export function matchRepairGrant<T extends RepairGrantRecord>(grants: T[], input: {
  now: Date;
  grantId?: string | null;
  consume?: boolean;
  websiteId: string;
  issueId: string | null;
  repairId: string;
  batchId?: string | null;
}) {
  return grants.find((grant) => (!input.grantId || grant.id === input.grantId)
    && grant.authorizationMethod && grant.expiresAt && grant.expiresAt > input.now
    && (input.consume ? !grant.consumedAt : true)
    && ((grant.decision === "authorized" || grant.decision === "auto_authorized")
      || (grant.decision === "consumed" && grant.executionResult === "task_dispatched"))
    && (grant.authorizationMethod !== "batch" || (Boolean(grant.batchId) && Boolean(input.batchId) && grant.batchId === input.batchId))
    && grant.executionWebsiteId === input.websiteId
    && grant.executionIssueId === input.issueId
    && grant.executionProposalId === input.repairId);
}

export function hasExpiredRepairGrant(grants: RepairGrantRecord[], now: Date) {
  return grants.some((grant) => grant.expiresAt && grant.expiresAt <= now);
}

export async function consumeRepairGrant(delegate: {
  updateMany(args: { where: { id: string; consumedAt: null; expiresAt: { gt: Date }; operationDigest: string }; data: { consumedAt: Date; decision: string } }): Promise<{ count: number }>;
}, input: { id: string; digest: string; now: Date }) {
  return delegate.updateMany({
    where: { id: input.id, consumedAt: null, expiresAt: { gt: input.now }, operationDigest: input.digest },
    data: { consumedAt: input.now, decision: "consumed" },
  });
}

export async function createRepairAuthorizationGrant(tx: Prisma.TransactionClient, input: {
  repairId: string; proposal: unknown; operationIds: string[]; userId?: string | null;
  method: "individual" | "batch" | "prompt" | "standing" | "wordpress_admin";
  websiteId: string; issueId: string | null; scope: Prisma.InputJsonValue; batchId?: string | null;
}) {
  const digest = repairOperationDigest(input.proposal, input.operationIds);
  return tx.repairApproval.create({ data: {
    repairId: input.repairId, actorUserId: input.userId ?? null,
    decision: input.method === "standing" ? "auto_authorized" : "authorized",
    comment: "Authorization is bound to the validated operation digest.",
    authorizationMethod: input.method, authorizationScope: input.scope, operationDigest: digest,
    expiresAt: new Date(Date.now() + GRANT_TTL_MS), batchId: input.batchId ?? null,
    executionWebsiteId: input.websiteId, executionIssueId: input.issueId, executionProposalId: input.repairId,
  } });
}
