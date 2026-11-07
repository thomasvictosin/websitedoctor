import { createHash } from "node:crypto";
import { z } from "zod";

const recoverySnapshotSchema = z.object({
  id: z.string().min(1).max(64),
  created_at: z.string().datetime(),
  description: z.string().max(200),
  complete: z.literal(true),
  operations: z.array(z.record(z.string(), z.unknown())).length(1),
}).strict();

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function validateWordPressRecoverySnapshot(input: {
  backupId: string;
  repairOperation: string;
  repairParameters: Record<string, unknown>;
  snapshot: unknown;
}): { ok: true; snapshot: z.infer<typeof recoverySnapshotSchema>; target: string } | { ok: false; message: string } {
  const parsed = recoverySnapshotSchema.safeParse(input.snapshot);
  if (!parsed.success || parsed.data.id !== input.backupId) {
    return { ok: false, message: "The WordPress recovery point is malformed or its identifier does not match." };
  }
  const operation = parsed.data.operations[0];
  if (operation.operation !== input.repairOperation || !["disable_plugin", "switch_theme", "update_setting", "replace_post_link", "add_scoped_css_rule"].includes(input.repairOperation)) {
    return { ok: false, message: "The recovery point operation does not match the approved WordPress repair." };
  }
  if (operation.applied !== false || !Object.hasOwn(operation, "before") || !Object.hasOwn(operation, "after")) {
    return { ok: false, message: "A recovery point must contain the complete pre-change state before execution." };
  }
  const expectedTarget = input.repairOperation === "disable_plugin"
    ? input.repairParameters.plugin
    : input.repairOperation === "switch_theme"
      ? input.repairParameters.stylesheet
      : input.repairOperation === "update_setting"
        ? input.repairParameters.option
      : input.repairOperation === "replace_post_link"
        ? input.repairParameters.postId
        : typeof operation.target === "string" ? operation.target : null;
  if (String(operation.target) !== String(expectedTarget)) {
    return { ok: false, message: "The recovery point target does not match the approved repair target." };
  }

  if (input.repairOperation === "disable_plugin"
    && (typeof operation.before !== "boolean" || operation.before !== true || operation.after !== false)) {
    return { ok: false, message: "The plugin recovery point does not contain a valid active-to-inactive transition." };
  }
  if (input.repairOperation === "switch_theme"
    && (!isRecord(operation.before) || !isRecord(operation.after)
      || typeof operation.before.stylesheet !== "string" || typeof operation.before.template !== "string"
      || typeof operation.after.stylesheet !== "string" || typeof operation.after.template !== "string")) {
    return { ok: false, message: "The theme recovery point is incomplete." };
  }
  if (input.repairOperation === "update_setting"
    && (typeof operation.before !== "string" || typeof operation.after !== "string"
      || operation.before !== input.repairParameters.expectedCurrentValue || operation.after !== input.repairParameters.value
      || !["blogname", "blogdescription"].includes(String(operation.target)))) {
    return { ok: false, message: "The setting recovery point does not match the approved exact before and after values." };
  }
  if (input.repairOperation === "replace_post_link") {
    const before = operation.before;
    const after = operation.after;
    if (typeof before !== "string" || typeof after !== "string"
      || before.length > 200_000 || after.length > 200_000
      || typeof operation.before_sha256 !== "string"
      || createHash("sha256").update(before).digest("hex") !== operation.before_sha256
      || typeof operation.after_sha256 !== "string"
      || createHash("sha256").update(after).digest("hex") !== operation.after_sha256) {
      return { ok: false, message: "The post recovery point failed its content integrity check." };
    }
  }
  if (input.repairOperation === "add_scoped_css_rule") {
    const before = operation.before;
    const after = operation.after;
    if (operation.selector !== input.repairParameters.selector
      || typeof input.repairParameters.selector !== "string"
      || !/^body\.(?:page-id|postid)-[1-9][0-9]{0,9}\s+(?:#[A-Za-z_][A-Za-z0-9_-]*|\.[A-Za-z_][A-Za-z0-9_-]*)$/.test(input.repairParameters.selector)
      || typeof before !== "string" || typeof after !== "string"
      || before.length > 200_000 || after.length > 200_000
      || typeof operation.before_sha256 !== "string"
      || createHash("sha256").update(before).digest("hex") !== operation.before_sha256
      || typeof operation.after_sha256 !== "string"
      || createHash("sha256").update(after).digest("hex") !== operation.after_sha256) {
      return { ok: false, message: "The staging CSS recovery point failed its content integrity check." };
    }
  }

  return { ok: true, snapshot: parsed.data, target: String(operation.target) };
}

export function repairParametersFromProposal(proposal: unknown): { operation: string; parameters: Record<string, unknown> } | null {
  if (!isRecord(proposal) || !isRecord(proposal.instructions) || !Array.isArray(proposal.instructions.steps)
    || proposal.instructions.steps.length !== 1) return null;
  const step = proposal.instructions.steps[0];
  if (!isRecord(step) || typeof step.operation !== "string" || !isRecord(step.parameters)) return null;
  return { operation: step.operation, parameters: step.parameters };
}
