import { HOSTING_OPERATION_REGISTRY, validateHostingOperationTarget } from "./hosting.ts";

export type HostingRepairAdapter<RecoveryPoint> = {
  createRecoveryPoint(input: { operation: string; target: string }): Promise<RecoveryPoint | null | undefined>;
  apply(input: { operation: string; target: string }): Promise<void>;
  verify(input: { operation: string; target: string }): Promise<{ verified: boolean; message?: string }>;
  restore(input: { operation: string; target: string; recoveryPoint: RecoveryPoint }): Promise<void>;
};

export type HostingRepairResult =
  | { status: "blocked"; message: string; target?: string }
  | { status: "verified"; message: string; target: string }
  | { status: "rolled_back"; message: string; target: string }
  | { status: "rollback_failed"; message: string; rollbackError: string; target: string };

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "The hosting operation failed with an unknown error.";
}

export async function executeHostingRepair<RecoveryPoint>(input: {
  operation: string;
  target: string;
  root: string;
  approved: boolean;
  adapter: HostingRepairAdapter<RecoveryPoint>;
}): Promise<HostingRepairResult> {
  if (!Object.hasOwn(HOSTING_OPERATION_REGISTRY, input.operation)) {
    return { status: "blocked", message: "The requested operation is not in the hosting allowlist." };
  }
  const definition = HOSTING_OPERATION_REGISTRY[input.operation];
  if (definition.kind !== "repair" || !definition.requiresApproval || !definition.requiresRecoveryPoint || !definition.requiresVerification) {
    return { status: "blocked", message: "The operation is not eligible for the guarded hosting repair lifecycle." };
  }
  if (!input.approved) {
    return { status: "blocked", message: "Explicit approval is required before a hosting repair can run." };
  }

  const targetValidation = validateHostingOperationTarget(input.target, input.root);
  if (!targetValidation.ok || !targetValidation.normalized) {
    return { status: "blocked", message: targetValidation.message ?? "The target path could not be validated." };
  }
  const target = targetValidation.normalized;
  const operation = input.operation;
  const operationInput = { operation, target };
  const recoveryPoint = await input.adapter.createRecoveryPoint(operationInput);
  if (recoveryPoint === null || recoveryPoint === undefined) {
    return { status: "blocked", message: "No complete recovery point was created; no change was applied.", target };
  }

  try {
    await input.adapter.apply(operationInput);
    const verification = await input.adapter.verify(operationInput);
    if (verification.verified) {
      return { status: "verified", message: verification.message ?? "The change was verified.", target };
    }
    return await restoreAfterFailure(
      input.adapter,
      operationInput,
      recoveryPoint,
      verification.message ?? "Post-change verification did not pass.",
    );
  } catch (error) {
    return await restoreAfterFailure(input.adapter, operationInput, recoveryPoint, errorMessage(error));
  }
}

async function restoreAfterFailure<RecoveryPoint>(
  adapter: HostingRepairAdapter<RecoveryPoint>,
  operationInput: { operation: string; target: string },
  recoveryPoint: RecoveryPoint,
  failureMessage: string,
): Promise<HostingRepairResult> {
  try {
    await adapter.restore({ ...operationInput, recoveryPoint });
    return {
      status: "rolled_back",
      message: `${failureMessage} The saved recovery point was restored.`,
      target: operationInput.target,
    };
  } catch (error) {
    return {
      status: "rollback_failed",
      message: failureMessage,
      rollbackError: errorMessage(error),
      target: operationInput.target,
    };
  }
}
