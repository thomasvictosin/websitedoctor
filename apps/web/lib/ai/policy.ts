import type { Diagnosis } from "./engine";
import { repairRiskForOperations } from "../repair-policy.ts";

type Severity = "low" | "medium" | "high" | "critical";

const severityRank = { low: 0, medium: 1, high: 2, critical: 3 } as const;

export function determineSeverity(
  evidenceSeverity: Severity,
  modelSeverity?: Diagnosis["severity"],
  source?: string,
): Severity {
  const baseline = source === "availability_check" ? "high" : evidenceSeverity;
  if (!modelSeverity || severityRank[baseline] >= severityRank[modelSeverity]) return baseline;
  return modelSeverity;
}

export function determineRepairRisk(operations: string[]): "low" | "medium" | "high" {
  return repairRiskForOperations(operations);
}
