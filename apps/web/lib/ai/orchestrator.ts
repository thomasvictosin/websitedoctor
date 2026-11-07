import { getAiEngine } from "./index";
import { analyzeFindingWithEngine, type FindingAnalysis, type FindingEvidence } from "./finding-analysis.ts";
import type { DiagnosticEvidenceSource } from "./tool-registry";
import { determineRepairRisk } from "./policy";
export { determineRepairRisk, determineSeverity } from "./policy";
export type { FindingAnalysis, FindingEvidence } from "./finding-analysis.ts";

export async function analyzeFinding(input: {
  website: { name: string; url: string };
  source: DiagnosticEvidenceSource;
  finding: FindingEvidence;
  evidence: Record<string, unknown>;
}): Promise<FindingAnalysis> {
  return analyzeFindingWithEngine(getAiEngine(), input);
}

export async function reviewRepairOutcome(input: {
  proposal: unknown;
  result: { status: string; verified: boolean; message: string; backupId?: string };
  beforeEvidence: unknown;
  afterEvidence: unknown;
}) {
  const engine = getAiEngine();
  const deterministicRollbackRequired = input.result.status === "failed"
    || input.result.status === "verification_failed"
    || (input.result.status === "completed" && !input.result.verified);
  let review: Awaited<ReturnType<typeof engine.reviewRepair>> | null = null;
  let comparison: Awaited<ReturnType<typeof engine.compareBeforeAfter>> | null = null;
  const errors: string[] = [];

  const [reviewResult, comparisonResult] = await Promise.allSettled([
    engine.reviewRepair(input),
    engine.compareBeforeAfter({
      before: input.beforeEvidence,
      after: input.afterEvidence,
      execution: input.result,
    }),
  ]);
  if (reviewResult.status === "fulfilled") review = reviewResult.value;
  else errors.push(reviewResult.reason instanceof Error ? reviewResult.reason.message : "AI repair review failed.");
  if (comparisonResult.status === "fulfilled") comparison = comparisonResult.value;
  else errors.push(comparisonResult.reason instanceof Error ? comparisonResult.reason.message : "AI before/after comparison failed.");

  const rollbackRecommended = deterministicRollbackRequired
    || review?.recommendRollback === true
    || review?.successful === false
    || comparison?.regressionRisk === "high";
  return {
    review,
    comparison,
    rollbackRecommended,
    aiStatus: errors.length === 0 ? "completed" as const : "partial" as const,
    aiErrors: errors,
  };
}
