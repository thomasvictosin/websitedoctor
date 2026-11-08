import type { Diagnosis, DiagnosisEvidence } from "./engine.ts";
import {
  deriveEvidenceSignals,
  selectEvidenceForAnalysis,
  selectRelevantTools,
  type DiagnosticEvidenceSource,
} from "./tool-registry.ts";
import { determineSeverity } from "./policy.ts";

export type FindingEvidence = {
  fingerprint: string;
  title: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
};

export type FindingAnalysis = {
  diagnosis: Diagnosis | null;
  severity: "low" | "medium" | "high" | "critical";
  confidence: number | null;
  relevantTools: ReturnType<typeof selectRelevantTools>;
  aiStatus: "completed" | "unavailable";
  aiError: string | null;
};

export async function analyzeFindingWithEngine(
  engine: { diagnose(evidence: DiagnosisEvidence): Promise<Diagnosis> },
  input: {
    website: { name: string; url: string };
    source: DiagnosticEvidenceSource;
    finding: FindingEvidence;
    evidence: Record<string, unknown>;
  },
): Promise<FindingAnalysis> {
  const findingReference = {
    fingerprint: input.finding.fingerprint,
    title: input.finding.title,
    description: input.finding.description,
  };
  const relevantTools = selectRelevantTools(deriveEvidenceSignals(input.source, input.evidence, findingReference));
  const selectedEvidence = selectEvidenceForAnalysis(input.source, input.evidence, relevantTools.map((tool) => tool.id), findingReference);
  try {
    const diagnosis = await engine.diagnose({
      websiteName: input.website.name,
      url: input.website.url,
      available: input.source !== "availability_check" || input.evidence.available === true,
      statusCode: typeof input.evidence.statusCode === "number" ? input.evidence.statusCode : null,
      responseTime: typeof input.evidence.responseTime === "number" ? input.evidence.responseTime : null,
      error: input.finding.description,
      issue: input.finding.title,
      evidence: selectedEvidence,
      relevantTools,
    });
    return {
      diagnosis,
      severity: determineSeverity(input.finding.severity, diagnosis.severity, input.source),
      confidence: diagnosis.confidence,
      relevantTools,
      aiStatus: "completed",
      aiError: null,
    };
  } catch (error) {
    const aiError = error instanceof Error ? error.message : "AI analysis failed.";
    return {
      diagnosis: null,
      severity: determineSeverity(input.finding.severity, undefined, input.source),
      confidence: null,
      relevantTools,
      aiStatus: "unavailable",
      aiError,
    };
  }
}
