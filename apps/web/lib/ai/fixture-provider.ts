import type { AiProvider } from "./provider";

/** Deterministic CI-only model double. It is deliberately unavailable in production. */
export class FixtureAiProvider implements AiProvider {
  async generateJson(prompt: string, evidence: unknown): Promise<unknown> {
    if (process.env.AIWD_FIXTURE_AI_FAILURE === "unavailable") throw new Error("Fixture model is unavailable.");
    if (process.env.AIWD_FIXTURE_AI_FAILURE === "malformed") return { invalid: true };
    const issueTitle = evidence && typeof evidence === "object" ? String((evidence as Record<string, unknown>).issue ?? "") : "";
    if (prompt.includes("Task: diagnose a website issue") && issueTitle === process.env.AIWD_FIXTURE_AI_FAILURE_TITLE) {
      throw new Error("Fixture model is unavailable for this finding.");
    }
    if (prompt.includes("Task: diagnose a website issue") && issueTitle === process.env.AIWD_FIXTURE_AI_MALFORMED_TITLE) return { invalid: true };
    if (prompt.includes("Task: diagnose a website issue")) return this.diagnosis(evidence);
    if (prompt.includes("Task: review a repair result")) {
      return { successful: true, summary: "The deterministic test model reviewed the recorded execution evidence.", remainingIssues: [], recommendRollback: false };
    }
    if (prompt.includes("Task: compare before and after diagnostic evidence")) {
      return { improved: true, summary: "The recorded before and after evidence was compared.", changes: ["The execution result and verification record were reviewed."], regressionRisk: "low" };
    }
    if (prompt.includes("Task: answer a question")) return { answer: "The fixture model can only answer from the supplied evidence.", evidenceRefs: [] };
    if (prompt.includes("Task: propose a repair")) {
      return { issue: "Recorded diagnostic finding", rationale: "The proposal is based on the supplied test evidence.", proposedChanges: [], risk: "high", requiresApproval: true, verificationPlan: ["Rerun diagnostics."] };
    }
    return { steps: [{ description: "Test operation", operation: "update_setting", parameters: { option: "blogname", expectedCurrentValue: "Old", value: "New" } }], rollbackPlan: ["Restore the saved previous setting value."], requiresApproval: true };
  }

  private diagnosis(evidence: unknown) {
    const input = evidence && typeof evidence === "object" ? evidence as Record<string, unknown> : {};
    const references = Array.isArray(input.evidenceReferences) ? input.evidenceReferences : [];
    const reference = references.find((item) => item && typeof item === "object" && /(^|\.)(issue|title|description|finding)$/i.test(String((item as Record<string, unknown>).path ?? "")))
      ?? references[0];
    const referenceId = reference && typeof reference === "object" && typeof (reference as Record<string, unknown>).id === "string"
      ? String((reference as Record<string, unknown>).id)
      : "E1";
    const website = typeof input.url === "string" ? input.url : "https://example.com";
    const issue = typeof input.issue === "string" ? input.issue : "The stored diagnostic finding";
    const claim = `The supplied diagnostic evidence records: ${issue}.`;
    return {
      issueTitle: issue.slice(0, 200), issueTitleEvidenceRefs: [referenceId], category: "wordpress",
      description: claim, descriptionEvidenceRefs: [referenceId], affectedWebsite: website,
      affectedPage: null, affectedComponent: null, severity: "medium", confidence: 0.8,
      facts: [{ claim, evidenceRefs: [referenceId] }], hypotheses: [],
      probableRootCause: { claim: "The supplied evidence is insufficient to confirm a root cause.", status: "insufficient_evidence", evidenceRefs: [referenceId] },
      alternativeExplanations: [],
      recommendedFix: { description: "Review the recorded evidence and use only a supported, reversible operation.", evidenceRefs: [referenceId], risk: "high", approvalRequired: true, verificationProcedure: ["Rerun the relevant diagnostic after an approved change."] },
    };
  }
}
