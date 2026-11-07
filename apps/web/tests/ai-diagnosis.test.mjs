import test from "node:test";
import assert from "node:assert/strict";
import { createAiEngine } from "../lib/ai/engine.ts";

const websiteUrl = "https://example.test/";
const input = {
  websiteName: "Example",
  url: websiteUrl,
  available: false,
  statusCode: 503,
  responseTime: 420,
  error: "Server returned HTTP 503.",
  issue: "Availability failure (HTTP 503)",
  evidence: {
    checkedAt: "2026-11-02T10:00:00.000Z",
    finding: { title: "Availability failure (HTTP 503)" },
  },
  relevantTools: [{ id: "http_availability" }],
};

function validDiagnosis(overrides = {}) {
  return {
    issueTitle: "Server returned an HTTP 503 response",
    issueTitleEvidenceRefs: ["E4"],
    category: "availability",
    description: "The central HTTP check received status code 503.",
    descriptionEvidenceRefs: ["E4"],
    affectedWebsite: websiteUrl,
    affectedPage: null,
    affectedComponent: null,
    severity: "high",
    confidence: 0.91,
    facts: [{ claim: "The HTTP response status was 503.", evidenceRefs: ["E4"] }],
    hypotheses: [{ claim: "The origin server may be temporarily unavailable.", evidenceRefs: ["E4"] }],
    probableRootCause: {
      claim: "A temporary origin-server failure is possible.",
      status: "hypothesis",
      evidenceRefs: ["E4"],
    },
    alternativeExplanations: [],
    recommendedFix: {
      description: "Check origin server health and upstream dependencies.",
      evidenceRefs: ["E4"],
      risk: "low",
      approvalRequired: true,
      verificationProcedure: ["Run another availability check and confirm a successful response."],
    },
    ...overrides,
  };
}

test("diagnosis schema requires evidence-linked facts, hypotheses, and repair verification", async () => {
  let calls = 0;
  const engine = createAiEngine({
    async generateJson(prompt) {
      calls += 1;
      if (calls === 1) return { ...validDiagnosis(), confidence: "high" };
      assert.match(prompt, /failed validation/i);
      return validDiagnosis();
    },
  });

  const diagnosis = await engine.diagnose(input);
  assert.equal(calls, 2);
  assert.equal(diagnosis.affectedWebsite, websiteUrl);
  assert.equal(diagnosis.probableRootCause.status, "hypothesis");
  assert.deepEqual(diagnosis.facts[0].evidenceRefs, ["E4"]);
  assert.equal(diagnosis.evidenceReferences.find((item) => item.id === "E4")?.value, 503);
});

test("invalid evidence references and invented affected pages are rejected after correction", async () => {
  const engine = createAiEngine({
    async generateJson(_prompt, _evidence) {
      return validDiagnosis({
        affectedPage: "https://invented.example/path",
        facts: [{ claim: "A measurement was observed.", evidenceRefs: ["E99"] }],
      });
    },
  });

  await assert.rejects(engine.diagnose(input), /failed strict validation/i);
});

test("AI model unavailability rejects analysis without inventing a diagnosis", async () => {
  const engine = createAiEngine({
    async generateJson() {
      throw new Error("Model endpoint unavailable.");
    },
  });
  await assert.rejects(engine.diagnose(input), /Model endpoint unavailable/);
});

test("website assistant can cite only facts present in stored diagnostic evidence", async () => {
  const engine = createAiEngine({
    async generateJson(_prompt, evidence) {
      const statusRef = evidence.evidenceReferences.find((item) => item.path === "latestCheck.statusCode");
      return {
        answer: "The latest recorded check returned HTTP 503.",
        evidenceRefs: [statusRef.id],
      };
    },
  });
  const result = await engine.answerWebsiteQuestion("What did the latest check return?", {
    latestCheck: { statusCode: 503 },
  });
  assert.equal(result.answer, "The latest recorded check returned HTTP 503.");
  assert.equal(result.evidenceReferences.length, 1);
  assert.equal(result.evidenceReferences[0]?.value, 503);

  const invalidEngine = createAiEngine({
    async generateJson() {
      return { answer: "Invented", evidenceRefs: ["E99"] };
    },
  });
  await assert.rejects(invalidEngine.answerWebsiteQuestion("Question?", { latestCheck: { statusCode: 503 } }), /failed strict validation/i);
});
