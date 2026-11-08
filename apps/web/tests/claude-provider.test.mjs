import test from "node:test";
import assert from "node:assert/strict";
import { extractJsonObject, isClaudeModel, CLAUDE_MODELS, DEFAULT_CLAUDE_MODEL } from "../lib/ai/claude.ts";

test("the reply's JSON object is extracted even with a code fence or prose around it", () => {
  assert.deepEqual(extractJsonObject('{"answer":"ok","evidenceRefs":["E1"]}'), { answer: "ok", evidenceRefs: ["E1"] });
  assert.deepEqual(extractJsonObject('```json\n{"answer":"ok"}\n```'), { answer: "ok" });
  assert.deepEqual(extractJsonObject('Here it is: {"a":{"b":1}} done'), { a: { b: 1 } });
  assert.throws(() => extractJsonObject("I cannot help with that."), /did not return a JSON object/);
});

test("only the offered models are accepted, Opus by default", () => {
  assert.equal(DEFAULT_CLAUDE_MODEL, "claude-opus-5-5");
  assert.deepEqual(Object.keys(CLAUDE_MODELS), ["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"]);
  assert.equal(isClaudeModel("claude-sonnet-5-5"), true);
  assert.equal(isClaudeModel("gpt-5"), false);
});
