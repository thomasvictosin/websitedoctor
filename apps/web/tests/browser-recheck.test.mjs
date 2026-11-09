import test from "node:test";
import assert from "node:assert/strict";
import { isPendingRecheck } from "../lib/browser-recheck.ts";

const now = new Date("2026-11-09T10:00:00.000Z");

test("a fresh unanswered re-check request is pending", () => {
  assert.equal(isPendingRecheck({ requestedAt: "2026-11-09T09:40:00.000Z", reason: "fix", answeredAt: null }, now), true);
});

test("an answered request is no longer pending", () => {
  assert.equal(isPendingRecheck({ requestedAt: "2026-11-09T09:40:00.000Z", reason: "fix", answeredAt: "2026-11-09T09:55:00.000Z" }, now), false);
});

test("a request the runner never answered expires after a day (the daily scan covers it)", () => {
  assert.equal(isPendingRecheck({ requestedAt: "2026-11-08T09:59:00.000Z", reason: "fix", answeredAt: null }, now), false);
  assert.equal(isPendingRecheck(null, now), false);
});
