import { timingSafeEqual } from "node:crypto";
import { NextResponse } from "next/server";
import { processScanQueueOnce } from "@/lib/scan-queue";
import { refreshDueRenewals } from "@/lib/renewals";
import { enqueueDueWebsites } from "@/lib/scheduler";

export const runtime = "nodejs";
// Serverless deployments have no long-lived worker, so a scheduled request
// (Vercel Cron, or any external scheduler) drives both scheduling and the
// scan queue. Jobs left unfinished keep their lease and are retried later.
export const maxDuration = 60;
const WORK_BUDGET_MS = 35_000;

function authorized(request: Request) {
  const secret = process.env.CRON_SECRET;
  if (!secret || secret.length < 16) return null;
  const expected = Buffer.from(`Bearer ${secret}`);
  const actual = Buffer.from(request.headers.get("authorization") ?? "");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export async function GET(request: Request) {
  const allowed = authorized(request);
  if (allowed === null) return NextResponse.json({ error: "CRON_SECRET is not configured (minimum 16 characters)." }, { status: 503 });
  if (!allowed) return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  const startedAt = Date.now();
  const queued = await enqueueDueWebsites();
  let processed = 0;
  while (Date.now() - startedAt < WORK_BUDGET_MS && await processScanQueueOnce()) processed += 1;
  // SSL, domain and hosting expiry: each site is checked once a day; reminders go out as dates approach.
  let renewals: unknown = null;
  try { renewals = await refreshDueRenewals(Math.max(5_000, 50_000 - (Date.now() - startedAt))); } catch (error) { renewals = { error: error instanceof Error ? error.message : "failed" }; }
  return NextResponse.json({ queued, processed, renewals, elapsedMs: Date.now() - startedAt }, { headers: { "cache-control": "no-store" } });
}
