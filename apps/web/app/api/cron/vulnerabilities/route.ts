import { timingSafeEqual } from "node:crypto";
import { NextResponse } from "next/server";
import { runDuePerformanceTests } from "@/lib/pagespeed";
import { refreshAllVulnerabilities } from "@/lib/vulnerabilities";

export const runtime = "nodejs";
export const maxDuration = 300;

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
  const vulnerabilities = await refreshAllVulnerabilities();
  // Weekly PageSpeed re-test per production site (needs a PageSpeed key in Settings).
  let performance: unknown = null;
  try { performance = await runDuePerformanceTests(Math.max(10_000, 200_000 - (Date.now() - startedAt))); } catch (error) { performance = { error: error instanceof Error ? error.message : "failed" }; }
  return NextResponse.json({ ...vulnerabilities, performance }, { headers: { "cache-control": "no-store" } });
}
