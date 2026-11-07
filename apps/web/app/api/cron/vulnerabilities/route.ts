import { timingSafeEqual } from "node:crypto";
import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { loadVulnerabilityIndex, refreshVulnerabilityIndex, storeVulnerabilityFindings } from "@/lib/vulnerabilities";

export const runtime = "nodejs";
export const maxDuration = 60;

function authorized(request: Request) {
  const secret = process.env.CRON_SECRET;
  if (!secret || secret.length < 16) return null;
  const expected = Buffer.from(`Bearer ${secret}`);
  const actual = Buffer.from(request.headers.get("authorization") ?? "");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

/** Daily: refresh the vulnerability index and re-match every connected site. */
export async function GET(request: Request) {
  const allowed = authorized(request);
  if (allowed === null) return NextResponse.json({ error: "CRON_SECRET is not configured (minimum 16 characters)." }, { status: 503 });
  if (!allowed) return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  const refresh = await refreshVulnerabilityIndex();
  const index = await loadVulnerabilityIndex();
  let sites = 0;
  let findings = 0;
  if (index) {
    for (const agent of await db.wordPressAgent.findMany({ where: { revokedAt: null }, select: { websiteId: true, diagnostics: true } })) {
      const result = await storeVulnerabilityFindings(agent.websiteId, agent.diagnostics, index);
      sites += 1;
      findings += "findings" in result ? result.findings ?? 0 : 0;
    }
  }
  return NextResponse.json({ refresh, indexFetchedAt: index?.fetchedAt ?? null, sites, findings }, { headers: { "cache-control": "no-store" } });
}
