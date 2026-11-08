import { timingSafeEqual } from "node:crypto";
import { NextResponse } from "next/server";
import { z } from "zod";
import { db } from "@/lib/db";
import { runAndStoreCheck } from "@/lib/monitoring-service";
import { readBoundedJson } from "@/lib/request-json";

export const runtime = "nodejs";
export const maxDuration = 120;

/**
 * Vercel functions have no browser, so layout, mobile-menu, JavaScript-error
 * and accessibility checks run on a GitHub Actions runner with Playwright
 * (scripts/browser-checks.mjs). It lists the monitored sites here, scans each
 * one, and posts the result back; this route stores it exactly as an
 * in-process browser scan would be stored.
 */
function authorized(request: Request) {
  const secret = process.env.CRON_SECRET;
  if (!secret || secret.length < 16) return null;
  const expected = Buffer.from(`Bearer ${secret}`);
  const actual = Buffer.from(request.headers.get("authorization") ?? "");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function deny(request: Request) {
  const allowed = authorized(request);
  if (allowed === null) return NextResponse.json({ error: "CRON_SECRET is not configured (minimum 16 characters)." }, { status: 503 });
  if (!allowed) return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  return null;
}

export async function GET(request: Request) {
  const denied = deny(request);
  if (denied) return denied;
  const sites = await db.website.findMany({ where: { monitoringEnabled: true }, orderBy: { createdAt: "asc" }, select: { id: true, name: true, url: true } });
  return NextResponse.json({ sites }, { headers: { "cache-control": "no-store" } });
}

const finding = z.object({
  fingerprint: z.string().regex(/^browser:[\w:./-]{1,190}$/),
  title: z.string().min(1).max(300),
  severity: z.enum(["low", "medium", "high", "critical"]),
  description: z.string().max(4000),
  evidence: z.record(z.string(), z.unknown()),
});
const resultSchema = z.object({
  status: z.string().max(40),
  scannedUrl: z.string().max(2000),
  checkedAt: z.string().max(40),
  viewports: z.array(z.unknown()).max(10),
  pages: z.array(z.unknown()).max(200),
  pageLimit: z.number().int().nonnegative(),
  pageLimitReached: z.boolean(),
  crawlIncomplete: z.boolean(),
  metrics: z.record(z.string(), z.unknown()),
  errors: z.array(z.unknown()).max(200),
  findings: z.array(finding).max(500),
}).passthrough();
const bodySchema = z.object({ siteId: z.string().min(1).max(64), result: resultSchema }).strict();

export async function POST(request: Request) {
  const denied = deny(request);
  if (denied) return denied;
  const parsed = bodySchema.safeParse(await readBoundedJson(request, 3_500_000));
  if (!parsed.success) return NextResponse.json({ error: parsed.error.issues[0]?.message ?? "Invalid browser result." }, { status: 400 });
  const website = await db.website.findFirst({ where: { id: parsed.data.siteId, monitoringEnabled: true }, select: { id: true, name: true, url: true } });
  if (!website) return NextResponse.json({ error: "Website not found or not monitored." }, { status: 404 });
  const result = parsed.data.result;
  // The availability and outside security checks run here as usual; only the browser part comes from the runner.
  const stored = await runAndStoreCheck(website, "scheduled_browser", { scanBrowserSite: async () => result as never });
  return NextResponse.json({ siteId: website.id, scanSessionId: stored.scanSessionId, findings: result.findings.length });
}
