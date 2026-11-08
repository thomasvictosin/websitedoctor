import { after, NextResponse } from "next/server";
import type { Prisma } from "@prisma/client";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { CleanupError, expireStaleRuns, PERFORMANCE_MEASURE_TITLES, startPerformanceChange } from "@/lib/cleanup-service";
import { db } from "@/lib/db";
import { getIntegrations } from "@/lib/integrations";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { PERFORMANCE_MEASURES, runPerformanceTest } from "@/lib/pagespeed";
import { readBoundedJson } from "@/lib/request-json";

export const runtime = "nodejs";
export const maxDuration = 180;
const RUNNING_KEY = "performance_running";

async function ownedSite(request: Request, siteId: string, write: boolean) {
  const authorization = await authorizeOwnerRequest(request, write);
  if ("response" in authorization) return { response: authorization.response } as const;
  const website = await db.website.findFirst({ where: ownedWebsiteWhere(authorization.ownerId, siteId), select: { id: true, organizationId: true, wordpressAgent: { select: { diagnostics: true, lastSeenAt: true } } } });
  if (!website) return { response: NextResponse.json({ error: "Website not found." }, { status: 404 }) } as const;
  return { website, ownerId: authorization.ownerId } as const;
}

async function runningMarker(websiteId: string) {
  return db.systemSetting.findFirst({ where: { scope: "website", scopeId: websiteId, key: RUNNING_KEY }, select: { id: true, value: true } });
}

/** Latest mobile and desktop results, score history, measure states and the latest speed-fix run. */
export async function GET(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const owned = await ownedSite(request, (await params).siteId, false);
  if ("response" in owned) return owned.response;
  const websiteId = owned.website.id;
  await expireStaleRuns(websiteId);
  const [reports, marker, integrations, runs] = await Promise.all([
    db.performanceReport.findMany({ where: { websiteId }, orderBy: { createdAt: "desc" }, take: 40 }),
    runningMarker(websiteId),
    getIntegrations(owned.website.organizationId),
    db.repairProposal.findMany({ where: { websiteId, operationIds: { has: "set_performance" } }, orderBy: { createdAt: "desc" }, take: 1, select: { id: true, status: true, verificationStatus: true, createdAt: true, proposal: true } }),
  ]);
  const startedAt = marker ? Date.parse(String((marker.value as { startedAt?: string }).startedAt ?? "")) : NaN;
  const running = Number.isFinite(startedAt) && Date.now() - startedAt < 4 * 60_000;
  const latest = (strategy: string) => reports.find((report) => report.strategy === strategy) ?? null;
  const diagnostics = (owned.website.wordpressAgent?.diagnostics ?? {}) as { performance?: { measures?: Array<{ id: string; enabled: boolean; verified: boolean | null; detail: string }>; server?: string; cachePlugins?: string[] }; site?: { pluginVersion?: string } };
  const reported = new Map((diagnostics.performance?.measures ?? []).map((measure) => [measure.id, measure]));
  const run = runs[0];
  const runProposal = (run?.proposal ?? {}) as { issue?: string; cleanup?: { steps?: Array<{ description?: string }>; execution?: { steps?: Array<{ status: string; message: string }>; verification?: { reasons?: string[] } } } };
  return NextResponse.json({
    keyConfigured: Boolean(integrations.pagespeedKey),
    running,
    mobile: latest("mobile"),
    desktop: latest("desktop"),
    history: reports.filter((report) => report.score !== null).slice(0, 30).map((report) => ({ strategy: report.strategy, score: report.score, createdAt: report.createdAt })).reverse(),
    supported: Boolean(diagnostics.performance),
    pluginVersion: diagnostics.site?.pluginVersion ?? null,
    server: diagnostics.performance?.server ?? null,
    cachePlugins: diagnostics.performance?.cachePlugins ?? [],
    measures: Object.entries(PERFORMANCE_MEASURES).map(([id, measure]) => ({ id, ...measure, enabled: reported.get(id)?.enabled ?? false, verified: reported.get(id)?.verified ?? null, detail: reported.get(id)?.detail ?? "" })),
    run: run ? { id: run.id, status: run.status, verificationStatus: run.verificationStatus, createdAt: run.createdAt, title: runProposal.issue ?? "Speed fixes", steps: (runProposal.cleanup?.steps ?? []).map((step) => step.description ?? ""), results: runProposal.cleanup?.execution?.steps ?? null, reasons: runProposal.cleanup?.execution?.verification?.reasons ?? [] } : null,
  }, { headers: { "cache-control": "no-store" } });
}

const actionSchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("test") }).strict(),
  z.object({ action: z.literal("fix"), changes: z.array(z.object({ measure: z.enum(Object.keys(PERFORMANCE_MEASURE_TITLES) as [string, ...string[]]), state: z.enum(["on", "off"]) }).strict()).min(1).max(11) }).strict(),
]);

/** test: run PageSpeed for mobile and desktop in the background. fix: apply or undo speed measures on the site. */
export async function POST(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const owned = await ownedSite(request, (await params).siteId, true);
  if ("response" in owned) return owned.response;
  const parsed = actionSchema.safeParse(await readBoundedJson(request, 4_000));
  if (!parsed.success) return NextResponse.json({ error: "Invalid request." }, { status: 400 });
  const websiteId = owned.website.id;
  if (parsed.data.action === "test") {
    const marker = await runningMarker(websiteId);
    const startedAt = marker ? Date.parse(String((marker.value as { startedAt?: string }).startedAt ?? "")) : NaN;
    if (Number.isFinite(startedAt) && Date.now() - startedAt < 4 * 60_000) return NextResponse.json({ running: true, message: "A test is already running." });
    const value = { startedAt: new Date().toISOString() } as Prisma.InputJsonValue;
    if (marker) await db.systemSetting.update({ where: { id: marker.id }, data: { value } });
    else await db.systemSetting.create({ data: { organizationId: owned.website.organizationId, scope: "website", scopeId: websiteId, key: RUNNING_KEY, value } });
    after(async () => {
      try { await runPerformanceTest(websiteId); } catch (error) { console.error("PageSpeed test failed:", error instanceof Error ? error.message : error); }
      await db.systemSetting.updateMany({ where: { scope: "website", scopeId: websiteId, key: RUNNING_KEY }, data: { value: { startedAt: null } } });
    });
    return NextResponse.json({ running: true, message: "Testing mobile and desktop with PageSpeed Insights; this takes about a minute." }, { status: 202 });
  }
  try {
    const started = await startPerformanceChange({ websiteId, organizationId: owned.website.organizationId, changes: parsed.data.changes as Array<{ measure: string; state: "on" | "off" }>, actor: { kind: "admin", userId: owned.ownerId } });
    return NextResponse.json(started, { status: 202 });
  } catch (error) {
    if (error instanceof CleanupError) return NextResponse.json({ error: error.message }, { status: error.status });
    throw error;
  }
}
