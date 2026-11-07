import { NextResponse } from "next/server";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { CleanupError, PROTECTION_MEASURE_TITLES, startProtectionChange } from "@/lib/cleanup-service";
import { db } from "@/lib/db";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { getProtectionSettings, recentSiteAlerts, saveProtectionSettings } from "@/lib/protection";
import { readBoundedJson } from "@/lib/request-json";

export const runtime = "nodejs";
export const maxDuration = 60;

const RECOMMENDED = ["block_php_uploads", "protect_sensitive_files", "disable_file_editor", "disable_xmlrpc", "block_user_enumeration", "security_headers", "verified_crawlers"];

async function ownedSite(request: Request, siteId: string, sameOrigin: boolean) {
  const authorization = await authorizeOwnerRequest(request, sameOrigin);
  if ("response" in authorization) return { response: authorization.response } as const;
  const website = await db.website.findFirst({ where: ownedWebsiteWhere(authorization.ownerId, siteId), select: { id: true, organizationId: true, wordpressAgent: { select: { diagnostics: true } } } });
  if (!website) return { response: NextResponse.json({ error: "Website not found." }, { status: 404 }) } as const;
  return { website, ownerId: authorization.ownerId } as const;
}

/** Protection status: measures reported by the plugin, automatic responses, and recent alerts. */
export async function GET(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const { siteId } = await params;
  const owned = await ownedSite(request, siteId, false);
  if ("response" in owned) return owned.response;
  const diagnostics = (owned.website.wordpressAgent?.diagnostics ?? {}) as { hardening?: Array<{ id: string; enabled: boolean; verified: boolean | null; detail: string; changedAt: string | null }>; site?: { pluginVersion?: string } };
  const reported = new Map((diagnostics.hardening ?? []).map((measure) => [measure.id, measure]));
  const measures = RECOMMENDED.map((id) => ({ id, title: PROTECTION_MEASURE_TITLES[id], enabled: reported.get(id)?.enabled ?? false, verified: reported.get(id)?.verified ?? null, detail: reported.get(id)?.detail ?? "", reported: reported.has(id) }));
  // The site runs one change at a time, so any active run (fix, update, cleanup) blocks protection changes.
  const [runs, activeRun] = await Promise.all([
    db.repairProposal.findMany({
      where: { websiteId: owned.website.id, operationIds: { has: "set_hardening" }, proposal: { path: ["kind"], equals: "compromise_cleanup" } },
      orderBy: { createdAt: "desc" }, take: 3,
      select: { id: true, status: true, verificationStatus: true, createdAt: true, proposal: true },
    }),
    db.repairProposal.findFirst({
      where: { websiteId: owned.website.id, status: { in: ["approved", "executing"] }, proposal: { path: ["kind"], equals: "compromise_cleanup" } },
      orderBy: { createdAt: "desc" },
      select: { id: true, status: true, verificationStatus: true, createdAt: true, proposal: true },
    }),
  ]);
  const describe = (run: (typeof runs)[number]) => {
    const proposal = run.proposal as { issue?: string; cleanup?: { steps?: Array<{ description?: string; operation?: string }>; execution?: { steps?: Array<{ status: string; message: string }> } } };
    const cleanup = proposal.cleanup ?? {};
    return { id: run.id, status: run.status, createdAt: run.createdAt, title: proposal.issue ?? "Site change", protection: (cleanup.steps ?? []).every((step) => step.operation === "set_hardening"), steps: (cleanup.steps ?? []).map((step) => step.description ?? ""), results: cleanup.execution?.steps ?? null };
  };
  const pending = activeRun;
  const latest = runs.find((run) => run.status !== "approved" && run.status !== "executing");
  return NextResponse.json({
    pending: pending ? describe(pending) : null,
    latest: latest ? describe(latest) : null,
    pluginVersion: diagnostics.site?.pluginVersion ?? null,
    supported: Boolean(diagnostics.hardening),
    measures,
    settings: await getProtectionSettings(owned.website.id),
    alerts: await recentSiteAlerts(owned.website.id, new Date(Date.now() - 7 * 24 * 60 * 60_000)),
  }, { headers: { "cache-control": "no-store" } });
}

const settingsSchema = z.object({ selfHealing: z.boolean().optional(), autoUpdates: z.boolean().optional() }).strict();

/** Switch self-healing or automatic updates on or off. */
export async function PUT(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const { siteId } = await params;
  const owned = await ownedSite(request, siteId, true);
  if ("response" in owned) return owned.response;
  const parsed = settingsSchema.safeParse(await readBoundedJson(request, 1024));
  if (!parsed.success || !Object.keys(parsed.data).length) return NextResponse.json({ error: "Send selfHealing and/or autoUpdates as true or false." }, { status: 400 });
  return NextResponse.json({ settings: await saveProtectionSettings(owned.website.id, owned.website.organizationId, parsed.data, owned.ownerId) });
}

const changeSchema = z.union([
  z.object({ measure: z.string().max(60), state: z.enum(["on", "off"]), confirm: z.literal(true) }).strict(),
  z.object({ recommended: z.literal(true), confirm: z.literal(true) }).strict(),
]);

/** Turn one measure on/off, or all recommended measures on, through the plugin. */
export async function POST(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const { siteId } = await params;
  const owned = await ownedSite(request, siteId, true);
  if ("response" in owned) return owned.response;
  const parsed = changeSchema.safeParse(await readBoundedJson(request, 1024));
  if (!parsed.success) return NextResponse.json({ error: "Send { measure, state, confirm: true } or { recommended: true, confirm: true }." }, { status: 400 });
  const diagnostics = (owned.website.wordpressAgent?.diagnostics ?? {}) as { hardening?: Array<{ id: string; enabled: boolean }> };
  const changes = "recommended" in parsed.data
    ? RECOMMENDED.filter((id) => !(diagnostics.hardening ?? []).some((measure) => measure.id === id && measure.enabled)).map((measure) => ({ measure, state: "on" as const }))
    : [{ measure: parsed.data.measure, state: parsed.data.state }];
  if (!changes.length) return NextResponse.json({ error: "All recommended protection is already on." }, { status: 409 });
  try {
    const started = await startProtectionChange({ websiteId: owned.website.id, organizationId: owned.website.organizationId, changes, actor: { kind: request.headers.get("x-awd-interface") === "mcp" ? "mcp" : "admin", userId: owned.ownerId } });
    return NextResponse.json({ repairId: started.repairId, steps: started.steps.map((step) => step.description), status: "queued_for_site_poll", message: "Approved and sent to the site. It usually takes effect within a few seconds; each rule is tested on your server." }, { status: 201 });
  } catch (error) {
    if (error instanceof CleanupError) return NextResponse.json({ error: error.message }, { status: error.status });
    throw error;
  }
}
