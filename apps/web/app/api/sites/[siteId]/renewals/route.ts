import { NextResponse } from "next/server";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { describeRenewal, refreshRenewals, RENEWAL_KINDS, saveManualRenewal } from "@/lib/renewals";
import { readBoundedJson } from "@/lib/request-json";

export const runtime = "nodejs";
export const maxDuration = 60;

async function ownedSite(request: Request, siteId: string, write: boolean) {
  const authorization = await authorizeOwnerRequest(request, write);
  if ("response" in authorization) return { response: authorization.response } as const;
  const website = await db.website.findFirst({ where: ownedWebsiteWhere(authorization.ownerId, siteId), select: { id: true } });
  if (!website) return { response: NextResponse.json({ error: "Website not found." }, { status: 404 }) } as const;
  return { website } as const;
}

async function listing(websiteId: string) {
  const rows = await db.siteRenewal.findMany({ where: { websiteId } });
  const byKind = new Map(rows.map((row) => [row.kind, row]));
  return RENEWAL_KINDS.map((kind) => byKind.get(kind)).filter((row) => row !== undefined).map(describeRenewal);
}

/** SSL, domain and hosting expiry for one website (checked on first view, then daily). */
export async function GET(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const owned = await ownedSite(request, (await params).siteId, false);
  if ("response" in owned) return owned.response;
  const ssl = await db.siteRenewal.findUnique({ where: { websiteId_kind: { websiteId: owned.website.id, kind: "ssl" } }, select: { checkedAt: true } });
  if (!ssl?.checkedAt) await refreshRenewals(owned.website.id);
  return NextResponse.json({ renewals: await listing(owned.website.id) }, { headers: { "cache-control": "no-store" } });
}

/** Check SSL and domain again now. */
export async function POST(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const owned = await ownedSite(request, (await params).siteId, true);
  if ("response" in owned) return owned.response;
  await refreshRenewals(owned.website.id);
  return NextResponse.json({ renewals: await listing(owned.website.id) });
}

const manualSchema = z.object({
  kind: z.enum(["domain", "hosting"]),
  expiresAt: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).nullable(),
  provider: z.string().trim().max(120).nullable().optional(),
  notes: z.string().trim().max(500).nullable().optional(),
}).strict();

/** Owner-entered hosting date (or a domain date the registry does not publish). */
export async function PUT(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const owned = await ownedSite(request, (await params).siteId, true);
  if ("response" in owned) return owned.response;
  const parsed = manualSchema.safeParse(await readBoundedJson(request, 4_000));
  if (!parsed.success) return NextResponse.json({ error: "Enter a date as YYYY-MM-DD." }, { status: 400 });
  const expiresAt = parsed.data.expiresAt ? new Date(`${parsed.data.expiresAt}T23:59:59Z`) : null;
  if (expiresAt && Number.isNaN(expiresAt.getTime())) return NextResponse.json({ error: "That date does not exist." }, { status: 400 });
  await saveManualRenewal(owned.website.id, parsed.data.kind, { expiresAt, provider: parsed.data.provider || null, notes: parsed.data.notes || null });
  return NextResponse.json({ renewals: await listing(owned.website.id) });
}
