import { NextResponse } from "next/server";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { applyCloudflareProtection, cloudflareStatus, CloudflareError, connectCloudflare, disconnectCloudflare } from "@/lib/cloudflare";
import { db } from "@/lib/db";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { readBoundedJson } from "@/lib/request-json";

export const runtime = "nodejs";
export const maxDuration = 60;

async function ownedSite(request: Request, siteId: string, sameOrigin: boolean) {
  const authorization = await authorizeOwnerRequest(request, sameOrigin);
  if ("response" in authorization) return { response: authorization.response } as const;
  const website = await db.website.findFirst({ where: ownedWebsiteWhere(authorization.ownerId, siteId), select: { id: true, url: true, organizationId: true, wordpressAgent: { select: { diagnostics: true } } } });
  if (!website) return { response: NextResponse.json({ error: "Website not found." }, { status: 404 }) } as const;
  return { website, ownerId: authorization.ownerId } as const;
}

function handle(error: unknown) {
  if (error instanceof CloudflareError) return NextResponse.json({ error: error.message }, { status: error.status });
  throw error;
}

export async function GET(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const { siteId } = await params;
  const owned = await ownedSite(request, siteId, false);
  if ("response" in owned) return owned.response;
  try {
    return NextResponse.json(await cloudflareStatus(owned.website.id, owned.website.url), { headers: { "cache-control": "no-store" } });
  } catch (error) { return handle(error); }
}

const actionSchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("connect"), token: z.string().min(30).max(200) }).strict(),
  z.object({ action: z.literal("apply"), botFightMode: z.boolean().default(false), confirm: z.literal(true) }).strict(),
  z.object({ action: z.literal("remove"), confirm: z.literal(true) }).strict(),
  z.object({ action: z.literal("disconnect"), confirm: z.literal(true) }).strict(),
]);

export async function POST(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const { siteId } = await params;
  const owned = await ownedSite(request, siteId, true);
  if ("response" in owned) return owned.response;
  const parsed = actionSchema.safeParse(await readBoundedJson(request, 2048));
  if (!parsed.success) return NextResponse.json({ error: "Send action connect (with token), apply, remove or disconnect." }, { status: 400 });
  const plugins = ((owned.website.wordpressAgent?.diagnostics ?? {}) as { plugins?: Array<{ file?: string; active?: boolean }> }).plugins ?? [];
  const jetpack = plugins.some((plugin) => plugin.file === "jetpack/jetpack.php" && plugin.active);
  try {
    switch (parsed.data.action) {
      case "connect":
        return NextResponse.json(await connectCloudflare({ websiteId: owned.website.id, organizationId: owned.website.organizationId, siteUrl: owned.website.url, token: parsed.data.token, userId: owned.ownerId }), { status: 201 });
      case "apply":
        return NextResponse.json(await applyCloudflareProtection({ websiteId: owned.website.id, organizationId: owned.website.organizationId, siteUrl: owned.website.url, botFightMode: parsed.data.botFightMode, blockXmlrpc: !jetpack, userId: owned.ownerId }));
      case "remove":
        return NextResponse.json(await applyCloudflareProtection({ websiteId: owned.website.id, organizationId: owned.website.organizationId, siteUrl: owned.website.url, botFightMode: false, blockXmlrpc: false, remove: true, userId: owned.ownerId }));
      case "disconnect":
        await disconnectCloudflare(owned.website.id, owned.website.organizationId, owned.ownerId);
        return NextResponse.json({ connected: false });
    }
  } catch (error) { return handle(error); }
}
