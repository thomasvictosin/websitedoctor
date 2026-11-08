import { NextResponse } from "next/server";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { CleanupError } from "@/lib/cleanup-service";
import { db } from "@/lib/db";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { createPackage, describePackage, PACKAGE_CHUNK_BYTES, PACKAGE_MAX_BYTES } from "@/lib/packages";
import { readBoundedJson } from "@/lib/request-json";

export const runtime = "nodejs";

/** Uploaded plugin/theme packages for this website. */
export async function GET(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const authorization = await authorizeOwnerRequest(request, false);
  if ("response" in authorization) return authorization.response;
  const website = await db.website.findFirst({ where: ownedWebsiteWhere(authorization.ownerId, (await params).siteId), select: { id: true } });
  if (!website) return NextResponse.json({ error: "Website not found." }, { status: 404 });
  const packages = await db.softwarePackage.findMany({ where: { websiteId: website.id, status: { not: "expired" } }, orderBy: { createdAt: "desc" }, take: 30 });
  return NextResponse.json({ packages: packages.map(describePackage), chunkBytes: PACKAGE_CHUNK_BYTES, maxBytes: PACKAGE_MAX_BYTES }, { headers: { "cache-control": "no-store" } });
}

const createSchema = z.object({
  kind: z.enum(["plugin", "theme"]),
  target: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,99}(?:\/[A-Za-z0-9._-]+\.php)?$/),
  fileName: z.string().trim().min(1).max(200).regex(/\.zip$/i, "Upload a .zip file."),
  size: z.number().int().min(100).max(PACKAGE_MAX_BYTES),
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
}).strict();

/** Start an upload: the browser then sends the file in pieces and finalizes it. */
export async function POST(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const website = await db.website.findFirst({ where: { ...ownedWebsiteWhere(authorization.ownerId, (await params).siteId), organization: { members: { some: { userId: authorization.ownerId, role: { in: ["owner", "admin"] } } } } }, select: { id: true, organizationId: true } });
  if (!website) return NextResponse.json({ error: "Only owners and administrators can upload packages for this website." }, { status: 403 });
  const parsed = createSchema.safeParse(await readBoundedJson(request, 4_000));
  if (!parsed.success) return NextResponse.json({ error: parsed.error.issues[0]?.message ?? "Invalid upload." }, { status: 400 });
  if ((parsed.data.kind === "plugin") !== parsed.data.target.includes("/")) return NextResponse.json({ error: "Invalid target." }, { status: 400 });
  try {
    const created = await createPackage({ websiteId: website.id, organizationId: website.organizationId, userId: authorization.ownerId, ...parsed.data });
    return NextResponse.json({ packageId: created.id, chunkCount: created.chunkCount, chunkBytes: PACKAGE_CHUNK_BYTES }, { status: 201 });
  } catch (error) {
    if (error instanceof CleanupError) return NextResponse.json({ error: error.message }, { status: error.status });
    throw error;
  }
}
