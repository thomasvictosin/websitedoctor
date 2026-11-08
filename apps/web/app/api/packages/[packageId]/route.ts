import { NextResponse } from "next/server";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { CleanupError } from "@/lib/cleanup-service";
import { db } from "@/lib/db";
import { describePackage, finalizePackage, startPackageInstall } from "@/lib/packages";
import { readBoundedJson } from "@/lib/request-json";

export const runtime = "nodejs";
export const maxDuration = 60;

async function ownedPackage(request: Request, packageId: string) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return { response: authorization.response } as const;
  const pkg = await db.softwarePackage.findFirst({ where: { id: packageId, website: { organization: { members: { some: { userId: authorization.ownerId, role: { in: ["owner", "admin"] } } } } } }, include: { website: { select: { id: true, organizationId: true } } } });
  if (!pkg) return { response: NextResponse.json({ error: "Package not found." }, { status: 404 }) } as const;
  return { pkg, ownerId: authorization.ownerId } as const;
}

/** finalize: check and scan the completed upload. install: approve installing a package that passed the scan. */
export async function POST(request: Request, { params }: { params: Promise<{ packageId: string }> }) {
  const owned = await ownedPackage(request, (await params).packageId);
  if ("response" in owned) return owned.response;
  const body = z.object({ action: z.enum(["finalize", "install"]), issueId: z.string().max(64).nullable().optional() }).strict().safeParse(await readBoundedJson(request, 1_000));
  if (!body.success) return NextResponse.json({ error: "Unknown action." }, { status: 400 });
  try {
    if (body.data.action === "finalize") {
      await finalizePackage(owned.pkg.id);
    } else {
      const issueId = body.data.issueId ? (await db.issue.findFirst({ where: { id: body.data.issueId, websiteId: owned.pkg.website.id }, select: { id: true } }))?.id ?? null : null;
      const started = await startPackageInstall({ packageId: owned.pkg.id, websiteId: owned.pkg.website.id, organizationId: owned.pkg.website.organizationId, actor: { kind: "admin", userId: owned.ownerId }, issueId });
      return NextResponse.json({ ...started, package: describePackage((await db.softwarePackage.findUniqueOrThrow({ where: { id: owned.pkg.id } }))) });
    }
    return NextResponse.json({ package: describePackage(await db.softwarePackage.findUniqueOrThrow({ where: { id: owned.pkg.id } })) });
  } catch (error) {
    if (error instanceof CleanupError) return NextResponse.json({ error: error.message }, { status: error.status });
    throw error;
  }
}

export async function DELETE(request: Request, { params }: { params: Promise<{ packageId: string }> }) {
  const owned = await ownedPackage(request, (await params).packageId);
  if ("response" in owned) return owned.response;
  if (owned.pkg.status === "installing") return NextResponse.json({ error: "The package is being installed right now." }, { status: 409 });
  await db.softwarePackage.delete({ where: { id: owned.pkg.id } });
  return NextResponse.json({ deleted: true });
}
