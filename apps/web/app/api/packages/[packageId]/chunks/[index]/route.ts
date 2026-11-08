import { NextResponse } from "next/server";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { CleanupError } from "@/lib/cleanup-service";
import { db } from "@/lib/db";
import { PACKAGE_CHUNK_BYTES, storeChunk } from "@/lib/packages";

export const runtime = "nodejs";

/** One 3 MB piece of an upload (raw bytes). */
export async function PUT(request: Request, { params }: { params: Promise<{ packageId: string; index: string }> }) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const { packageId, index } = await params;
  const owned = await db.softwarePackage.findFirst({ where: { id: packageId, website: { organization: { members: { some: { userId: authorization.ownerId, role: { in: ["owner", "admin"] } } } } } }, select: { id: true } });
  if (!owned) return NextResponse.json({ error: "Package not found." }, { status: 404 });
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (declared > PACKAGE_CHUNK_BYTES) return NextResponse.json({ error: "Piece too large." }, { status: 413 });
  const body = Buffer.from(await request.arrayBuffer());
  if (body.length > PACKAGE_CHUNK_BYTES) return NextResponse.json({ error: "Piece too large." }, { status: 413 });
  try {
    await storeChunk(packageId, Number(index), body);
    return NextResponse.json({ ok: true });
  } catch (error) {
    if (error instanceof CleanupError) return NextResponse.json({ error: error.message }, { status: error.status });
    throw error;
  }
}
