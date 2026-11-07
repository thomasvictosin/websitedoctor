import { createHash, randomBytes } from "node:crypto";
import { NextResponse } from "next/server";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { findAdminWebsite } from "@/lib/google-drive-authorization";
import { createGoogleDriveAuthorizationUrl } from "@/lib/google-drive";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const url = new URL(request.url);
  const siteId = url.searchParams.get("siteId") ?? "";
  const website = siteId ? await findAdminWebsite(authorization.ownerId, siteId) : null;
  if (!website) return NextResponse.json({ error: "Choose a website you administer before connecting Google Drive." }, { status: 403 });

  const state = randomBytes(32).toString("base64url");
  await db.googleDriveOAuthState.deleteMany({ where: { expiresAt: { lt: new Date() } } });
  await db.googleDriveOAuthState.create({
    data: {
      stateHash: createHash("sha256").update(state).digest("hex"),
      organizationId: website.organizationId,
      userId: authorization.ownerId,
      expiresAt: new Date(Date.now() + 10 * 60_000),
    },
  });

  try {
    return NextResponse.redirect(createGoogleDriveAuthorizationUrl(state));
  } catch (error) {
    await db.googleDriveOAuthState.deleteMany({ where: { stateHash: createHash("sha256").update(state).digest("hex") } });
    throw error;
  }
}
