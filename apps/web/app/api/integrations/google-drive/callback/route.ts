import { createHash } from "node:crypto";
import { NextResponse } from "next/server";
import { getSessionUserId } from "@/lib/auth";
import { db } from "@/lib/db";
import { createGoogleDriveRootFolder, decryptGoogleDriveValue, encryptGoogleDriveValue, exchangeGoogleDriveAuthorizationCode } from "@/lib/google-drive";

export const runtime = "nodejs";

function dashboardRedirect(status: string) {
  const origin = process.env.APP_ORIGIN;
  if (!origin) throw new Error("APP_ORIGIN must be set for Google Drive OAuth callbacks.");
  const url = new URL("/", origin);
  url.searchParams.set("drive", status);
  return NextResponse.redirect(url);
}

export async function GET(request: Request) {
  const userId = await getSessionUserId();
  if (!userId) return dashboardRedirect("session_expired");
  const url = new URL(request.url);
  if (url.searchParams.has("error")) return dashboardRedirect("cancelled");
  const state = url.searchParams.get("state") ?? "";
  const code = url.searchParams.get("code") ?? "";
  if (!/^[A-Za-z0-9_-]{40,64}$/.test(state) || !code || code.length > 4096) {
    return dashboardRedirect("invalid_callback");
  }

  const stateHash = createHash("sha256").update(state).digest("hex");
  const pending = await db.googleDriveOAuthState.findFirst({
    where: { stateHash, userId, expiresAt: { gt: new Date() } },
    select: { id: true, organizationId: true },
  });
  if (!pending) return dashboardRedirect("invalid_state");
  const claimed = await db.googleDriveOAuthState.deleteMany({ where: { id: pending.id, userId, expiresAt: { gt: new Date() } } });
  if (claimed.count !== 1) return dashboardRedirect("invalid_state");
  const membership = await db.organizationMember.findFirst({
    where: { userId, organizationId: pending.organizationId, role: { in: ["owner", "admin"] } },
    select: { role: true },
  });
  if (!membership) return dashboardRedirect("permission_changed");

  const { refreshToken, accountEmail } = await exchangeGoogleDriveAuthorizationCode(code);
  const encryptedRefreshToken = encryptGoogleDriveValue(refreshToken);
  const existing = await db.googleDriveConnection.findUnique({
    where: { organizationId: pending.organizationId },
    select: { accountEmail: true, rootFolderId: true, encryptedRefreshToken: true },
  });
  let rootFolderId: string;
  if (existing?.accountEmail.toLowerCase() === accountEmail.toLowerCase()) {
    decryptGoogleDriveValue(existing.encryptedRefreshToken);
    rootFolderId = existing.rootFolderId;
  } else {
    rootFolderId = await createGoogleDriveRootFolder(encryptedRefreshToken);
  }
  await db.googleDriveConnection.upsert({
    where: { organizationId: pending.organizationId },
    create: {
      organizationId: pending.organizationId,
      connectedByUserId: userId,
      accountEmail,
      encryptedRefreshToken,
      rootFolderId,
    },
    update: { connectedByUserId: userId, accountEmail, encryptedRefreshToken, rootFolderId },
  });
  await db.auditLog.create({
    data: {
      action: "google_drive_connected",
      actorType: "admin",
      actorId: userId,
      actorUserId: userId,
      organizationId: pending.organizationId,
      resourceType: "google_drive",
      details: { accountEmail },
    },
  });
  return dashboardRedirect("connected");
}
