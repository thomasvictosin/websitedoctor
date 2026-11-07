import { NextResponse } from "next/server";
import { authIsConfigured, createSession, isSameOrigin, validAdminPassword } from "@/lib/auth";
import { verifyPassword } from "@/lib/password";
import { loginSchema } from "@/lib/login-input";
import { writeAuditLog } from "@/lib/audit-log";
import { enforceRateLimit, requestSourceHash } from "@/lib/rate-limit";
import { readBoundedJson } from "@/lib/request-json";
import { db } from "@/lib/db";

export const runtime = "nodejs";

export async function POST(request: Request) {
  if (!(await isSameOrigin(request))) {
    return NextResponse.json({ error: "Request origin was rejected." }, { status: 403 });
  }
  if (!authIsConfigured()) {
    return NextResponse.json({ error: "Authentication is not configured. Set ADMIN_PASSWORD_HASH, SESSION_SECRET, and (in production) APP_ORIGIN." }, { status: 503 });
  }
  const limited = await enforceRateLimit({
    namespace: "login",
    subject: requestSourceHash(request),
    limit: 10,
    windowMs: 15 * 60_000,
  });
  if (limited) return limited;

  const body = await readBoundedJson(request, 4096);
  const parsed = loginSchema.safeParse(body);
  if (!parsed.success) {
    await writeAuditLog({ action: "login_failed", actorType: "admin", request, details: { reason: "invalid_request" } });
    return NextResponse.json({ error: "Invalid password." }, { status: 401 });
  }
  const email = (parsed.data.email ?? "admin@localhost").trim().toLowerCase();
  const user = await db.user.findUnique({ where: { email }, select: { id: true, email: true, passwordHash: true, disabledAt: true } });
  const authenticated = Boolean(user && !user.disabledAt && (user.passwordHash
    ? verifyPassword(parsed.data.password, user.passwordHash)
    : user.id === "local-admin" && email === "admin@localhost" && validAdminPassword(parsed.data.password)));
  if (!authenticated || !user) {
    await writeAuditLog({
      action: "login_failed",
      actorType: "admin",
      request,
      details: { reason: "invalid_password" },
    });
    return NextResponse.json({ error: "Invalid password." }, { status: 401 });
  }

  await writeAuditLog({ action: "login_succeeded", actorType: "admin", actorId: user.id, actorUserId: user.id, request });
  await createSession(user.id);
  return NextResponse.json({ ok: true });
}
