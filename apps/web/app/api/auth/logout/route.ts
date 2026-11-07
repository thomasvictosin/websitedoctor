import { NextResponse } from "next/server";
import { authorizeRequest } from "@/lib/auth-api";
import { destroySession } from "@/lib/auth";
import { writeAuditLog } from "@/lib/audit-log";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const denied = await authorizeRequest(request, true);
  if (denied instanceof Response) return denied;
  await destroySession();
  await writeAuditLog({ action: "logout", actorType: "admin", actorId: denied, actorUserId: denied, request });
  return NextResponse.json({ ok: true });
}
