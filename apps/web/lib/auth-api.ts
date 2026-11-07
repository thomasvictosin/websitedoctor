import { NextResponse } from "next/server";
import { getSessionUserId, isSameOrigin } from "./auth";
import { enforceRateLimit } from "./rate-limit";

export async function authorizeRequest(request?: Request, requireSameOrigin = false) {
  const ownerId = await getSessionUserId();
  if (!ownerId) {
    return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  }
  if (requireSameOrigin && (!request || !(await isSameOrigin(request)))) {
    return NextResponse.json({ error: "Request origin was rejected." }, { status: 403 });
  }
  return ownerId;
}

export async function authorizeOwnerRequest(request?: Request, requireSameOrigin = false) {
  const ownerId = await authorizeRequest(request, requireSameOrigin);
  if (ownerId instanceof NextResponse) return { response: ownerId } as const;
  const limited = await enforceRateLimit({
    namespace: "owner-api",
    subject: ownerId,
    limit: 300,
    windowMs: 60_000,
  });
  if (limited) return { response: limited } as const;
  return { ownerId } as const;
}
