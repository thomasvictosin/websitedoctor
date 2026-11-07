import { NextResponse } from "next/server";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { createOpaqueToken, hashOpaqueToken } from "@/lib/agent-auth";
import { db } from "@/lib/db";
import { z } from "zod";
import { enforceRateLimit, requestSourceHash } from "@/lib/rate-limit";
import { readBoundedJson } from "@/lib/request-json";

export const runtime = "nodejs";
const pairingSchema = z.object({ websiteId: z.string().min(1).max(64) });

export async function POST(request: Request) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const limited = await enforceRateLimit({
    namespace: "agent-pairing",
    subject: authorization.ownerId,
    limit: 10,
    windowMs: 60 * 60_000,
  });
  if (limited) return limited;
  const body = await readBoundedJson(request, 4096);
  const parsed = pairingSchema.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "Select a valid website." }, { status: 400 });

  const website = await db.website.findFirst({
    where: ownedWebsiteWhere(authorization.ownerId, parsed.data.websiteId),
    include: { wordpressAgent: { select: { id: true, revokedAt: true } } },
  });
  if (!website) return NextResponse.json({ error: "Website not found." }, { status: 404 });
  if (website.wordpressAgent && !website.wordpressAgent.revokedAt) {
    return NextResponse.json({ error: "A WordPress agent is already connected. Disconnect it before pairing another." }, { status: 409 });
  }

  const code = createOpaqueToken();
  const expiresAt = new Date(Date.now() + 10 * 60_000);
  const now = new Date();
  await db.$transaction(async (transaction) => {
    await transaction.agentPairing.updateMany({
      where: { websiteId: website.id, consumedAt: null },
      data: { consumedAt: now },
    });
    await transaction.agentPairing.create({
      data: {
        websiteId: website.id,
        tokenHash: hashOpaqueToken(code),
        expiresAt,
      },
    });
    await transaction.auditLog.create({
      data: {
        action: "agent_pairing_code_created",
        actorType: "admin",
        actorId: authorization.ownerId,
        actorUserId: authorization.ownerId,
        organizationId: website.organizationId,
        resourceType: "website",
        resourceId: website.id,
        sourceHash: requestSourceHash(request),
      },
    });
  });
  return NextResponse.json({
    code,
    expiresAt: expiresAt.toISOString(),
    website: { id: website.id, name: website.name, url: website.url },
  }, { headers: { "cache-control": "no-store" } });
}
