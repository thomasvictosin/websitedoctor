import { NextResponse } from "next/server";
import { Prisma } from "@prisma/client";
import { z } from "zod";
import { createOpaqueToken, hashOpaqueToken } from "@/lib/agent-auth";
import { enforceRateLimit, requestSourceHash } from "@/lib/rate-limit";
import { isSecureRequest } from "@/lib/origin";
import { db } from "@/lib/db";
import { readBoundedJson } from "@/lib/request-json";

export const runtime = "nodejs";
const registrationSchema = z.object({
  code: z.string().regex(/^[A-Za-z0-9_-]{40,64}$/),
  siteUrl: z.string().url().max(2048),
  siteName: z.string().trim().min(1).max(200),
  wpVersion: z.string().max(40),
  phpVersion: z.string().max(40),
  pluginVersion: z.string().max(40),
});

function originOf(rawUrl: string): string | null {
  try {
    const url = new URL(rawUrl);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) return null;
    const path = url.pathname.replace(/\/+$/, "") || "/";
    return `${url.origin.toLowerCase()}${path}`;
  } catch {
    return null;
  }
}

export async function POST(request: Request) {
  if (!isSecureRequest(request)) {
    return NextResponse.json({ error: "Agent registration requires HTTPS." }, { status: 400 });
  }
  const limited = await enforceRateLimit({
    namespace: "agent-registration",
    subject: requestSourceHash(request),
    limit: 10,
    windowMs: 60 * 60_000,
  });
  if (limited) return limited;
  const body = await readBoundedJson(request, 16_384);
  if (body === null) return NextResponse.json({ error: "Request is invalid or too large." }, { status: 413 });
  const parsed = registrationSchema.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "Invalid registration details." }, { status: 400 });

  const pairingHash = hashOpaqueToken(parsed.data.code);
  const agentToken = createOpaqueToken();
  const now = new Date();
  try {
    const result = await db.$transaction(async (transaction) => {
      const pairing = await transaction.agentPairing.findUnique({
        where: { tokenHash: pairingHash },
        include: {
          website: {
            select: {
              id: true,
              url: true,
              organizationId: true,
              wordpressAgent: { select: { id: true, revokedAt: true } },
            },
          },
        },
      });
      if (!pairing || pairing.consumedAt || pairing.expiresAt <= now) return null;
      if (originOf(pairing.website.url) !== originOf(parsed.data.siteUrl)) return null;
      if (pairing.website.wordpressAgent && !pairing.website.wordpressAgent.revokedAt) return null;
      const consumed = await transaction.agentPairing.updateMany({
        where: { id: pairing.id, consumedAt: null, expiresAt: { gt: now } },
        data: { consumedAt: now },
      });
      if (consumed.count !== 1) return null;
      const agentData = {
        siteUrl: parsed.data.siteUrl,
        siteName: parsed.data.siteName,
        wpVersion: parsed.data.wpVersion,
        phpVersion: parsed.data.phpVersion,
        pluginVersion: parsed.data.pluginVersion,
        diagnostics: Prisma.DbNull,
        lastSeenAt: now,
        revokedAt: null,
      };
      const agent = pairing.website.wordpressAgent
        ? await transaction.wordPressAgent.update({
          where: { id: pairing.website.wordpressAgent.id },
          data: agentData,
          select: { id: true },
        })
        : await transaction.wordPressAgent.create({
          data: { websiteId: pairing.website.id, ...agentData },
          select: { id: true },
        });
      await transaction.installationCredential.updateMany({
        where: { agentId: agent.id, revokedAt: null },
        data: { revokedAt: now },
      });
      await transaction.installationCredential.create({
        data: {
          agentId: agent.id,
          tokenHash: hashOpaqueToken(agentToken),
        },
      });
      await transaction.agentRequestNonce.deleteMany({ where: { agentId: agent.id } });
      await transaction.auditLog.create({
        data: {
          action: "wordpress_agent_registered",
          actorType: "wordpress_agent",
          actorId: agent.id,
          organizationId: pairing.website.organizationId,
          resourceType: "wordpress_agent",
          resourceId: agent.id,
          sourceHash: requestSourceHash(request),
        },
      });
      return agent;
    });
    if (!result) return NextResponse.json({ error: "Pairing code expired, was already used, or did not match this website." }, { status: 401 });
    return NextResponse.json({ agentId: result.id, token: agentToken }, {
      status: 201,
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "P2002") {
      return NextResponse.json({ error: "A WordPress agent is already connected to this website." }, { status: 409 });
    }
    console.error("WordPress agent registration failed:", error);
    return NextResponse.json({ error: "Agent registration failed." }, { status: 500 });
  }
}
