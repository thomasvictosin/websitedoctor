import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { enforceRateLimit } from "@/lib/rate-limit";
import { requestSourceKey } from "@/lib/request-source";
import { signAgentRequest } from "@/lib/agent-signature";
import { isSecureRequest } from "@/lib/origin";
import { isAgentCredentialActive } from "@/lib/agent-credential-policy";
export { signAgentRequest } from "@/lib/agent-signature";

const DEFAULT_MAX_SIGNED_BODY_BYTES = 100_000;
const MAX_CLOCK_SKEW_SECONDS = 300;
const globalForNonceCleanup = globalThis as typeof globalThis & { agentNonceCleanupAt?: number };

export function createOpaqueToken(): string {
  return randomBytes(32).toString("base64url");
}

export function hashOpaqueToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function safeEqualHex(left: string, right: string): boolean {
  if (!/^[a-f0-9]{64}$/i.test(left) || !/^[a-f0-9]{64}$/i.test(right)) return false;
  const a = Buffer.from(left, "hex");
  const b = Buffer.from(right, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}

async function digestBoundedBody(request: Request, maxBodyBytes: number): Promise<string | null> {
  const declaredLength = Number(request.headers.get("content-length") ?? 0);
  if (declaredLength > maxBodyBytes) return null;
  const reader = request.clone().body?.getReader();
  if (!reader) return createHash("sha256").digest("hex");
  const hash = createHash("sha256");
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBodyBytes) {
      await reader.cancel();
      return null;
    }
    hash.update(value);
  }
  return hash.digest("hex");
}

export async function authenticateAgent(
  request: Request,
  agentId: string,
  maxSignedBodyBytes = DEFAULT_MAX_SIGNED_BODY_BYTES,
) {
  if (!isSecureRequest(request)) {
    return { response: NextResponse.json({ error: "Agent API requests require HTTPS." }, { status: 400 }) };
  }
  const sourceLimit = await enforceRateLimit({
    namespace: "agent-auth-source",
    subject: requestSourceKey(request),
    limit: 300,
    windowMs: 60_000,
  });
  if (sourceLimit) return { response: sourceLimit };

  const authorization = request.headers.get("authorization") ?? "";
  const bearer = /^Bearer ([A-Za-z0-9_-]{40,64})$/.exec(authorization);
  const timestampHeader = request.headers.get("x-awd-timestamp") ?? "";
  const nonce = request.headers.get("x-awd-nonce") ?? "";
  const signature = request.headers.get("x-awd-signature") ?? "";
  const timestamp = Number(timestampHeader);
  if (!bearer
    || !/^\d{10}$/.test(timestampHeader)
    || !Number.isSafeInteger(timestamp)
    || Math.abs(Math.floor(Date.now() / 1000) - timestamp) > MAX_CLOCK_SKEW_SECONDS
    || !/^[a-f0-9]{32}$/i.test(nonce)
    || !/^[a-f0-9]{64}$/i.test(signature)) {
    return { response: NextResponse.json({ error: "Signed agent authentication is required." }, { status: 401 }) };
  }

  const tokenHash = hashOpaqueToken(bearer[1]);
  const candidate = await db.wordPressAgent.findUnique({
    where: { id: agentId },
    select: {
      id: true,
      websiteId: true,
      revokedAt: true,
      credentials: {
        where: {
          revokedAt: null,
        },
        select: { id: true, tokenHash: true, expiresAt: true, revokedAt: true },
        orderBy: { createdAt: "desc" },
      },
    },
  });
  const credential = candidate?.credentials.find((entry) => safeEqualHex(entry.tokenHash, tokenHash)
    && isAgentCredentialActive({ agentRevokedAt: candidate.revokedAt, credentialRevokedAt: entry.revokedAt, expiresAt: entry.expiresAt }));
  const agent = candidate && credential
    ? { id: candidate.id, websiteId: candidate.websiteId, credentialId: credential.id }
    : null;
  if (!agent) return { response: NextResponse.json({ error: "Agent authentication failed." }, { status: 401 }) };

  const limited = await enforceRateLimit({
    namespace: "wordpress-agent",
    subject: agent.id,
    limit: 120,
    windowMs: 60_000,
  });
  if (limited) return { response: limited };

  const bodyHash = await digestBoundedBody(request, maxSignedBodyBytes);
  if (!bodyHash) {
    return { response: NextResponse.json({ error: "Signed request body is too large." }, { status: 413 }) };
  }
  const url = new URL(request.url);
  const expectedSignature = signAgentRequest({
    token: bearer[1],
    method: request.method,
    target: `${url.pathname}${url.search}`,
    timestamp: timestampHeader,
    nonce,
    bodyHash,
  });
  if (!safeEqualHex(signature, expectedSignature)) {
    return { response: NextResponse.json({ error: "Agent request signature is invalid." }, { status: 401 }) };
  }

  try {
    await db.agentRequestNonce.create({ data: { agentId: agent.id, nonce } });
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "P2002") {
      return { response: NextResponse.json({ error: "Agent request was already used." }, { status: 409 }) };
    }
    throw error;
  }
  const currentTime = Date.now();
  if (!globalForNonceCleanup.agentNonceCleanupAt || currentTime - globalForNonceCleanup.agentNonceCleanupAt > 60_000) {
    globalForNonceCleanup.agentNonceCleanupAt = currentTime;
    await db.agentRequestNonce.deleteMany({ where: { createdAt: { lt: new Date(currentTime - 600_000) } } });
  }
  await db.$transaction([
    db.installationCredential.update({
      where: { id: agent.credentialId },
      data: { lastUsedAt: new Date() },
    }),
    db.wordPressAgent.update({
      where: { id: agent.id },
      data: { lastSeenAt: new Date() },
    }),
  ]);
  return { agent };
}
