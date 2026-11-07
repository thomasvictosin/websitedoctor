import { createHash, randomBytes } from "node:crypto";
import { db } from "@/lib/db";

const TOKEN_PREFIX = "awd_mcp_";
const MAX_ACTIVE_TOKENS_PER_USER = 10;
const LAST_USED_WRITE_INTERVAL_MS = 5 * 60_000;

export function hashMcpToken(secret: string): string {
  return createHash("sha256").update(secret).digest("hex");
}

export type CreatedMcpToken = {
  id: string;
  name: string;
  prefix: string;
  expiresAt: Date | null;
  createdAt: Date;
  /** Returned once at creation and never stored. */
  token: string;
};

export async function createMcpToken(input: { userId: string; name: string; expiresInDays: number | null }): Promise<CreatedMcpToken | { error: string }> {
  const active = await db.mcpAccessToken.count({
    where: { userId: input.userId, revokedAt: null, OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }] },
  });
  if (active >= MAX_ACTIVE_TOKENS_PER_USER) return { error: `You already have ${MAX_ACTIVE_TOKENS_PER_USER} active MCP tokens. Revoke one before creating another.` };
  const token = `${TOKEN_PREFIX}${randomBytes(32).toString("base64url")}`;
  const expiresAt = input.expiresInDays ? new Date(Date.now() + input.expiresInDays * 86_400_000) : null;
  const created = await db.mcpAccessToken.create({
    data: { userId: input.userId, name: input.name, tokenHash: hashMcpToken(token), prefix: token.slice(0, TOKEN_PREFIX.length + 6), expiresAt },
    select: { id: true, name: true, prefix: true, expiresAt: true, createdAt: true },
  });
  return { ...created, token };
}

export async function listMcpTokens(userId: string) {
  return db.mcpAccessToken.findMany({
    where: { userId },
    orderBy: { createdAt: "desc" },
    select: { id: true, name: true, prefix: true, lastUsedAt: true, expiresAt: true, revokedAt: true, createdAt: true },
  });
}

export async function revokeMcpToken(userId: string, tokenId: string): Promise<boolean> {
  const result = await db.mcpAccessToken.updateMany({ where: { id: tokenId, userId, revokedAt: null }, data: { revokedAt: new Date() } });
  return result.count === 1;
}

/** Resolves an `Authorization: Bearer awd_mcp_…` header to an active, enabled user. */
export async function verifyMcpBearer(authorizationHeader: string | null): Promise<{ userId: string; tokenId: string } | null> {
  const match = /^Bearer\s+(\S+)$/i.exec(authorizationHeader ?? "");
  const secret = match?.[1];
  if (!secret || !secret.startsWith(TOKEN_PREFIX) || secret.length > 200) return null;
  const record = await db.mcpAccessToken.findUnique({
    where: { tokenHash: hashMcpToken(secret) },
    select: { id: true, userId: true, revokedAt: true, expiresAt: true, lastUsedAt: true, user: { select: { disabledAt: true } } },
  });
  if (!record || record.revokedAt || record.user.disabledAt) return null;
  const now = Date.now();
  if (record.expiresAt && record.expiresAt.getTime() <= now) return null;
  if (!record.lastUsedAt || now - record.lastUsedAt.getTime() > LAST_USED_WRITE_INTERVAL_MS) {
    await db.mcpAccessToken.update({ where: { id: record.id }, data: { lastUsedAt: new Date(now) } });
  }
  return { userId: record.userId, tokenId: record.id };
}
