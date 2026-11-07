import { NextResponse } from "next/server";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { createMcpToken, listMcpTokens, revokeMcpToken } from "@/lib/mcp-tokens";
import { getDefaultOrganizationId } from "@/lib/ownership";
import { requestSourceHash } from "@/lib/rate-limit";
import { currentPrincipal } from "@/lib/request-principal";
import { readBoundedJson } from "@/lib/request-json";

export const runtime = "nodejs";

const createSchema = z.object({
  name: z.string().trim().min(1).max(80),
  expiresInDays: z.union([z.literal(30), z.literal(90), z.literal(365), z.null()]).default(90),
}).strict();
const revokeSchema = z.object({ tokenId: z.string().min(1).max(64) }).strict();

// Token management requires a signed-in browser session. A request already
// authenticated by an MCP token must never mint or revoke tokens.
async function sessionOnly(request?: Request, requireSameOrigin = false) {
  if (currentPrincipal()) return { response: NextResponse.json({ error: "MCP tokens cannot manage MCP tokens." }, { status: 403 }) } as const;
  return authorizeOwnerRequest(request, requireSameOrigin);
}

async function audit(request: Request, userId: string, action: string, tokenId: string) {
  let organizationId: string | null = null;
  try { organizationId = await getDefaultOrganizationId(userId); } catch { organizationId = null; }
  await db.auditLog.create({
    data: { action, actorType: "admin", actorId: userId, actorUserId: userId, organizationId, resourceType: "mcp_access_token", resourceId: tokenId, sourceHash: requestSourceHash(request) },
  });
}

export async function GET() {
  const authorization = await sessionOnly();
  if ("response" in authorization) return authorization.response;
  return NextResponse.json({ tokens: await listMcpTokens(authorization.ownerId) }, { headers: { "cache-control": "no-store" } });
}

export async function POST(request: Request) {
  const authorization = await sessionOnly(request, true);
  if ("response" in authorization) return authorization.response;
  const parsed = createSchema.safeParse(await readBoundedJson(request, 1024));
  if (!parsed.success) return NextResponse.json({ error: "Give the token a name (1–80 characters) and an expiry of 30, 90, or 365 days, or none." }, { status: 400 });
  const created = await createMcpToken({ userId: authorization.ownerId, ...parsed.data });
  if ("error" in created) return NextResponse.json({ error: created.error }, { status: 409 });
  await audit(request, authorization.ownerId, "mcp_token_created", created.id);
  return NextResponse.json(created, { status: 201, headers: { "cache-control": "no-store" } });
}

export async function DELETE(request: Request) {
  const authorization = await sessionOnly(request, true);
  if ("response" in authorization) return authorization.response;
  const parsed = revokeSchema.safeParse(await readBoundedJson(request, 1024));
  if (!parsed.success) return NextResponse.json({ error: "Select a token to revoke." }, { status: 400 });
  if (!(await revokeMcpToken(authorization.ownerId, parsed.data.tokenId))) return NextResponse.json({ error: "Active token not found." }, { status: 404 });
  await audit(request, authorization.ownerId, "mcp_token_revoked", parsed.data.tokenId);
  return NextResponse.json({ ok: true }, { headers: { "cache-control": "no-store" } });
}
