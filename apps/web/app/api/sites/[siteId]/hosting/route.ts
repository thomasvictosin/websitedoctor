import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { buildHostingConnectionRecord, encryptHostingSecret, fingerprintHostingCredential, normalizeHostingAuthMethod, testHostingConnection } from "@/lib/hosting";
import { readBoundedJson } from "@/lib/request-json";
import { hostingConnectionInputSchema } from "@/lib/validation";

export const runtime = "nodejs";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ siteId: string }> },
) {
  const authorization = await authorizeOwnerRequest();
  if ("response" in authorization) return authorization.response;
  const { siteId } = await params;

  const website = await db.website.findFirst({
    where: ownedWebsiteWhere(authorization.ownerId, siteId),
    select: { id: true },
  });
  if (!website) return NextResponse.json({ error: "Website not found." }, { status: 404 });

  const connections = await db.hostingConnection.findMany({
    where: { websiteId: website.id, ownerId: authorization.ownerId },
    include: { capabilities: { orderBy: { capability: "asc" } } },
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json(connections.map((connection) => ({
    ...connection,
    discoveredCapabilities: connection.discoveredCapabilities ?? connection.capabilities.map((capability) => ({
      capability: capability.capability,
      supported: capability.supported,
      details: capability.details,
    })),
    credentialId: undefined,
  })));
}

export async function POST(
  request: Request,
  { params }: { params: Promise<{ siteId: string }> },
) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;

  const body = await readBoundedJson(request, 16384);
  const parsed = hostingConnectionInputSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: parsed.error.issues[0]?.message ?? "Invalid hosting connection settings." }, { status: 400 });
  }

  const { siteId } = await params;
  const website = await db.website.findFirst({
    where: ownedWebsiteWhere(authorization.ownerId, siteId),
    select: { id: true, name: true, organizationId: true },
  });
  if (!website) return NextResponse.json({ error: "Website not found." }, { status: 404 });

  const probe = await testHostingConnection({
    method: parsed.data.method,
    hostname: parsed.data.hostname,
    port: parsed.data.port,
    username: parsed.data.username,
    authMethod: parsed.data.authMethod,
    secret: parsed.data.secret,
    hostKeyFingerprint: parsed.data.hostKeyFingerprint,
    documentRoot: parsed.data.documentRoot,
    provider: parsed.data.provider,
  });
  if (!probe.ok) {
    return NextResponse.json({ error: probe.message }, { status: 400 });
  }
  if (parsed.data.testConnection) {
    return NextResponse.json({
      ok: true,
      message: probe.message,
      capabilities: probe.capabilities,
    });
  }

  const connectionRecord = buildHostingConnectionRecord({
    provider: parsed.data.provider,
    method: parsed.data.method,
    hostname: parsed.data.hostname,
    username: parsed.data.username,
    port: parsed.data.port,
    authMethod: parsed.data.authMethod,
    documentRoot: parsed.data.documentRoot,
    secret: parsed.data.secret,
  });

  const created = await db.$transaction(async (transaction) => {
    let credentialId: string | null = null;
    if (parsed.data.secret && parsed.data.secret.trim().length > 0) {
      const credential = await transaction.hostingCredential.create({
        data: {
          ownerId: authorization.ownerId,
          name: `${website.name} ${connectionRecord.connectionMethod}`,
          kind: normalizeHostingAuthMethod(parsed.data.authMethod) === "token" ? "api_token" : normalizeHostingAuthMethod(parsed.data.authMethod) === "password" ? "password" : "ssh_key",
          encryptedValue: encryptHostingSecret(parsed.data.secret),
          keyFingerprint: fingerprintHostingCredential(parsed.data.secret.trim()),
        },
      });
      credentialId = credential.id;
    }

    const connection = await transaction.hostingConnection.create({
      data: {
        websiteId: website.id,
        ownerId: authorization.ownerId,
        provider: connectionRecord.provider,
        connectionMethod: connectionRecord.connectionMethod,
        hostname: connectionRecord.hostname,
        port: connectionRecord.port ?? null,
        username: connectionRecord.username,
        authMethod: connectionRecord.authMethod,
        documentRoot: connectionRecord.documentRoot,
        credentialId,
        status: probe.ok ? "connected" : "error",
        lastConnectionTest: new Date(),
        lastSuccessfulConnection: probe.ok ? new Date() : null,
        discoveredCapabilities: probe.capabilities,
        connectionMetadata: {
          providerName: connectionRecord.provider,
          authMethod: connectionRecord.authMethod,
          documentRoot: connectionRecord.documentRoot,
          hostKeyFingerprint: probe.metadata?.hostKeyFingerprint ?? null,
          testMode: parsed.data.testConnection,
        },
        capabilities: {
          createMany: {
            data: probe.capabilities.map((capability) => ({
              capability: capability.capability,
              supported: capability.supported,
            details: capability.details ? capability.details : undefined,
            })),
          },
        },
      },
      include: { capabilities: { orderBy: { capability: "asc" } } },
    });

    await transaction.auditLog.create({
      data: {
        action: "hosting_connection_created",
        actorType: "admin",
        actorId: authorization.ownerId,
        actorUserId: authorization.ownerId,
        organizationId: website.organizationId,
        resourceType: "hosting_connection",
        resourceId: connection.id,
        details: {
          websiteId: website.id,
          provider: connection.provider,
          connectionMethod: connection.connectionMethod,
          authMethod: connection.authMethod,
          hostname: connection.hostname,
        },
      },
    });

  return {
    ...connection,
    discoveredCapabilities: connection.discoveredCapabilities ?? connection.capabilities.map((capability) => ({
      capability: capability.capability,
      supported: capability.supported,
      details: capability.details,
    })),
    credentialId: undefined,
  };
  });

  return NextResponse.json(created, { status: 201 });
}
