import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { decryptHostingSecret, HOSTING_OPERATION_REGISTRY, normalizeHostingMethod, resolveHostingOperations, validateHostingOperationTarget } from "@/lib/hosting";
import { inspectPinnedSftpTarget } from "@/lib/hosting-sftp";
import { readBoundedJson } from "@/lib/request-json";

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
    orderBy: { createdAt: "desc" },
    include: { capabilities: { orderBy: { capability: "asc" } } },
  });

  return NextResponse.json(connections.map((connection) => {
    const capabilities = connection.capabilities.map((entry) => ({ capability: entry.capability, supported: entry.supported }));
    const operations = resolveHostingOperations(normalizeHostingMethod(connection.connectionMethod), capabilities);
    const implementedDiagnostics = new Set(["inspect_directory_structure", "inspect_file_permissions"]);
    return {
      connectionId: connection.id,
      provider: connection.provider,
      connectionMethod: connection.connectionMethod,
      status: connection.status,
      capabilities,
      availableOperations: operations.filter((operation) => (
        normalizeHostingMethod(connection.connectionMethod) === "sftp"
        && operation.kind === "diagnostic"
        && implementedDiagnostics.has(operation.operation)
      )).map((operation) => ({
        operation: operation.operation,
        kind: operation.kind,
        risk: operation.risk,
        description: operation.description,
        requiresApproval: operation.requiresApproval,
        requiresRecoveryPoint: operation.requiresRecoveryPoint,
        requiresVerification: operation.requiresVerification,
      })),
    };
  }));
}

export async function POST(
  request: Request,
  { params }: { params: Promise<{ siteId: string }> },
) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;

  const { siteId } = await params;
  const website = await db.website.findFirst({
    where: ownedWebsiteWhere(authorization.ownerId, siteId),
    select: { id: true, organizationId: true },
  });
  if (!website) return NextResponse.json({ error: "Website not found." }, { status: 404 });

  const body = (await readBoundedJson(request, 8192)) as Record<string, unknown>;
  const operationName = typeof body.operation === "string" ? body.operation : "";
  if (!Object.hasOwn(HOSTING_OPERATION_REGISTRY, operationName)) {
    return NextResponse.json({ error: "That hosting operation is not registered in the allowlist." }, { status: 400 });
  }
  const definition = HOSTING_OPERATION_REGISTRY[operationName];
  if (definition.kind !== "diagnostic") {
    return NextResponse.json({ error: "Remote hosting repairs are not implemented. No change was made." }, { status: 501 });
  }

  const connectionId = typeof body.connectionId === "string" ? body.connectionId : "";
  const connection = connectionId
    ? await db.hostingConnection.findFirst({
        where: {
          id: connectionId,
          websiteId: siteId,
          ownerId: authorization.ownerId,
          status: "connected",
        },
        select: {
          hostname: true,
          connectionMethod: true,
          documentRoot: true,
          authMethod: true,
          username: true,
          port: true,
          connectionMetadata: true,
          credential: { select: { encryptedValue: true } },
          capabilities: { select: { capability: true, supported: true } },
        },
      })
    : null;
  if (!connection) {
    return NextResponse.json({ error: "A connected hosting connection for this website is required." }, { status: 404 });
  }
  const availableOperations = resolveHostingOperations(
    normalizeHostingMethod(connection.connectionMethod),
    connection.capabilities,
  );
  if (!availableOperations.some((operation) => operation.operation === operationName)) {
    return NextResponse.json({ error: "This connection has not confirmed the capabilities required for that operation." }, { status: 400 });
  }
  const targetValue = typeof body.target === "string" ? body.target : null;
  const validationResult = targetValue && connection.documentRoot
    ? validateHostingOperationTarget(targetValue, connection.documentRoot)
    : { ok: false as const, message: "A target path and configured website root are required." };
  if (!validationResult.ok || !validationResult.normalized) {
    return NextResponse.json({ error: validationResult.message ?? "Target validation failed." }, { status: 400 });
  }

  if (definition.kind === "diagnostic") {
    if (
      normalizeHostingMethod(connection.connectionMethod) !== "sftp"
      || (operationName !== "inspect_directory_structure" && operationName !== "inspect_file_permissions")
    ) {
      return NextResponse.json({ error: "This diagnostic operation does not have an implemented adapter." }, { status: 501 });
    }
    const metadata = connection.connectionMetadata;
    const hostKeyFingerprint = metadata && typeof metadata === "object" && "hostKeyFingerprint" in metadata
      ? metadata.hostKeyFingerprint
      : null;
    if (
      typeof hostKeyFingerprint !== "string"
      || !connection.credential?.encryptedValue
      || !connection.username
      || !connection.documentRoot
    ) {
      return NextResponse.json({ error: "The SFTP connection is missing its pinned host key or credential." }, { status: 409 });
    }
    let result: Record<string, unknown>;
    try {
      result = await inspectPinnedSftpTarget({
        hostname: connection.hostname,
        port: connection.port ?? 22,
        username: connection.username,
        authMethod: connection.authMethod === "password" ? "password" : "key",
        secret: decryptHostingSecret(connection.credential.encryptedValue),
        hostKeyFingerprint,
        documentRoot: connection.documentRoot,
        target: validationResult.normalized,
        operation: operationName,
      });
    } catch {
      await db.auditLog.create({
        data: {
          action: "hosting_diagnostic_failed",
          actorType: "admin",
          actorId: authorization.ownerId,
          actorUserId: authorization.ownerId,
          organizationId: website.organizationId,
          resourceType: "hosting_connection",
          resourceId: connectionId,
          details: {
            websiteId: website.id,
            operation: operationName,
            target: validationResult.normalized,
            success: false,
          },
        },
      });
      return NextResponse.json({
        error: "SFTP inspection failed. Check the connection, target path, and remote permissions.",
      }, { status: 502 });
    }
    await db.auditLog.create({
      data: {
        action: "hosting_diagnostic_completed",
        actorType: "admin",
        actorId: authorization.ownerId,
        actorUserId: authorization.ownerId,
        organizationId: website.organizationId,
        resourceType: "hosting_connection",
        resourceId: connectionId,
        details: {
          websiteId: website.id,
          operation: operationName,
          target: validationResult.normalized,
          success: true,
        },
      },
    });
    return NextResponse.json({ ok: true, operation: operationName, result });
  }

  return NextResponse.json({ error: "This operation does not have an implemented hosting adapter." }, { status: 501 });
}
