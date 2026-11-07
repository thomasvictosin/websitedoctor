import { NextResponse } from "next/server";
import { Prisma } from "@prisma/client";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { normalizeHostingMethod, validateHostingRepairProposal } from "@/lib/hosting";
import { requestSourceHash } from "@/lib/rate-limit";
import { readBoundedJson } from "@/lib/request-json";

export const runtime = "nodejs";

const hostingRepairProposalSchema = z.object({
  connectionId: z.string().min(1).max(128),
  issueId: z.string().min(1).max(128),
  operation: z.string().min(1).max(100),
  target: z.string().min(1).max(512),
}).strict();

const activeRepairStatuses = ["pending_approval", "approved", "executing", "in_progress"];

export async function POST(
  request: Request,
  { params }: { params: Promise<{ siteId: string }> },
) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;

  const parsed = hostingRepairProposalSchema.safeParse(await readBoundedJson(request, 4096));
  if (!parsed.success) {
    return NextResponse.json({ error: parsed.error.issues[0]?.message ?? "Invalid hosting repair proposal." }, { status: 400 });
  }
  const { siteId } = await params;
  const website = await db.website.findFirst({
    where: ownedWebsiteWhere(authorization.ownerId, siteId),
    select: { id: true, organizationId: true },
  });
  if (!website) return NextResponse.json({ error: "Website not found." }, { status: 404 });

  const [issue, connection] = await Promise.all([
    db.issue.findFirst({
      where: { id: parsed.data.issueId, websiteId: website.id, status: { in: ["open", "acknowledged"] } },
      select: { id: true, title: true, fingerprint: true },
    }),
    db.hostingConnection.findFirst({
      where: {
        id: parsed.data.connectionId,
        websiteId: website.id,
        ownerId: authorization.ownerId,
        status: "connected",
      },
      select: { id: true, connectionMethod: true, hostname: true, documentRoot: true },
    }),
  ]);
  if (!issue) return NextResponse.json({ error: "Choose an issue belonging to this website." }, { status: 404 });
  if (!connection || normalizeHostingMethod(connection.connectionMethod) !== "sftp") {
    return NextResponse.json({ error: "A connected SFTP host is required to record a hosting repair proposal." }, { status: 409 });
  }

  const validated = validateHostingRepairProposal(parsed.data.operation, parsed.data.target, connection.documentRoot);
  if (!validated.ok) return NextResponse.json({ error: validated.message }, { status: 400 });
  const { operation, target } = validated;

  const repair = await db.$transaction(async (transaction) => {
    await transaction.$queryRaw`WITH advisory_lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(hashtext(${website.id}))) SELECT 1 FROM advisory_lock`;
    const existing = await transaction.repairProposal.findFirst({
      where: { issueId: issue.id, status: { in: activeRepairStatuses } },
      select: { id: true },
    });
    if (existing) return null;

    const title = `${operation.description} Target: ${target}`;
    const proposal = {
      issue: issue.title,
      rationale: `A hosting-level action was requested for review based on issue ${issue.fingerprint}. This request does not establish that the host change is appropriate.`,
      proposedChanges: [title],
      expectedImpact: "No remote change is performed by this proposal.",
      recoveryAvailability: "No hosting recovery point has been created. A future adapter must create and verify one before any write.",
      risk: operation.risk,
      requiresApproval: true,
      verificationPlan: [
        "Review the exact operation, target path, and issue evidence before approving.",
        "Approval records review only; remote hosting execution is disabled.",
        "Before any future write, a host adapter must create an operation-specific recovery point and verify the result.",
      ],
      manualGuidance: [
        "This hosting proposal is recorded for review only. It cannot change remote files.",
        "Do not treat approval as permission to execute a host repair; the app currently has no remote-write adapter.",
      ],
      executionAvailable: false,
      hostingRequest: {
        connectionId: connection.id,
        hostname: connection.hostname,
        operation: operation.operation,
        target,
        executionEnabled: false,
      },
    };

    const created = await transaction.repairProposal.create({
      data: {
        websiteId: website.id,
        issueId: issue.id,
        risk: operation.risk,
        initiatingInterface: "dashboard",
        operationIds: [operation.operation],
        requiredPermissions: ["hosting_access"],
        approvalStatus: "pending",
        backupStatus: "not_started",
        executionStatus: "not_started",
        verificationStatus: "not_started",
        rollbackStatus: "not_requested",
        proposal: proposal as Prisma.InputJsonValue,
      },
    });
    await transaction.repairEvent.create({
      data: {
        repairId: created.id,
        eventType: "hosting_repair_proposal_created",
        actor: "dashboard",
        details: {
          websiteId: website.id,
          issueId: issue.id,
          connectionId: connection.id,
          operation: operation.operation,
          target,
          executionEnabled: false,
        },
      },
    });
    await transaction.auditLog.create({
      data: {
        action: "hosting_repair_proposal_created",
        actorType: "admin",
        actorId: authorization.ownerId,
        actorUserId: authorization.ownerId,
        organizationId: website.organizationId,
        resourceType: "repair",
        resourceId: created.id,
        sourceHash: requestSourceHash(request),
        details: {
          websiteId: website.id,
          issueId: issue.id,
          connectionId: connection.id,
          operation: operation.operation,
          target,
          risk: operation.risk,
          executionEnabled: false,
        },
      },
    });
    return created;
  });

  if (!repair) return NextResponse.json({ error: "An active repair proposal already exists for this issue." }, { status: 409 });
  return NextResponse.json(repair, { status: 201, headers: { "cache-control": "no-store" } });
}
