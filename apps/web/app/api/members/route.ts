import { NextResponse } from "next/server";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { getDefaultOrganizationId } from "@/lib/ownership";
import { hashPassword } from "@/lib/password";
import { readBoundedJson } from "@/lib/request-json";

export const runtime = "nodejs";
const memberSchema = z.object({
  email: z.string().email().max(254).transform((value) => value.trim().toLowerCase()),
  name: z.string().trim().min(1).max(200),
  temporaryPassword: z.string().min(12).max(128),
  role: z.enum(["admin", "member"]).default("member"),
});
const removalSchema = z.object({ userId: z.string().min(1).max(64) });

async function organizationFor(userId: string) {
  const organizationId = await getDefaultOrganizationId(userId);
  const membership = await db.organizationMember.findUnique({ where: { organizationId_userId: { organizationId, userId } } });
  return { organizationId, membership };
}

export async function GET() {
  const authorization = await authorizeOwnerRequest();
  if ("response" in authorization) return authorization.response;
  const { organizationId } = await organizationFor(authorization.ownerId);
  const members = await db.organizationMember.findMany({
    where: { organizationId },
    orderBy: { createdAt: "asc" },
    select: { role: true, createdAt: true, user: { select: { id: true, email: true, name: true, disabledAt: true } } },
  });
  return NextResponse.json({ organizationId, members }, { headers: { "cache-control": "no-store" } });
}

export async function POST(request: Request) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const { organizationId, membership } = await organizationFor(authorization.ownerId);
  if (!membership || !["owner", "admin"].includes(membership.role)) return NextResponse.json({ error: "Only organization owners and administrators can add members." }, { status: 403 });
  const body = await readBoundedJson(request, 4096);
  const parsed = memberSchema.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "Provide a valid name, email, role, and temporary password of at least 12 characters." }, { status: 400 });
  try {
    const member = await db.$transaction(async (transaction) => {
      const created = await transaction.user.create({
        data: { email: parsed.data.email, name: parsed.data.name, role: parsed.data.role, passwordHash: hashPassword(parsed.data.temporaryPassword) },
        select: { id: true, email: true, name: true, disabledAt: true },
      });
      await transaction.organizationMember.create({ data: { organizationId, userId: created.id, role: parsed.data.role } });
      await transaction.auditLog.create({
        data: {
          action: "organization_member_added", actorType: "admin", actorId: authorization.ownerId, actorUserId: authorization.ownerId,
          organizationId, resourceType: "user", resourceId: created.id, details: { role: parsed.data.role },
        },
      });
      return { ...created, role: parsed.data.role, createdAt: new Date() };
    });
    return NextResponse.json({ member }, { status: 201, headers: { "cache-control": "no-store" } });
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "P2002") return NextResponse.json({ error: "That email address already has an account." }, { status: 409 });
    return NextResponse.json({ error: error instanceof Error ? error.message : "Could not add organization member." }, { status: 500 });
  }
}

export async function DELETE(request: Request) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const { organizationId, membership } = await organizationFor(authorization.ownerId);
  if (!membership || !["owner", "admin"].includes(membership.role)) return NextResponse.json({ error: "Only organization owners and administrators can remove members." }, { status: 403 });
  const parsed = removalSchema.safeParse(await readBoundedJson(request, 4096));
  if (!parsed.success || parsed.data.userId === authorization.ownerId) return NextResponse.json({ error: "Select another member to remove." }, { status: 400 });
  const target = await db.organizationMember.findUnique({ where: { organizationId_userId: { organizationId, userId: parsed.data.userId } } });
  if (!target) return NextResponse.json({ error: "Member not found." }, { status: 404 });
  if (target.role === "owner") {
    const owners = await db.organizationMember.count({ where: { organizationId, role: "owner" } });
    if (owners <= 1) return NextResponse.json({ error: "An organization must retain at least one owner." }, { status: 409 });
  }
  await db.$transaction([
    db.organizationMember.delete({ where: { organizationId_userId: { organizationId, userId: parsed.data.userId } } }),
    db.auditLog.create({ data: { action: "organization_member_removed", actorType: "admin", actorId: authorization.ownerId, actorUserId: authorization.ownerId, organizationId, resourceType: "user", resourceId: parsed.data.userId } }),
  ]);
  return NextResponse.json({ ok: true });
}
