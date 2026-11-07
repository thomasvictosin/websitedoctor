import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { websiteUpdateSchema } from "@/lib/validation";
import { readBoundedJson } from "@/lib/request-json";
import { requestSourceHash } from "@/lib/rate-limit";

export const runtime = "nodejs";

export async function PUT(
  request: Request,
  { params }: { params: Promise<{ siteId: string }> },
) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const { siteId } = await params;
  const body = await readBoundedJson(request, 8192);
  const parsed = websiteUpdateSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: parsed.error.issues[0]?.message ?? "Invalid website settings." }, { status: 400 });
  }

  const website = await db.website.findFirst({ where: ownedWebsiteWhere(authorization.ownerId, siteId) });
  if (!website) return NextResponse.json({ error: "Website not found." }, { status: 404 });
  if (parsed.data.relatedWebsiteId) {
    if (parsed.data.relatedWebsiteId === siteId) return NextResponse.json({ error: "A website cannot be related to itself." }, { status: 400 });
    const related = await db.website.findFirst({
      where: { ...ownedWebsiteWhere(authorization.ownerId, parsed.data.relatedWebsiteId), organizationId: website.organizationId },
      select: { id: true, environmentType: true },
    });
    if (!related) return NextResponse.json({ error: "Related website not found in this organization." }, { status: 400 });
    if (related.environmentType === parsed.data.environmentType) return NextResponse.json({ error: "A related website must be in the other environment." }, { status: 400 });
  }

  const settingsChanged = website.url !== parsed.data.url
    || website.intervalMinutes !== parsed.data.intervalMinutes
    || website.monitoringEnabled !== parsed.data.monitoringEnabled
    || website.environmentType !== parsed.data.environmentType
    || website.relatedWebsiteId !== (parsed.data.relatedWebsiteId || null);
  const current = await db.$transaction(async (transaction) => {
    const updated = await transaction.website.updateMany({
      where: ownedWebsiteWhere(authorization.ownerId, siteId),
      data: {
        ...parsed.data,
        nextCheckAt: parsed.data.monitoringEnabled
          ? settingsChanged ? new Date() : website.nextCheckAt
          : null,
      },
    });
    if (updated.count !== 1) return null;
    const saved = await transaction.website.findFirst({
      where: ownedWebsiteWhere(authorization.ownerId, siteId),
    });
    if (!saved) return null;
    await transaction.auditLog.create({
      data: {
        action: "website_updated",
        actorType: "admin",
        actorId: authorization.ownerId,
        actorUserId: authorization.ownerId,
        organizationId: saved.organizationId,
        resourceType: "website",
        resourceId: saved.id,
        sourceHash: requestSourceHash(request),
        details: { monitoringSettingsChanged: settingsChanged },
      },
    });
    return saved;
  });
  if (!current) return NextResponse.json({ error: "Website not found." }, { status: 404 });
  return NextResponse.json(current);
}

export async function DELETE(
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
  const deleted = await db.$transaction(async (transaction) => {
    const result = await transaction.website.deleteMany({
      where: ownedWebsiteWhere(authorization.ownerId, siteId),
    });
    if (result.count !== 1) return result;
    await transaction.auditLog.create({
      data: {
        action: "website_deleted",
        actorType: "admin",
        actorId: authorization.ownerId,
        actorUserId: authorization.ownerId,
        organizationId: website.organizationId,
        resourceType: "website",
        resourceId: website.id,
        sourceHash: requestSourceHash(request),
      },
    });
    return result;
  });
  if (deleted.count === 0) return NextResponse.json({ error: "Website not found." }, { status: 404 });
  return NextResponse.json({ ok: true });
}
