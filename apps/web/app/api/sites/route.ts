import { NextResponse } from "next/server";
import { browserRechecks } from "@/lib/browser-recheck";
import { db } from "@/lib/db";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { getDefaultOrganizationId, ownedWebsiteWhere } from "@/lib/ownership";
import { websiteInputSchema } from "@/lib/validation";
import { readBoundedJson } from "@/lib/request-json";
import { redactApiValue } from "@/lib/redaction";
import { requestSourceHash } from "@/lib/rate-limit";

export const runtime = "nodejs";

export async function GET() {
  const authorization = await authorizeOwnerRequest();
  if ("response" in authorization) return authorization.response;
  const websites = await db.website.findMany({
    where: ownedWebsiteWhere(authorization.ownerId),
    orderBy: { createdAt: "desc" },
    include: {
      checks: { orderBy: { checkedAt: "desc" }, take: 20 },
      _count: { select: { issues: true } },
      relatedWebsite: { select: { id: true, name: true, url: true, environmentType: true } },
      wordpressAgent: {
        select: {
          id: true,
          siteName: true,
          siteUrl: true,
          wpVersion: true,
          phpVersion: true,
          pluginVersion: true,
          diagnostics: true,
          lastSeenAt: true,
          revokedAt: true,
          executions: {
            orderBy: { createdAt: "desc" },
            take: 5,
            select: {
              id: true,
              status: true,
              createdAt: true,
              repair: { select: { issue: { select: { title: true } } } },
            },
          },
        },
      },
    },
  });
  const rechecks = await browserRechecks(websites.map((website) => website.id));
  const withRechecks = websites.map((website) => ({ ...website, browserRecheck: rechecks.get(website.id) ?? null }));
  return NextResponse.json(redactApiValue(withRechecks), { headers: { "cache-control": "no-store" } });
}

export async function POST(request: Request) {
  try {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const input = await readBoundedJson(request, 8192);
  if (input === null) return NextResponse.json({ error: "The website request was empty, invalid JSON, or too large." }, { status: 400 });
  const parsed = websiteInputSchema.safeParse(input);
  if (!parsed.success) {
    return NextResponse.json({ error: parsed.error.issues[0]?.message ?? "Invalid website." }, { status: 400 });
  }
  let organizationId: string;
  try {
    organizationId = await getDefaultOrganizationId(authorization.ownerId);
  } catch {
    return NextResponse.json({ error: "Your account is not linked to an organization yet. Refresh the page or contact the administrator." }, { status: 409 });
  }
  if (parsed.data.relatedWebsiteId) {
    const related = await db.website.findFirst({
      where: { ...ownedWebsiteWhere(authorization.ownerId, parsed.data.relatedWebsiteId), organizationId },
      select: { id: true, environmentType: true },
    });
    if (!related) return NextResponse.json({ error: "Related website not found in this organization." }, { status: 400 });
    if (related.environmentType === parsed.data.environmentType) return NextResponse.json({ error: "A related website must be in the other environment." }, { status: 400 });
  }

  try {
  const website = await db.$transaction(async (transaction) => {
    const created = await transaction.website.create({
      data: {
        ...parsed.data,
        ownerId: authorization.ownerId,
        organizationId,
        nextCheckAt: null,
      },
    });
    await transaction.auditLog.create({
      data: {
        action: "website_created",
        actorType: "admin",
        actorId: authorization.ownerId,
        actorUserId: authorization.ownerId,
        organizationId: created.organizationId,
        resourceType: "website",
        resourceId: created.id,
        sourceHash: requestSourceHash(request),
      },
    });
    return created;
  });
  return NextResponse.json(website, { status: 201 });
  } catch (error) {
    console.error("Website creation failed", error instanceof Error ? error.message : "Unknown error");
    return NextResponse.json({ error: "The website could not be saved. Check that the database is running and its schema is up to date, then try again." }, { status: 500 });
  }
  } catch (error) {
    console.error("Website creation request failed", error instanceof Error ? error.message : "Unknown error");
    return NextResponse.json({ error: "Website creation could not be completed. Refresh the page, check the database connection, and try again." }, { status: 500 });
  }
}
