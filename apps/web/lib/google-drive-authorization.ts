import { db } from "./db";
import { ownedWebsiteWhere } from "./ownership";

export async function findAdminWebsite(userId: string, websiteId: string) {
  const website = await db.website.findFirst({
    where: ownedWebsiteWhere(userId, websiteId),
    select: { id: true, name: true, organizationId: true },
  });
  if (!website) return null;
  const membership = await db.organizationMember.findFirst({
    where: { userId, organizationId: website.organizationId, role: { in: ["owner", "admin"] } },
    select: { role: true },
  });
  return membership ? website : null;
}
