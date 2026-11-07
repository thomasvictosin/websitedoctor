import { db } from "@/lib/db";
export { ownedIssueWhere, ownedRepairWhere, ownedWebsiteWhere } from "./ownership-filters";

export async function getInitialAdminOwnerId(): Promise<string> {
  const owner = await db.user.upsert({
    where: { id: "local-admin" },
    create: {
      id: "local-admin",
      email: "admin@localhost",
      name: "Local administrator",
      role: "admin",
    },
    update: {},
    select: { id: true },
  });
  return owner.id;
}

export async function getDefaultOrganizationId(userId: string): Promise<string> {
  const membership = await db.organizationMember.findFirst({
    where: { userId },
    orderBy: { createdAt: "asc" },
    select: { organizationId: true },
  });
  if (!membership) throw new Error("The authenticated user has no organization membership.");
  return membership.organizationId;
}
