import type { Prisma } from "@prisma/client";

export function ownedWebsiteWhere(ownerId: string, websiteId?: string): Prisma.WebsiteWhereInput {
  return {
    organization: { members: { some: { userId: ownerId } } },
    ...(websiteId ? { id: websiteId } : {}),
  };
}

export function ownedIssueWhere(ownerId: string, issueId?: string): Prisma.IssueWhereInput {
  return {
    ...(issueId ? { id: issueId } : {}),
    website: { organization: { members: { some: { userId: ownerId } } } },
  };
}

export function ownedRepairWhere(ownerId: string, repairId?: string): Prisma.RepairProposalWhereInput {
  return {
    ...(repairId ? { id: repairId } : {}),
    website: { organization: { members: { some: { userId: ownerId } } } },
  };
}
