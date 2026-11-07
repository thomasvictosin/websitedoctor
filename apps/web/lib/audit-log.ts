import { Prisma } from "@prisma/client";
import { db } from "@/lib/db";
import { requestSourceHash } from "@/lib/rate-limit";

export async function writeAuditLog(input: {
  action: string;
  actorType: "admin" | "wordpress_agent" | "system";
  actorId?: string;
  actorUserId?: string;
  organizationId?: string;
  resourceType?: string;
  resourceId?: string;
  request?: Request;
  details?: Prisma.InputJsonObject;
}) {
  return db.auditLog.create({
    data: {
      action: input.action,
      actorType: input.actorType,
      actorId: input.actorId,
      actorUserId: input.actorUserId,
      organizationId: input.organizationId,
      resourceType: input.resourceType,
      resourceId: input.resourceId,
      sourceHash: input.request ? requestSourceHash(input.request) : undefined,
      details: input.details,
    },
  });
}
