import { createHash } from "node:crypto";
import { NextResponse } from "next/server";
import { Prisma } from "@prisma/client";
import { db } from "@/lib/db";
export { requestSourceKey, requestSourceHash } from "@/lib/request-source";

const globalForCleanup = globalThis as typeof globalThis & { rateLimitCleanupAt?: number };

export async function enforceRateLimit(input: {
  namespace: string;
  subject: string;
  limit: number;
  windowMs: number;
}): Promise<NextResponse | null> {
  const key = createHash("sha256").update(`${input.namespace}:${input.subject}`).digest("hex");
  const now = new Date();
  const resetAt = new Date(now.getTime() + input.windowMs);
  const [bucket] = await db.$queryRaw<Array<{ count: number; resetAt: Date }>>(Prisma.sql`
    INSERT INTO "RateLimitBucket" ("key", "count", "resetAt", "updatedAt")
    VALUES (${key}, 1, ${resetAt}, ${now})
    ON CONFLICT ("key") DO UPDATE SET
      "count" = CASE
        WHEN "RateLimitBucket"."resetAt" <= ${now} THEN 1
        ELSE "RateLimitBucket"."count" + 1
      END,
      "resetAt" = CASE
        WHEN "RateLimitBucket"."resetAt" <= ${now} THEN EXCLUDED."resetAt"
        ELSE "RateLimitBucket"."resetAt"
      END,
      "updatedAt" = ${now}
    RETURNING "count", "resetAt"
  `);
  if (!bucket) throw new Error("Rate limiter did not return its updated bucket.");

  const currentTime = Date.now();
  if (!globalForCleanup.rateLimitCleanupAt || currentTime - globalForCleanup.rateLimitCleanupAt > 60_000) {
    globalForCleanup.rateLimitCleanupAt = currentTime;
    await db.rateLimitBucket.deleteMany({ where: { resetAt: { lt: new Date(currentTime - 86_400_000) } } });
  }

  if (bucket.count <= input.limit) return null;
  const retryAfter = Math.max(1, Math.ceil((bucket.resetAt.getTime() - currentTime) / 1000));
  return NextResponse.json(
    { error: "Too many requests. Please wait before trying again." },
    { status: 429, headers: { "retry-after": String(retryAfter), "cache-control": "no-store" } },
  );
}
