import "dotenv/config";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@prisma/client";

const connectionString = process.env.DATABASE_URL;
if (!connectionString) throw new Error("DATABASE_URL must be set before initializing the database.");

const prisma = new PrismaClient({
  adapter: new PrismaPg({ connectionString }),
});

try {
  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "User" (
      "id" TEXT NOT NULL PRIMARY KEY,
      "email" TEXT NOT NULL UNIQUE,
      "name" TEXT NOT NULL,
      "role" TEXT NOT NULL DEFAULT 'admin',
      "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "updatedAt" TIMESTAMP(3) NOT NULL
    )
  `);
  await prisma.$executeRawUnsafe(
    `INSERT INTO "User" ("id", "email", "name", "role", "updatedAt")
     VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
     ON CONFLICT ("id") DO NOTHING`,
    "local-admin",
    "admin@localhost",
    "Local administrator",
    "admin",
  );
  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "Organization" (
      "id" TEXT NOT NULL PRIMARY KEY,
      "name" TEXT NOT NULL,
      "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "updatedAt" TIMESTAMP(3) NOT NULL
    )
  `);
  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "OrganizationMember" (
      "organizationId" TEXT NOT NULL REFERENCES "Organization"("id") ON DELETE CASCADE,
      "userId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE,
      "role" TEXT NOT NULL DEFAULT 'member',
      "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY ("organizationId", "userId")
    )
  `);
  await prisma.$executeRawUnsafe(
    `INSERT INTO "Organization" ("id", "name", "updatedAt")
     VALUES ($1, $2, CURRENT_TIMESTAMP)
     ON CONFLICT ("id") DO NOTHING`,
    "local-organization",
    "Personal workspace",
  );
  await prisma.$executeRawUnsafe(
    `INSERT INTO "OrganizationMember" ("organizationId", "userId", "role")
     VALUES ($1, $2, $3)
     ON CONFLICT ("organizationId", "userId") DO NOTHING`,
    "local-organization",
    "local-admin",
    "owner",
  );
} finally {
  await prisma.$disconnect();
}
