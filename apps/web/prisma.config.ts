import "dotenv/config";
import { defineConfig, env } from "prisma/config";

export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: { path: "prisma/migrations" },
  // Use a direct database connection for Prisma CLI schema operations when
  // configured; serverless runtime deployments should use transaction pooling.
  datasource: { url: process.env.DIRECT_URL || env("DATABASE_URL") },
});
