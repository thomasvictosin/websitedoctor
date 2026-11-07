import "dotenv/config";
import { defineConfig, env } from "prisma/config";

export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: { path: "prisma/migrations" },
  // Use a direct database connection for Prisma CLI schema operations when
  // configured; the application can use Supabase's session pooler URL.
  datasource: { url: process.env.DIRECT_URL || env("DATABASE_URL") },
});
