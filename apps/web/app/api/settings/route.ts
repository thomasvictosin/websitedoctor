import { NextResponse } from "next/server";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { ownedWebsiteWhere } from "@/lib/ownership";

export const runtime = "nodejs";

export async function GET() {
  const authorization = await authorizeOwnerRequest();
  if ("response" in authorization) return authorization.response;
  const websiteCount = await db.website.count({ where: ownedWebsiteWhere(authorization.ownerId) });
  const aiProvider = process.env.AI_PROVIDER ?? "ollama";
  return NextResponse.json({
    aiProvider,
    aiConfigured: aiProvider === "ollama"
      && Boolean(process.env.OLLAMA_MODEL ?? "qwen2.5:3b")
      && Boolean(process.env.OLLAMA_BASE_URL ?? "http://localhost:11434"),
    scheduledMonitoring: true,
    websiteCount,
    authentication: "organization_memberships",
  }, { headers: { "cache-control": "no-store" } });
}
