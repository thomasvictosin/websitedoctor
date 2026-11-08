import { NextResponse } from "next/server";
import { authenticateAgent } from "@/lib/agent-auth";
import { chunkForAgent } from "@/lib/packages";

export const runtime = "nodejs";

/** One piece of an approved package for the site that installs it (signed agent request). */
export async function GET(request: Request, { params }: { params: Promise<{ agentId: string; packageId: string; index: string }> }) {
  const { agentId, packageId, index } = await params;
  const auth = await authenticateAgent(request, agentId);
  if ("response" in auth) return auth.response;
  if (auth.agent.id !== agentId) return NextResponse.json({ error: "Agent identity mismatch." }, { status: 403 });
  const piece = /^\d{1,3}$/.test(index) ? await chunkForAgent(auth.agent.websiteId, packageId, Number(index)) : null;
  if (!piece) return NextResponse.json({ error: "Package piece not found." }, { status: 404 });
  return new NextResponse(Buffer.from(piece.data), { headers: { "content-type": "application/octet-stream", "x-awd-sha256": piece.sha256, "cache-control": "no-store" } });
}
