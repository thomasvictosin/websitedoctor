import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { NextResponse } from "next/server";
import { createWebsiteDoctorMcpServer } from "@/lib/mcp/server";
import { verifyMcpBearer } from "@/lib/mcp-tokens";
import { enforceRateLimit } from "@/lib/rate-limit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

// Remote MCP endpoint (Streamable HTTP, stateless) for Claude Code / Claude
// Desktop. Authenticate with `Authorization: Bearer awd_mcp_…` created in the
// dashboard's Team view. Each request gets a fresh server bound to that token's
// user; tools call the existing API route handlers as that user.
async function handle(request: Request): Promise<Response> {
  const verified = await verifyMcpBearer(request.headers.get("authorization"));
  if (!verified) {
    return NextResponse.json(
      { error: "A valid AI Website Doctor MCP token is required. Create one in the dashboard under Team → Claude MCP access." },
      { status: 401, headers: { "www-authenticate": 'Bearer realm="ai-website-doctor"', "cache-control": "no-store" } },
    );
  }
  const limited = await enforceRateLimit({ namespace: "mcp", subject: verified.tokenId, limit: 120, windowMs: 60_000 });
  if (limited) return limited;

  const origin = process.env.APP_ORIGIN ? new URL(process.env.APP_ORIGIN).origin : new URL(request.url).origin;
  const server = createWebsiteDoctorMcpServer({ userId: verified.userId, tokenId: verified.tokenId, via: "mcp_token" }, origin);
  const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  try {
    await server.connect(transport);
    const response = await transport.handleRequest(request);
    response.headers.set("cache-control", "no-store");
    return response;
  } finally {
    await server.close();
  }
}

export { handle as GET, handle as POST, handle as DELETE };
