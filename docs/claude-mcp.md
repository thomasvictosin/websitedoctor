# Claude MCP access

The web app exposes a remote [Model Context Protocol](https://modelcontextprotocol.io) server at `/api/mcp`, so Claude Code or Claude Desktop can diagnose and repair the organization's websites.

Claude connects only to the central app. It reaches the WordPress plugin through the existing agent protocol: it reads the diagnostics the plugin syncs, and it queues approved repairs that the plugin executes on its next signed poll. The plugin still accepts no inbound connections, and no plugin change is needed.

## Connect

1. Sign in to the dashboard, open **Team → Claude MCP access**, and create a token. It is shown once. It acts as you, with your organization role.
2. Claude Code:

   ```sh
   claude mcp add --transport http website-doctor https://<your-app-origin>/api/mcp \
     --header "Authorization: Bearer awd_mcp_…"
   ```

3. Claude Desktop (requires Node.js): add this to `claude_desktop_config.json`, then restart.

   ```json
   {
     "mcpServers": {
       "website-doctor": {
         "command": "npx",
         "args": ["-y", "mcp-remote", "https://<your-app-origin>/api/mcp", "--header", "Authorization: Bearer awd_mcp_…"]
       }
     }
   }
   ```

claude.ai web connectors require OAuth, which this server does not implement yet.

## Tools

| Tool | Effect |
| --- | --- |
| `list_websites` | Websites, latest check, issue count, plugin connection and freshness |
| `get_wordpress_diagnostics` | Latest plugin-synced WordPress diagnostics |
| `list_issues`, `get_issue` | Issues with evidence, diagnosis, and repair history |
| `get_check_history`, `get_repair_policy`, `get_repair_status` | Read-only status |
| `get_recommendation` | Deterministic, evidence-based recommendation (no change) |
| `diagnose_issue` | Stores a deterministic (or local-AI) diagnosis on the issue |
| `run_scan`, `get_scan_status` | Queue and follow a central scan |
| `propose_repair` | Creates an evidence-backed proposal (no website change) |
| `apply_repair` | Approves and queues an executable proposal for the plugin (destructive) |
| `decide_repair` | Approves without queuing, or rejects |
| `update_issue_status` | Acknowledge, resolve, or reopen an issue |

Not exposed: deleting websites, members, standing repair permissions, hosting connections or credentials, Google Drive, and token management.

## Security model

- Tokens are random 256-bit secrets prefixed `awd_mcp_`. Only a SHA-256 hash is stored. Tokens can expire and can be revoked immediately, and disabled users' tokens stop working.
- Each tool call runs the existing API route handler as the token's user (`lib/request-principal.ts`, checked in `authorizeRequest`). Organization scoping, role checks, rate limits, the operation allowlist, recovery points, executor freshness, conflict locks, and central verification apply unchanged. The browser same-origin check is skipped only for token-authenticated calls, because browsers never attach bearer tokens automatically.
- Token management (`/api/mcp-tokens`) requires a browser session, so a token cannot mint tokens.
- `/api/mcp` is rate limited to 120 requests per minute per token. Every tool call is written to the audit log as `mcp_tool_called` with the token ID.
- Approval grants are single-use: the plugin receives a queued repair on exactly one poll.

## Limits

- The plugin polls about every 5 minutes through WP-Cron, which is traffic-triggered. A queued repair runs on that poll, and `apply_repair` requires a plugin sync within the last 15 minutes.
- On Vercel there is no persistent scan worker, so `run_scan` may stay queued or fail. Plugin diagnostics are the reliable live WordPress evidence there.
- `diagnose_issue` with `withAi: true` calls the app's configured local AI provider (Ollama), which the hosted app usually cannot reach. Claude does the reasoning over the evidence; the app's deterministic rules decide what is executable.

## Setup on an existing database

The token table is new. Apply it with `npx prisma db push` (from `apps/web`, with `DIRECT_URL`/`DATABASE_URL` pointing at the target database) before deploying. The change only adds the `McpAccessToken` table and does not alter existing tables.
