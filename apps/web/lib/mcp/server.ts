import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { db } from "@/lib/db";
import { getDefaultOrganizationId } from "@/lib/ownership";
import { runAsPrincipal, type RequestPrincipal } from "@/lib/request-principal";
const listSitesRoute = () => import("@/app/api/sites/route").then((module) => module.GET);
const listIssuesRoute = () => import("@/app/api/issues/route").then((module) => module.GET);
const updateIssueRoute = () => import("@/app/api/issues/[issueId]/route").then((module) => module.PATCH);
const diagnoseIssueRoute = () => import("@/app/api/issues/[issueId]/diagnose/route").then((module) => module.POST);
const recommendRoute = () => import("@/app/api/issues/[issueId]/recommend/route").then((module) => module.GET);
const proposeRepairRoute = () => import("@/app/api/issues/[issueId]/repairs/route").then((module) => module.POST);
const decideRepairRoute = () => import("@/app/api/repairs/[repairId]/route").then((module) => module.PATCH);
const runScanRoute = () => import("@/app/api/sites/[siteId]/check/route").then((module) => module.POST);
const scanStatusRoute = () => import("@/app/api/sites/[siteId]/scans/[scanId]/route").then((module) => module.GET);
const securityCheckRoute = () => import("@/app/api/sites/[siteId]/security-check/route").then((module) => module.POST);
const cleanupGetRoute = () => import("@/app/api/sites/[siteId]/cleanup/route").then((module) => module.GET);
const cleanupPostRoute = () => import("@/app/api/sites/[siteId]/cleanup/route").then((module) => module.POST);
const fixIssueRoute = () => import("@/app/api/issues/[issueId]/fix/route").then((module) => module.POST);
const protectionGetRoute = () => import("@/app/api/sites/[siteId]/protection/route").then((module) => module.GET);
const protectionPutRoute = () => import("@/app/api/sites/[siteId]/protection/route").then((module) => module.PUT);
const protectionPostRoute = () => import("@/app/api/sites/[siteId]/protection/route").then((module) => module.POST);
const cloudflareGetRoute = () => import("@/app/api/sites/[siteId]/cloudflare/route").then((module) => module.GET);
const cloudflarePostRoute = () => import("@/app/api/sites/[siteId]/cloudflare/route").then((module) => module.POST);
const historyRoute = () => import("@/app/api/sites/[siteId]/history/route").then((module) => module.GET);
const repairPolicyRoute = () => import("@/app/api/sites/[siteId]/repair-authorization/route").then((module) => module.GET);

// The executor must have checked in within this window before the central app
// will queue a repair (mirrors app/api/repairs/[repairId]/route.ts).
const EXECUTOR_FRESH_MS = 15 * 60_000;
const MAX_TOOL_OUTPUT_CHARS = 60_000;

const INSTRUCTIONS = `AI Website Doctor: diagnose and repair the WordPress websites registered in this organization.

How the system works:
- The central app stores websites, availability checks, issues, evidence, diagnoses, and repair proposals.
- Each website's WordPress plugin syncs diagnostics (plugins, theme, PHP errors, WP-Cron, settings, detected issues) to the central app about every 5 minutes. get_wordpress_diagnostics returns that data and how fresh it is. Plugin 0.2.0+ also sends an "integrity" report: core files that differ from WordPress.org checksums, unknown PHP files in core directories and uploads, malware code-pattern matches, injected .htaccess rules, a physical robots.txt, and recently created administrators.
- run_security_check fetches the site as a browser, as Googlebot, and as a visitor from Google search, and inspects robots.txt and the sitemap. It detects cloaking (crawlers get a different page), search-referrer redirects, blank 200 pages, and injected spam sitemaps, which an availability check reports as "up". It runs immediately and works on every deployment.
- A compromised site's own plugin can be tampered with; prefer run_security_check evidence (gathered from outside the site) when judging whether a cleanup worked.
- You cannot connect to WordPress directly. Repairs reach the plugin only through the central app: propose_repair creates an evidence-backed proposal, and apply_repair approves and queues it. The plugin executes it on its next poll (WP-Cron, traffic-triggered, typically within 5 minutes), records an operation-specific recovery point first, and the central app verifies the result and rolls back on failure.
- Only allowlisted operations can execute: disable_plugin, switch_theme, update_setting (blogname/blogdescription), replace_post_link, add_scoped_css_rule (staging only). Everything else gets manual guidance. You cannot run code, SQL, shell, or edit arbitrary files.
- Hacked sites have a separate compromise cleanup playbook (plugin 0.3.0+): get_cleanup_plan builds an ordered list from the integrity scan and outside check (quarantine malicious/unknown files, restore modified core files from WordPress.org, remove injected .htaccess rules, optionally remove risky plugins or demote unknown admins, rotate salts, purge cache). start_cleanup approves exactly the reviewed plan (bound by planDigest) in one step. The plugin runs it on its next poll, keeps everything it changes in a private quarantine, rescans, and the app verifies from outside. A failed verification keeps the changes and lists what remains. purge_quarantine permanently deletes a verified run's quarantine.
- One-click maintenance (plugin 0.4.0+): fix_issue applies a finding's single fix (update a plugin with an available update, or reinstall a WordPress.org plugin whose code differs from the official checksums); update_plugins updates all WordPress.org plugins with updates. Packages come only from WordPress.org, every file is checked against official checksums, and the previous version is put back automatically if the update fails or breaks the site. Premium plugins (not on WordPress.org) must be updated from their vendor.
- Protection (plugin 0.5.0+): get_protection shows each hardening measure (block PHP in uploads, protect sensitive files, code editor off, XML-RPC off, hide usernames, security headers, fake-crawler/attack-tool filter) with whether it is verified effective on the server, the self-healing and automatic-update settings, and recent alerts. apply_protection turns measures on/off through the plugin; set_protection switches self-healing (automatic safe cleanup of new malware files, max 3/day) and daily verified plugin updates. No setting makes a site unhackable; say so if asked.
- Cloudflare edge protection: get_cloudflare_status shows whether the site's Cloudflare zone is connected and traffic is proxied; apply_cloudflare_protection adds the app's rules (PHP in uploads, sensitive files, fake crawlers on login/admin, attack tools, login challenge and rate limit) and keeps the owner's own rules. The owner connects a Cloudflare API token in the dashboard's Protection tab; tokens are never accepted through MCP.

Recommended workflow:
1. list_websites, then list_issues for the site. When asked about a site's health or security, also run_security_check: a 200 response does not mean the site is healthy.
2. get_issue and get_wordpress_diagnostics to read the evidence. Reason from the recorded evidence only; say when evidence is missing.
3. Optionally diagnose_issue (deterministic rules) and get_recommendation.
4. propose_repair. If the proposal has no executable operation, give the user its manual guidance instead.
5. Only after the user agrees, apply_repair. Then follow get_repair_status until it reaches verified, rolled_back, failed, or rollback_required. Never report a fix as done before status is "verified".`;

type RouteHandler<P> = (request: Request, context: { params: Promise<P> }) => Promise<Response | undefined>;
// Route handlers are loaded lazily, per tool call: a static import of every
// route would make one route's heavy dependency (the scan route pulls in
// Playwright, which is not bundled on Vercel) break the whole MCP endpoint.
type RouteLoader<P> = () => Promise<RouteHandler<P>>;

type Json = Record<string, unknown>;

function asRecord(value: unknown): Json {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Json : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function text(value: unknown, isError = false) {
  let body = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  if (body.length > MAX_TOOL_OUTPUT_CHARS) {
    body = `${body.slice(0, MAX_TOOL_OUTPUT_CHARS)}\n… [truncated ${body.length - MAX_TOOL_OUTPUT_CHARS} characters; request a narrower result]`;
  }
  return { content: [{ type: "text" as const, text: body }], ...(isError ? { isError: true } : {}) };
}

export function createWebsiteDoctorMcpServer(principal: RequestPrincipal, origin: string) {
  const server = new McpServer({ name: "ai-website-doctor", version: "0.1.0" }, { instructions: INSTRUCTIONS });

  /** Invokes an existing route handler as the token's user, so every app safety check applies. */
  async function callRoute<P extends Record<string, string>>(load: RouteLoader<P>, path: string, options: { method?: string; body?: unknown; params?: P; headers?: Record<string, string> } = {}) {
    const request = new Request(new URL(path, origin), {
      method: options.method ?? "GET",
      headers: { ...(options.body === undefined ? {} : { "content-type": "application/json" }), ...(options.headers ?? {}) },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
    let handler: RouteHandler<P>;
    try {
      handler = await load();
    } catch (error) {
      console.error(`MCP route for ${path} could not be loaded`, error instanceof Error ? error.message : "Unknown error");
      return { ok: false, status: 503, data: { error: "This capability is not available on this deployment (its server module could not be loaded)." } };
    }
    const response = await runAsPrincipal(principal, () => handler(request, { params: Promise.resolve((options.params ?? {}) as P) }));
    if (!response) return { ok: false, status: 500, data: { error: "The route returned no response." } };
    const raw = await response.text();
    let data: unknown = raw;
    try { data = raw ? JSON.parse(raw) : null; } catch { data = raw; }
    return { ok: response.ok, status: response.status, data };
  }

  function failure(result: { status: number; data: unknown }) {
    const message = typeof asRecord(result.data).error === "string" ? asRecord(result.data).error : result.data;
    return text({ error: message, httpStatus: result.status }, true);
  }

  let organizationId: string | null | undefined;
  async function audit(tool: string, args: Json, outcome: string) {
    try {
      if (organizationId === undefined) {
        try { organizationId = await getDefaultOrganizationId(principal.userId); } catch { organizationId = null; }
      }
      await db.auditLog.create({
        data: {
          action: "mcp_tool_called", actorType: "mcp", actorId: principal.tokenId, actorUserId: principal.userId,
          organizationId, resourceType: "mcp_tool", resourceId: tool, details: { arguments: args, outcome } as never,
        },
      });
    } catch (error) {
      console.error("MCP audit log failed", error instanceof Error ? error.message : "Unknown error");
    }
  }

  function tool<Shape extends z.ZodRawShape>(
    name: string,
    config: { title: string; description: string; inputSchema: Shape; annotations: { readOnlyHint: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean } },
    run: (args: z.infer<z.ZodObject<Shape>>) => Promise<ReturnType<typeof text>>,
  ) {
    server.registerTool(name, config, (async (args: z.infer<z.ZodObject<Shape>>) => {
      let result: ReturnType<typeof text>;
      try {
        result = await run(args);
      } catch (error) {
        console.error(`MCP tool ${name} failed`, error instanceof Error ? error.message : "Unknown error");
        result = text({ error: "The tool failed on the server. Check the app logs and the database connection." }, true);
      }
      await audit(name, args as Json, result.isError ? "error" : "ok");
      return result;
    }) as never);
  }

  async function loadSites() {
    const result = await callRoute(listSitesRoute, "/api/sites");
    return { result, sites: asArray(result.data).map(asRecord) };
  }

  async function loadIssues() {
    const result = await callRoute(listIssuesRoute, "/api/issues");
    return { result, issues: asArray(result.data).map(asRecord) };
  }

  function pluginSummary(site: Json) {
    const agent = asRecord(site.wordpressAgent);
    if (!site.wordpressAgent) return { connected: false, note: "No WordPress plugin is paired with this website." };
    const lastSeen = typeof agent.lastSeenAt === "string" ? Date.parse(agent.lastSeenAt) : NaN;
    const ageMs = Number.isFinite(lastSeen) ? Date.now() - lastSeen : null;
    return {
      connected: !agent.revokedAt,
      revoked: Boolean(agent.revokedAt),
      agentId: agent.id,
      siteName: agent.siteName,
      wordpressVersion: agent.wpVersion,
      phpVersion: agent.phpVersion,
      pluginVersion: agent.pluginVersion,
      lastSyncAt: agent.lastSeenAt,
      minutesSinceLastSync: ageMs === null ? null : Math.round(ageMs / 60_000),
      canQueueRepairs: !agent.revokedAt && ageMs !== null && ageMs < EXECUTOR_FRESH_MS,
      recentExecutions: asArray(agent.executions),
    };
  }

  function repairSummary(repair: Json) {
    const proposal = asRecord(repair.proposal);
    return {
      repairId: repair.id,
      status: repair.status,
      risk: repair.risk,
      operations: repair.operationIds,
      executable: asArray(repair.operationIds).length > 0 && proposal.executionAvailable === true,
      approvalStatus: repair.approvalStatus,
      executionStatus: repair.executionStatus,
      verificationStatus: repair.verificationStatus,
      rollbackStatus: repair.rollbackStatus,
    };
  }

  tool("list_websites", {
    title: "List websites",
    description: "List the organization's websites with their latest availability check, issue count, and WordPress plugin connection (versions, last sync, and whether repairs can be queued).",
    inputSchema: {},
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async () => {
    const { result, sites } = await loadSites();
    if (!result.ok) return failure(result);
    return text(sites.map((site) => ({
      siteId: site.id,
      name: site.name,
      url: site.url,
      environment: site.environmentType,
      scheduledMonitoring: site.monitoringEnabled,
      totalIssues: asRecord(site._count).issues,
      latestCheck: asArray(site.checks)[0] ?? null,
      wordpressPlugin: pluginSummary(site),
    })));
  });

  tool("get_wordpress_diagnostics", {
    title: "Get WordPress plugin diagnostics",
    description: "Return the latest diagnostics the site's WordPress plugin synced to the central app: WordPress/PHP versions, active theme, plugin inventory and available updates, PHP errors and fatal errors, WP-Cron history, settings, editable pages, and plugin-detected issues. Includes sync freshness.",
    inputSchema: { siteId: z.string().min(1).max(64).describe("Website ID from list_websites.") },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async ({ siteId }) => {
    const { result, sites } = await loadSites();
    if (!result.ok) return failure(result);
    const site = sites.find((item) => item.id === siteId);
    if (!site) return text({ error: "Website not found in your organization." }, true);
    return text({ siteId, name: site.name, url: site.url, plugin: pluginSummary(site), diagnostics: asRecord(site.wordpressAgent).diagnostics ?? null });
  });

  tool("list_issues", {
    title: "List issues",
    description: "List recorded issues (from the plugin, availability checks, and browser scans) with severity, status, and repair state. Filter by website and status.",
    inputSchema: {
      siteId: z.string().min(1).max(64).optional().describe("Only issues for this website."),
      status: z.enum(["active", "open", "acknowledged", "resolved", "all"]).default("active").describe("'active' means open or acknowledged."),
      limit: z.number().int().min(1).max(200).default(50),
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async ({ siteId, status, limit }) => {
    const { result, issues } = await loadIssues();
    if (!result.ok) return failure(result);
    const rows = issues
      .filter((issue) => !siteId || asRecord(issue.website).id === siteId)
      .filter((issue) => status === "all" || (status === "active" ? issue.status !== "resolved" : issue.status === status));
    return text({
      total: rows.length,
      issues: rows.slice(0, limit).map((issue) => ({
        issueId: issue.id,
        title: issue.title,
        severity: issue.severity,
        status: issue.status,
        source: issue.source,
        fingerprint: issue.fingerprint,
        website: issue.website,
        lastSeenAt: issue.lastSeenAt,
        diagnosed: Boolean(asRecord(issue.diagnosis).diagnosis),
        repairs: asArray(issue.repairs).map((repair) => repairSummary(asRecord(repair))),
      })),
    });
  });

  tool("get_issue", {
    title: "Get issue details",
    description: "Return one issue with its full recorded evidence, stored diagnosis, and every repair proposal with lifecycle events, approvals, executions, and verification results.",
    inputSchema: { issueId: z.string().min(1).max(64) },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async ({ issueId }) => {
    const { result, issues } = await loadIssues();
    if (!result.ok) return failure(result);
    const issue = issues.find((item) => item.id === issueId);
    return issue ? text(issue) : text({ error: "Issue not found in your organization." }, true);
  });

  tool("diagnose_issue", {
    title: "Store a diagnosis",
    description: "Run the central app's diagnosis for an issue and store it on the issue. withAi=false (default) uses deterministic evidence rules. withAi=true calls the app's configured local AI provider, which is often unreachable from the hosted app; it then falls back to the deterministic diagnosis and reports aiStatus 'unavailable'.",
    inputSchema: { issueId: z.string().min(1).max(64), withAi: z.boolean().default(false) },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async ({ issueId, withAi }) => {
    const result = await callRoute(diagnoseIssueRoute, `/api/issues/${encodeURIComponent(issueId)}/diagnose`, { method: "POST", body: { withAi }, params: { issueId } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("get_recommendation", {
    title: "Get repair recommendation",
    description: "Return the deterministic, evidence-based recommendation for an issue: whether a supported allowlisted operation exists, its risk, the proposed change or manual steps, and the verification plan. Does not change anything.",
    inputSchema: { issueId: z.string().min(1).max(64) },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async ({ issueId }) => {
    const result = await callRoute(recommendRoute, `/api/issues/${encodeURIComponent(issueId)}/recommend`, { params: { issueId } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("get_check_history", {
    title: "Get availability check history",
    description: "Return up to 100 recent central HTTP availability checks for a website (status code, response time, error).",
    inputSchema: { siteId: z.string().min(1).max(64) },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async ({ siteId }) => {
    const result = await callRoute(historyRoute, `/api/sites/${encodeURIComponent(siteId)}/history`, { params: { siteId } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("run_scan", {
    title: "Queue a website scan",
    description: "Queue a central availability and browser scan for a website (limit: 2 active and 6 per 15 minutes per organization). Returns a scanId to pass to get_scan_status. On the hosted (Vercel) deployment there is no persistent background worker, so a scan can stay queued or fail; the plugin's diagnostics sync remains the reliable WordPress evidence.",
    inputSchema: { siteId: z.string().min(1).max(64) },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  }, async ({ siteId }) => {
    const result = await callRoute(runScanRoute, `/api/sites/${encodeURIComponent(siteId)}/check`, { method: "POST", params: { siteId } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("run_security_check", {
    title: "Run a compromise (security) check now",
    description: "Fetch the website as a regular browser, as Googlebot, and as a visitor arriving from Google search, then inspect robots.txt and the sitemap. Detects cloaking (search engines shown different content), conditional redirects, blank 200 home pages, and machine-generated spam sitemaps. Findings are stored as issues (source security_probe) and earlier ones are resolved when no longer observed. Runs synchronously (about 10–30 seconds); needs no background worker or browser runtime.",
    inputSchema: { siteId: z.string().min(1).max(64) },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  }, async ({ siteId }) => {
    const result = await callRoute(securityCheckRoute, `/api/sites/${encodeURIComponent(siteId)}/security-check`, { method: "POST", params: { siteId } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("get_cleanup_plan", {
    title: "Get the compromise cleanup plan",
    description: "Build the cleanup playbook for a hacked site from its latest integrity scan and security findings: the ordered steps that will run, optional items (risky plugins, recently created administrators) that run only if included, manual follow-ups, warnings, blockers (for example an outdated plugin or a stale scan), recent cleanup runs with their verification, and the planDigest to pass to start_cleanup. Read-only.",
    inputSchema: { siteId: z.string().min(1).max(64) },
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async ({ siteId }) => {
    const result = await callRoute(cleanupGetRoute, `/api/sites/${encodeURIComponent(siteId)}/cleanup`, { params: { siteId } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("start_cleanup", {
    title: "Approve and queue the compromise cleanup",
    description: "Approve the cleanup plan exactly as returned by get_cleanup_plan and queue it for the site's plugin. This changes files and settings on the live site (quarantines files, restores core files, edits .htaccess and wp-config.php salts, which signs everyone out). Show the user the full step list and get their explicit agreement first. Fails if the plan changed since planDigest was read. include lists optional item ids the user chose. Afterwards follow get_repair_status with the returned repairId until verified or failed.",
    inputSchema: {
      siteId: z.string().min(1).max(64),
      planDigest: z.string().regex(/^[a-f0-9]{64}$/),
      include: z.array(z.string().max(120)).max(60).default([]).describe("Optional item ids from the plan to include."),
      confirm: z.literal(true).describe("Must be true: the user explicitly approved this cleanup."),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, async ({ siteId, planDigest, include, confirm }) => {
    const result = await callRoute(cleanupPostRoute, `/api/sites/${encodeURIComponent(siteId)}/cleanup`, { method: "POST", body: { action: "start", planDigest, include, confirm }, params: { siteId }, headers: { "x-awd-interface": "mcp" } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("purge_quarantine", {
    title: "Permanently delete a verified cleanup's quarantine",
    description: "Queue permanent deletion of the files a verified cleanup run quarantined. After this the run can no longer be restored. Only allowed for runs with status verified. Ask the user first.",
    inputSchema: { siteId: z.string().min(1).max(64), repairId: z.string().min(1).max(64), confirm: z.literal(true) },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, async ({ siteId, repairId, confirm }) => {
    const result = await callRoute(cleanupPostRoute, `/api/sites/${encodeURIComponent(siteId)}/cleanup`, { method: "POST", body: { action: "purge", repairId, confirm }, params: { siteId }, headers: { "x-awd-interface": "mcp" } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("fix_issue", {
    title: "Apply a finding's one-click fix",
    description: "Approve and queue the one-click fix for an issue: 'Plugin update available' findings update that WordPress.org plugin to the available version; 'Plugin code differs from the official release' findings reinstall it. Changes the live site; ask the user first. Compromise (security/integrity) findings are fixed together with start_cleanup instead. Follow get_repair_status with the returned repairId.",
    inputSchema: { issueId: z.string().min(1).max(64), confirm: z.literal(true) },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, async ({ issueId, confirm }) => {
    const result = await callRoute(fixIssueRoute, `/api/issues/${encodeURIComponent(issueId)}/fix`, { method: "POST", body: { confirm }, params: { issueId }, headers: { "x-awd-interface": "mcp" } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("update_plugins", {
    title: "Update WordPress.org plugins",
    description: "Approve and queue updates for WordPress.org plugins with an available update (all of them, or only the listed plugin files, e.g. 'elementor/elementor.php'). Each update is verified against official checksums and rolled back automatically if it fails or breaks the site. The response lists plugins that cannot be updated this way (premium/vendor plugins). Changes the live site; ask the user first.",
    inputSchema: { siteId: z.string().min(1).max(64), plugins: z.array(z.string().max(200)).max(60).optional(), confirm: z.literal(true) },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, async ({ siteId, plugins, confirm }) => {
    const result = await callRoute(cleanupPostRoute, `/api/sites/${encodeURIComponent(siteId)}/cleanup`, { method: "POST", body: { action: "update_plugins", ...(plugins ? { plugins } : {}), confirm }, params: { siteId }, headers: { "x-awd-interface": "mcp" } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("get_protection", {
    title: "Get site protection status",
    description: "Return the site's hardening measures (on/off and whether verified effective on this server), self-healing and automatic-update settings, and alerts from the last 7 days.",
    inputSchema: { siteId: z.string().min(1).max(64) },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async ({ siteId }) => {
    const result = await callRoute(protectionGetRoute, `/api/sites/${encodeURIComponent(siteId)}/protection`, { params: { siteId } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("apply_protection", {
    title: "Turn protection measures on or off",
    description: "Queue a hardening change through the site's plugin: either one measure (measure + state) or recommended: true to turn on every recommended measure that is off. Measures: block_php_uploads, protect_sensitive_files, disable_file_editor, disable_xmlrpc, block_user_enumeration, security_headers, verified_crawlers. .htaccess rules are tested on the server and removed again if they break the site. Ask the user first.",
    inputSchema: {
      siteId: z.string().min(1).max(64),
      measure: z.enum(["block_php_uploads", "protect_sensitive_files", "disable_file_editor", "disable_xmlrpc", "block_user_enumeration", "security_headers", "verified_crawlers"]).optional(),
      state: z.enum(["on", "off"]).optional(),
      recommended: z.boolean().optional(),
      confirm: z.literal(true),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, async ({ siteId, measure, state, recommended, confirm }) => {
    const body = recommended ? { recommended: true, confirm } : { measure, state, confirm };
    if (!recommended && (!measure || !state)) return text({ error: "Pass measure and state, or recommended: true." }, true);
    const result = await callRoute(protectionPostRoute, `/api/sites/${encodeURIComponent(siteId)}/protection`, { method: "POST", body, params: { siteId }, headers: { "x-awd-interface": "mcp" } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("set_protection", {
    title: "Switch self-healing or automatic updates",
    description: "Turn self-healing (automatic safe cleanup when new malware files appear, at most 3 runs a day, then an alert) and/or automatic daily verified WordPress.org plugin updates on or off for a site. Ask the user first.",
    inputSchema: { siteId: z.string().min(1).max(64), selfHealing: z.boolean().optional(), autoUpdates: z.boolean().optional() },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async ({ siteId, selfHealing, autoUpdates }) => {
    const result = await callRoute(protectionPutRoute, `/api/sites/${encodeURIComponent(siteId)}/protection`, { method: "PUT", body: { ...(selfHealing === undefined ? {} : { selfHealing }), ...(autoUpdates === undefined ? {} : { autoUpdates }) }, params: { siteId } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("get_cloudflare_status", {
    title: "Get Cloudflare edge protection status",
    description: "Return whether the site is connected to a Cloudflare zone, whether its traffic actually passes through Cloudflare, the app's firewall and rate-limit rules, Bot Fight Mode, and the last verification. The API token is never returned.",
    inputSchema: { siteId: z.string().min(1).max(64) },
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async ({ siteId }) => {
    const result = await callRoute(cloudflareGetRoute, `/api/sites/${encodeURIComponent(siteId)}/cloudflare`, { params: { siteId } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("apply_cloudflare_protection", {
    title: "Apply or remove Cloudflare edge protection",
    description: "Apply the app's Cloudflare protection to a connected site (security level medium, HTTPS only, TLS 1.2+, browser integrity check, one block rule, a login challenge and a login rate limit; the owner's other rules are kept), or remove the app's rules. botFightMode also challenges automated traffic site-wide but makes the app's outside cloaking check inconclusive. Ask the user first.",
    inputSchema: { siteId: z.string().min(1).max(64), remove: z.boolean().default(false), botFightMode: z.boolean().default(false), confirm: z.literal(true) },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  }, async ({ siteId, remove, botFightMode, confirm }) => {
    const result = await callRoute(cloudflarePostRoute, `/api/sites/${encodeURIComponent(siteId)}/cloudflare`, { method: "POST", body: remove ? { action: "remove", confirm } : { action: "apply", botFightMode, confirm }, params: { siteId } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("get_scan_status", {
    title: "Get scan status",
    description: "Return the status and results of a scan queued with run_scan.",
    inputSchema: { siteId: z.string().min(1).max(64), scanId: z.string().min(1).max(64) },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async ({ siteId, scanId }) => {
    const result = await callRoute(scanStatusRoute, `/api/sites/${encodeURIComponent(siteId)}/scans/${encodeURIComponent(scanId)}`, { params: { siteId, scanId } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("get_repair_policy", {
    title: "Get repair permissions",
    description: "Return the website's standing repair authorization policy (manual or automatic mode, allowed operations, risk ceiling, paused). Read-only: this server cannot change standing permissions.",
    inputSchema: { siteId: z.string().min(1).max(64) },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async ({ siteId }) => {
    const result = await callRoute(repairPolicyRoute, `/api/sites/${encodeURIComponent(siteId)}/repair-authorization`, { params: { siteId } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("propose_repair", {
    title: "Create a repair proposal",
    description: "Create an evidence-backed repair proposal for an issue. The app emits an executable step only when the evidence maps to exactly one allowlisted operation; otherwise the proposal contains manual guidance only. Creating a proposal does not change the website. For a confirmed broken-link (404/410) finding, pass replacementUrl: a reachable, clean same-origin URL the user chose.",
    inputSchema: {
      issueId: z.string().min(1).max(64),
      replacementUrl: z.string().url().max(2000).optional().describe("Only for browser broken-link findings."),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  }, async ({ issueId, replacementUrl }) => {
    const result = await callRoute(proposeRepairRoute, `/api/issues/${encodeURIComponent(issueId)}/repairs`, { method: "POST", body: replacementUrl ? { replacementUrl } : {}, params: { issueId } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("apply_repair", {
    title: "Approve and apply a repair",
    description: "Approve a pending, executable repair proposal and queue it for the site's WordPress plugin. The plugin applies it on its next poll (usually within about 5 minutes), saves a recovery point first, and the central app verifies the result and rolls back on failure. Requires owner/admin role, a plugin that synced within 15 minutes, and no overlapping active repair. Ask the user before calling this. Afterwards, follow get_repair_status.",
    inputSchema: { repairId: z.string().min(1).max(64) },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, async ({ repairId }) => {
    const result = await callRoute(decideRepairRoute, `/api/repairs/${encodeURIComponent(repairId)}`, { method: "PATCH", body: { decision: "approve_and_apply" }, params: { repairId } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("decide_repair", {
    title: "Approve or reject without applying",
    description: "Record a decision on a pending repair proposal without queuing execution. 'approve' records central approval (for a manual-guidance plan it acknowledges the plan; a WordPress admin can then apply executable ones from the plugin). 'reject' closes the proposal.",
    inputSchema: { repairId: z.string().min(1).max(64), decision: z.enum(["approve", "reject"]) },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  }, async ({ repairId, decision }) => {
    const result = await callRoute(decideRepairRoute, `/api/repairs/${encodeURIComponent(repairId)}`, { method: "PATCH", body: { decision }, params: { repairId } });
    return result.ok ? text(result.data) : failure(result);
  });

  tool("get_repair_status", {
    title: "Get repair status",
    description: "Return a repair's current status, lifecycle events, executions, and verification results. Terminal statuses: verified, rolled_back, failed, verification_failed, inconclusive, rollback_required, rejected.",
    inputSchema: { repairId: z.string().min(1).max(64) },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async ({ repairId }) => {
    const { result, issues } = await loadIssues();
    if (!result.ok) return failure(result);
    for (const issue of issues) {
      const repair = asArray(issue.repairs).map(asRecord).find((item) => item.id === repairId);
      if (repair) return text({ issue: { issueId: issue.id, title: issue.title, status: issue.status, website: issue.website }, ...repairSummary(repair), proposal: repair.proposal, events: repair.events, executions: repair.executions, verificationResults: repair.verificationResults });
    }
    // Cleanup runs can exist without an anchor issue.
    const unanchored = await db.repairProposal.findFirst({
      where: { id: repairId, issueId: null, website: { organization: { members: { some: { userId: principal.userId } } } } },
      include: { website: { select: { id: true, name: true, url: true } }, events: { orderBy: { createdAt: "asc" } }, executions: { orderBy: { createdAt: "asc" } }, verificationResults: { orderBy: { createdAt: "asc" } } },
    });
    if (unanchored) return text({ issue: null, website: unanchored.website, ...repairSummary(unanchored as unknown as Json), proposal: unanchored.proposal, events: unanchored.events, executions: unanchored.executions, verificationResults: unanchored.verificationResults });
    return text({ error: "Repair not found in your organization." }, true);
  });

  tool("update_issue_status", {
    title: "Update issue status",
    description: "Mark an issue acknowledged or resolved, or reopen it. Use 'resolved' only when the evidence shows the problem is gone; this does not change the website.",
    inputSchema: { issueId: z.string().min(1).max(64), status: z.enum(["open", "acknowledged", "resolved"]) },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async ({ issueId, status }) => {
    const result = await callRoute(updateIssueRoute, `/api/issues/${encodeURIComponent(issueId)}`, { method: "PATCH", body: { status }, params: { issueId } });
    return result.ok ? text(result.data) : failure(result);
  });

  return server;
}
