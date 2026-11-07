# AI Website Doctor web application

The independent Next.js control panel and central intelligence/API service for this monorepo.

## Requirements and local setup

- Node.js 22.12+
- Docker Compose for local PostgreSQL
- Optional Ollama for local inference

From the monorepo root:

1. Copy `apps/web/.env.example` to `apps/web/.env`.
2. Generate a password verifier with `npm run auth:hash-password --workspace apps/web` and save the printed `ADMIN_PASSWORD_HASH` line in `.env`. The password is entered without terminal echo and is not stored in plaintext.
3. Set `SESSION_SECRET` to a private random secret of at least 32 bytes (for example, generate one with `openssl rand -base64 32`).
4. Start PostgreSQL: `docker compose up -d db`
5. Install dependencies: `npm install`
6. Install the Playwright Chromium runtime: `npm run browser:install --workspace apps/web`.
7. Generate the Prisma client and apply the schema: `npm run db:generate && npm run db:push`. `db:push` creates the initial administrator and personal organization, applies the schema, and migrates existing agent hashes into installation credentials.
8. Start the dashboard: `npm run dev`, then open [http://localhost:3000](http://localhost:3000).

## Supabase PostgreSQL

Supabase can replace the local PostgreSQL service without changing Prisma or the app data model. Keep Docker Compose for local development if useful; do not point a local development session at a production database.

1. Create a Supabase project and choose its region. Keep the database password private.
2. In the Supabase dashboard's **Connect** panel, choose the connection mode for the application host. For Vercel/serverless deployments, use the **Transaction pooler** URL on port `6543` for `DATABASE_URL`; add `pgbouncer=true` as Supabase's Prisma guide specifies. Serverless function instances open independent connection pools, so the session pooler's per-project client limit can be exhausted. For a persistent Node server, use a direct connection when its network supports it, or the **Session pooler** URL on port `5432`.
3. Copy the project's **Direct connection** URL into `DIRECT_URL` for Prisma CLI schema operations. Direct connectivity requires IPv6 or the project's IPv4 add-on; if unavailable from your network, use the session pooler URL for `DIRECT_URL`.
4. Put both values in the deployment environment, not a committed `.env` file. Preserve URL-encoded password characters. Do not add a Supabase service-role key to the browser; the app uses Prisma server-side.
5. For a new, empty project, generate the Prisma client and apply the schema with `npm run db:generate && npm run db:push --workspace apps/web` while both URLs point only to that new project. `db:push` creates the bootstrap administrator/organization and syncs the schema; it is for initial setup/development, not a routine production migration command.
6. Before moving existing local data, make a database dump and verify it can be restored to a separate Supabase project. Do not run the bootstrap/schema-push script against an existing production project without reviewing the diff and keeping a recoverable backup.
7. Deploy the Next.js app to a Node-compatible application host separately. Set production `APP_ORIGIN`, `SESSION_SECRET`, `ADMIN_PASSWORD_HASH`, `DATABASE_URL`, and `DIRECT_URL` there. Docker is optional for the app deployment and remains useful locally.

Supabase is managed PostgreSQL, not a zero-maintenance or unlimited store: choose region, compute/storage plan, backup/retention, connection mode, and budget before production. See [the Supabase setup checklist](../../docs/supabase-setup.md) for migration and deployment details.

The app binds to loopback by default. Database-backed accounts are scoped through organization memberships. The bootstrap administrator creates member or administrator accounts in the Team view using a temporary password; accounts can be removed from the current organization. Self-service signup, password reset, invitation email, and multiple organization switching are not provided.

For production, set `NODE_ENV=production` and `APP_ORIGIN` to the exact public HTTPS origin (for example `https://doctor.example`). Set `TRUST_PROXY=true` only when a trusted reverse proxy overwrites `X-Forwarded-For` and `X-Real-IP`; otherwise client-based login throttling uses a single local bucket. The production session cookie is Secure, HttpOnly, SameSite=Strict, and signed. Login and API limits are stored in PostgreSQL. Apply the current Prisma schema before starting the application.

## Capabilities

- Register and remove websites, configure periodic availability and browser checks, and review check history.
- Perform on-demand DNS-pinned HTTP(S) HEAD checks. Private/local IPs and unsafe redirects are rejected; each redirect is resolved and pinned separately, request timeout is 10 seconds. HTTP responses below 500 are marked available.
- Discover same-origin URLs from page links and robots.txt/sitemap.xml (including sitemap indexes), then crawl up to 250 pages at depth 8 and mobile, tablet, and desktop widths. A dedicated broken-link detector checks up to 1,000 same-origin link candidates and probes at most 200 unvisited destinations with DNS-pinned `HEAD` requests; it reports 404/410 and missing same-page anchors, ignores external links and 401/403, and marks exhausted probe budgets as partial evidence. Redirects are revalidated and followed only while they remain on the registered origin. Layout overflow, navigation behavior, missing image alt text, unnamed controls, axe-core WCAG A/AA rules, uncaught page exceptions, console errors, failed requests, and HTTP errors are also recorded with their viewport observations. Browser performance findings use explicit lab-sample thresholds: load event over 5 seconds, LCP over 2.5 seconds, CLS over 0.1, a measured resource at least 1 MB encoded or at least 3 seconds, and more than 100 resource entries on a page. These are triage signals, not Lighthouse scores or field Core Web Vitals; cross-origin resource sizes can be unavailable in Resource Timing. Scan-level subresource counts and transfer-size totals deduplicate resources across viewports and pages; timing summaries report the median, 75th percentile, and maximum of valid page/viewport samples. Contrast is reported through axe-core; the previous simplistic color-compositing heuristic has been removed. The scan is bounded by 10 minutes, 3000 browser requests, 2 MB per response, and 100 MB combined response size. Browser requests are DNS-pinned, public-address only, GET/HEAD only, and redirects are revalidated; WebSockets and WebRTC are disabled. Crawl limits and page errors are stored as partial-scan metadata.
- Run a local-process scheduler for enabled checks. The Node app must stay running; the scheduler is for one local instance, not distributed/high availability.
- Manual and scheduled scans are persisted as background jobs. Manual requests return `202` with a scan ID, tenant queues are limited to two active/pending scans and six scans per 15 minutes, workers use two local slots, database-backed expiring leases, up to three attempts, and exponential retry delays. The worker queue can be claimed across app instances, but the due-site scheduler itself remains an in-process single-instance scheduler.
- Each website offers **Scan only** and **Scan + AI**. Both queue the same HTTP, bounded Playwright, responsive, and axe-core evidence collection and return promptly with a scan ID. Scan only stops after deterministic evidence collection. Scan + AI then analyzes up to ten active findings associated with that scan using the configured local model; remaining findings can be analyzed individually. AI is optional, and WordPress logs/plugin inventory/cron evidence is available only when the separate plugin is connected and has synced diagnostics.
- Record detected availability/WordPress issues, manage issue state, request local-AI diagnoses and evidence-based repair proposals (including manual-only remediation plans), record approvals, and export JSON reports.
- Validate AI diagnoses against a strict schema with evidence-reference IDs, separate observed facts from hypotheses, and refuse unsupported page/component claims. Invalid model output gets one structured correction attempt, then is safely rejected while deterministic findings remain.
- Pair an independent WordPress plugin through the HTTP API. The PHP plugin is not imported, loaded, executed, or served by Next.js.
- Record each WordPress repair's operation allowlist, risk, required permission, approval, operation-specific recovery record, execution, verification, rollback state, and lifecycle history. Executable proposals cover exact plugin/theme changes isolated by completed disposable-staging comparisons, temporary deactivation of an exact active plugin mapped unambiguously to a recent PHP fatal, and replacement of one exact link in a published editable post/page. Permanent redirects use their verified final destination. For confirmed 404/410 links, an administrator supplies one replacement URL; the app requires same-origin and a successful HTTP response before creating the proposal. Before any change, the plugin stores only the exact operation target and prior value/content, and refuses execution if that record is incomplete or the target has changed. It restores only that target if it still matches the expected after-value; unrelated newer state is preserved. Link edits retain exact post content and hash; the central app rescans the source page and replacement destination. Missing anchors, links owned by a menu/template/shortcode, and external links remain manual guidance. The blog name/description setting operation requires the exact expected current value and requested new value. Cache flush is not executable because prior cache contents cannot be restored. Fatal containment is verified by fresh plugin diagnostics and a central home-page availability check; it does not claim to repair plugin code. No new full-site backup confirmation is required; existing site backups remain the broader recovery option. Other findings receive evidence-specific manual remediation steps when no exact operation and verification are available; performance findings do not yet authorize automatic changes.

The crawl may not reach every page on a large site, and broken-link probing is limited to same-origin links and the stated per-scan cap. `HEAD`-only endpoints that reject or misreport `HEAD` can remain unclassified; only 404/410 responses are called missing, while authentication failures and external URLs are excluded. Axe-core automated checks are not a complete WCAG audit or conformance claim; manual review remains necessary, and browser performance data is not Lighthouse or field Core Web Vitals. Performance resource measurements can be unavailable or cache-sensitive, and the thresholds are heuristic triage controls. Browser findings do not create automatic CSS/layout repairs. The plugin detects fatal errors observed by its shutdown handler and, only when an administrator enables authorized log collection, parses at most 20 PHP warning/notice/deprecation/fatal entries from a redacted tail excerpt of `wp-content/debug.log` (up to 16 KiB read and 12 KiB sent). It does not read PHP-FPM, web-server, hosting-provider, or historical rotated logs; an absent/unreadable log is reported as unavailable evidence, not as proof of no errors. Full-site backups and non-WordPress repair execution are not implemented; repairs remain limited to the documented WordPress allowlist. Organization accounts currently require an administrator to provision a temporary password; no reset or invitation delivery is provided.

## Local AI

Ollama is optional; the application continues non-AI diagnostics if it is unavailable.

```sh
docker compose --profile ai up -d ollama
docker compose exec ollama ollama pull qwen2.5:3b
```

Configure `AI_PROVIDER=ollama`, `OLLAMA_BASE_URL`, and `OLLAMA_MODEL` in `apps/web/.env`. The engine is provider-independent, but Ollama is the only implemented provider. Confirm model licensing and local hardware needs before use.

## API boundary

WordPress pairing, agent authentication, diagnostics, task polling, and execution-result contracts are documented in [`../../contracts/wordpress-agent-api.md`](../../contracts/wordpress-agent-api.md). The web app owns the central AI engine and API; the PHP plugin remains a separate project.

Agent API calls require a per-installation HMAC signature, timestamp, and one-use nonce. Bearer credentials are stored centrally only as hashes, rate-limited by agent identity, and revoked on disconnect. Pair again to rotate credentials. The app persists auth/agent security events and the complete repair lifecycle.

## Data model

PostgreSQL/Prisma models cover organizations and memberships, websites and monitoring settings, WordPress installations and separately hashed/rotatable installation credentials, scan sessions, diagnostic results and evidence, issues and AI diagnoses, repair proposals/approvals/executions, backups, verification results, notifications, audit logs, rate-limit buckets, durable background jobs, and scoped system settings. Scan workers use the database-backed job queue; the due-site scheduler remains an in-process single-instance timer. Environment secrets remain outside the settings table and secret-marked settings must never be returned to clients. Diagnostics retain JSON snapshots for compatibility while normalized scan/evidence records support history and reporting.
