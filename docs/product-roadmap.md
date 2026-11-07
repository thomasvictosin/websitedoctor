# Product roadmap: hosting control, repair recovery, AI, and remote access

This roadmap records the product decisions and current implementation boundary discussed on 6 November 2026. Hosting adapters stay provider-neutral: each client can use a different host, and capability detection is more useful than a provider allowlist.

## Agreed product principles

- A website can be registered as production without a staging companion. Pairing staging is optional.
- Diagnosis, evidence-based recommendations, and manual guidance must remain useful when AI is unavailable or disabled.
- AI analysis is an explicit optional step; AI output never directly authorizes a change.
- The owner chooses whether to apply a supported change, and sees its target, backup/recovery method, risk, and verification plan first.
- Hosting writes are user-selected. Present a clear warning and a confirmation step; do not silently write. SFTP must not be forced into read-only mode as a product rule.
- Hosting providers vary by client. Prefer protocols and capability discovery (SFTP/SSH, cPanel-compatible UAPI, Plesk, provider APIs, WordPress agent) rather than designing around one provider brand. A credential/connection protocol is not proof that a particular host exposes a safe write API.
- Keep both change-level recovery and, where a compatible backup integration supports it, whole-site backup/restore. Label the scope and cost before the owner enables full-site retention or restore.
- Local Docker is a development option. Production runs the app on a suitable application host and points Prisma at managed PostgreSQL; Docker is optional for that deployment.

## Current state

- WordPress change execution exists for a small allowlist through the paired plugin, with exact-target recovery and verification.
- Google Drive can hold encrypted operation-specific WordPress recovery snapshots. It is not a complete file/database backup.
- Hosting inspection currently supports pinned SFTP reads. cPanel, Plesk, and provider adapters have registry/UI placeholders, not operational adapters. Hosting proposals do not execute.
- Deterministic browser/HTTP/accessibility diagnostics already run without AI. Deterministic rule-based diagnosis and remediation guidance are available as explicit no-AI issue actions; these label observed facts and leave root cause unconfirmed. This is a bounded rule checklist, not an inferred root cause.
- Ollama is the only model provider. It defaults to `qwen2.5:3b`; no OpenRouter/Grok providers, credit-aware fallback, or provider health policy are implemented.
- Docker Compose supplies local PostgreSQL and optional Ollama only. Prisma uses the PostgreSQL `DATABASE_URL` environment variable.
- No MCP server is implemented.

## Checklist, in implementation order

### 1. Provider-neutral hosting connections and explicit write intent

- [x] Replace provider-specific UI wording with provider-neutral method/capability choices and a free-text provider label. (Some unimplemented protocols remain disabled until adapters exist.)
- [x] Remove copy that says SFTP is read-only by design. Current SFTP features inspect only; future write capability depends on a safe adapter and the selected operation.
- [ ] Add a write-intent confirmation screen/modal that names the host, exact path, intended operation, backup scope, overwrite risk, and rollback limits.
- [ ] Keep SFTP writes disabled until the adapter can guarantee safe path confinement, conditional commit or writer fencing, pre-change snapshots, and conflict-safe rollback. A confirmation warning is necessary for consent, but cannot repair the technical race where another process changes a remote file between inspection and write.
- [ ] Implement and validate adapters by actual host capability, not brand. First investigate a minimal per-site Linux agent or documented conditional provider API. Treat cPanel UAPI and branded control panels as different APIs unless the hosting account proves compatibility.
- [ ] Keep unsupported write attempts explicit and non-mutating; never imply that an acknowledged proposal performed a change.

### 2. Deterministic recommendations and optional AI

- [x] Add an authenticated deterministic recommendation endpoint and “Get Recommendation (No AI)” issue action using the fingerprint, measured evidence, and existing remediation rules.
- [x] Make “Analyze with AI” a separate optional action; it retains deterministic diagnosis when the provider is offline or invalid.
- [x] Explain that deterministic diagnosis reports recorded facts, leaves root cause unconfirmed, and does not bypass owner approval.
- [x] Reuse deterministic evidence-gated allowlist checks for recommendation and repair proposals; unsupported cases stay manual guidance.

### 3. Staging-to-production promotion and recovery

- [ ] Support promotion for explicit, versioned artifacts created by this app (initially narrowly scoped plugin/theme or file changes), rather than copying an entire WordPress database from staging over production.
- [ ] Require owner selection of source staging site and destination production site, an exact artifact/change list, destination compatibility check, a fresh destination backup/recovery point, approval, and post-deploy verification.
- [ ] Make promotion optional; users can continue to apply changes manually on staging and separately approve production changes.
- [ ] Add one-click change rollback for supported operations, with compare-before-restore conflict protection.
- [ ] Add optional full-site backup/restore only through a compatible host/backup adapter that can capture both files and database and prove restore completion. Show storage/compute cost, retention, and expected downtime/restore impact before enabling it.
- [ ] Keep operation snapshots and whole-site backups distinct in the UI and audit records.

### 4. AI provider routing and fallback

- [ ] Preserve Ollama as an optional self-hosted provider, not a required runtime dependency.
- [ ] Add provider adapters for explicitly configured hosted models (for example OpenRouter or xAI) and a provider chain with timeouts, retry limits, transient-failure detection, and configurable priority.
- [ ] Configure API keys server-side only. A fallback between paid APIs can spend money; show the configured provider order and require an administrator to enable each provider/cost-bearing fallback.
- [ ] Record provider/model/status per diagnosis without saving secrets; provide a health/configuration indicator.
- [ ] Keep non-AI workflows fully functional when all model providers are unavailable or out of quota.

### 5. Production database and deployment

- [ ] Keep Docker Compose for reproducible local development and optional local Postgres/Ollama. It is not the production deployment requirement.
- [ ] Add deployment documentation for a managed application host and managed PostgreSQL; production configuration only needs the managed Postgres connection string, secrets, HTTPS origin, and persistent job execution.
- [x] Document Supabase as a PostgreSQL option and prepare distinct runtime `DATABASE_URL` and Prisma CLI `DIRECT_URL` configuration, with a checklist for connection mode and IPv4/IPv6 constraints.
- [ ] Validate Prisma schema initialization, backups/point-in-time recovery, storage/compute limits, and production secrets in a separate project before switching.
- [ ] Decide the production database host and application host before any live migration. Never point a developer database at production during schema experiments.

### 6. MCP integration

- [ ] Add a remote Streamable HTTP MCP endpoint for authenticated, organization-scoped read tools: list sites, fetch scan summaries, list findings, and get deterministic/AI diagnoses.
- [ ] Start with read-only tools. Add write tools only for actions already supported by the app API, requiring the same user permissions, exact approval grant, audit trail, and confirmation policy.
- [ ] Use scoped, revocable credentials/OAuth and enforce tenant ownership/rate limits; do not expose raw database access, credentials, arbitrary shell, or unrestricted file operations.
- [ ] Publish a setup guide for connecting a user-selected MCP client/cloud interface.

## Decisions needed before production integrations

1. Which application hosting platform and database host should the production deployment target? Supabase is technically compatible, but account, region, budget, and connection details must come from the owner.
2. Which hosted AI providers may be enabled for paid fallback, and what monthly spend ceiling should be enforced? Until specified, only explicitly configured Ollama should run.
3. For full-site backups, should the first integration use the client’s existing hosting backup capability, or a chosen external backup provider? Full-site storage and restore can incur ongoing cost and provider-specific access requirements.
4. Which MCP client/cloud interface will connect first? The server should remain standard Streamable HTTP, but OAuth and client setup depend on the target.

## Research notes

- WordPress supports site migration, but promotion is not a universal atomic “push staging” operation: the deployed change can include files and database state, and URL changes require serialization-aware replacement. The safe first deployment feature is artifact-level promotion plus backup and verification, not a blind full staging database overwrite.
- Supabase provides managed PostgreSQL connection modes, including direct and pooled connections. Prisma can use it; select connection mode based on whether the app is long-running or serverless and how the deployment network reaches IPv4/IPv6 endpoints.
- MCP supports remote Streamable HTTP servers; use it for a controlled tool API, not direct DB connectivity.

## Primary references

- [WordPress migration handbook](https://developer.wordpress.org/advanced-administration/upgrade/migrating/)
- [WP-CLI database export](https://developer.wordpress.org/cli/commands/db/export/)
- [WP-CLI database import](https://developer.wordpress.org/cli/commands/db/import/)
- [WP-CLI serialization-aware search-replace](https://developer.wordpress.org/cli/commands/search-replace/)
- [Supabase PostgreSQL connection modes](https://supabase.com/docs/guides/database/connecting-to-postgres)
- [Supabase Prisma guide](https://supabase.com/docs/guides/database/prisma)
- [MCP TypeScript Streamable HTTP server transport](https://ts.sdk.modelcontextprotocol.io/v2/api/%40modelcontextprotocol/node/streamableHttp.html)
