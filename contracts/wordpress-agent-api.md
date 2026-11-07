# WordPress Agent API contract

Version: `v1` (current routes are prefixed `/api/agents`; breaking changes require a new versioned route).

The WordPress plugin and central app are separate projects. The plugin communicates only over HTTPS JSON APIs; it does not include or load application code. The app does not load, execute, or serve plugin PHP. Local development may use HTTP loopback only.

## Pairing

1. An authenticated app administrator creates a pairing code:

   `POST /api/agents/pairings`

   Request: `{ "websiteId": "<registered-site-id>" }`

   Response `201`: `{ "code": "<opaque-single-use-code>", "expiresAt": "<ISO-8601>", "website": { "id": "...", "name": "...", "url": "..." } }`

   The code is shown once, stored centrally only as a SHA-256 hash, and expires after ten minutes.

2. The plugin submits the code and its site identity:

   `POST /api/agents/register`

   Request: `{ "code": "...", "siteUrl": "https://site.example/", "siteName": "...", "wpVersion": "...", "phpVersion": "...", "pluginVersion": "..." }`

   The normalized site origin/path must match the central registered URL. A pairing code can be consumed once. Response `201`: `{ "agentId": "<id>", "token": "<opaque-bearer-secret>" }`. The bearer secret is displayed only in this response; central storage holds its hash. Both pairing and registration responses are `Cache-Control: no-store`.

## Agent authorization

Subsequent agent requests use:

`Authorization: Bearer <agent-secret>`

Every authenticated request must also include `X-AWD-Timestamp` (Unix seconds), a fresh random 32-character hexadecimal `X-AWD-Nonce`, and `X-AWD-Signature` (64-character hexadecimal HMAC-SHA256). The HMAC key is the per-installation bearer token. The canonical signed text is the uppercase method, request path plus query, timestamp, nonce, and lowercase SHA-256 digest of the exact HTTP body, joined with newline characters. Timestamps outside five minutes are rejected; a nonce can be used once per installation. Signed request bodies are limited to 100 KB. Retries must be freshly signed.

The plugin stores the secret locally; it must never log or include it in diagnostics. The app stores only a hash, checks the agent ID on each route, applies per-agent rate limits, and supports revocation. Disconnect/revoke and pair again to rotate the installation credential. TLS certificate verification is required; redirects are not followed.

## Diagnostics sync

`POST /api/agents/{agentId}/diagnostics`

Payload:

```json
{
  "collectedAt": "2026-01-01T00:00:00Z",
  "site": {
    "wpVersion": "6.x",
    "phpVersion": "8.x",
    "memoryLimit": "256M",
    "debugMode": false,
    "cronDisabled": false,
    "overdueCronCount": 0,
    "activeTheme": { "name": "Theme", "version": "1.0", "stylesheet": "theme" }
  },
  "plugins": [
    { "name": "Example", "version": "1.0", "file": "example/example.php", "active": true, "updateAvailable": false }
  ],
  "phpErrors": [
    { "id": "<32-character-hash>", "level": "warning", "message": "A bounded, redacted PHP log message", "file": "example.php", "line": 42 }
  ],
  "phpErrorLog": {
    "collectionEnabled": true,
    "status": "readable",
    "observedCount": 1,
    "limit": 20
  },
  "issues": [
    { "fingerprint": "wp-cron-disabled", "title": "WP-Cron disabled", "description": "Review scheduling.", "severity": "medium" }
  ],
  "authorizedLogExcerpt": "Optional, explicitly opted-in excerpt"
}
```

Fields and array counts are bounded and validated by the app. `phpErrors` contains at most 20 parsed warning, notice, deprecation, fatal, parse, or uncaught-exception records from the same excerpt. `phpErrorLog.status` is `disabled`, `readable`, `not_found`, `unreadable`, `empty`, or `unavailable`; an unavailable log is not evidence that PHP is healthy. Log collection is opt-in in the plugin, reads only a 16 KiB tail of `wp-content/debug.log`, sends at most 12 KiB of redacted excerpt, and may still contain sensitive data. The plugin also records PHP fatal errors observed at shutdown independently of log opt-in. It cannot access host PHP-FPM, web-server, or rotated logs. The central app stores diagnostics and creates/updates WordPress issues.

## Plugin dashboard and shared repair decisions

`GET /api/agents/{agentId}/dashboard` returns the connected website's latest synchronized diagnostics, latest WordPress scan, central HTTP availability result, and WordPress issue records with their central AI diagnosis, repair proposals, approval/execution state, and lifecycle events. It is read-only and scoped to the authenticated agent's website. The plugin may cache this response for display during temporary central-service outages.

`POST /api/agents/{agentId}/analysis` accepts `{ "issueId": "..." }`, runs the central AI engine against that stored issue and its evidence, and stores the same diagnosis record exposed in the custom application. If central inference is unavailable, the response records `aiStatus: "unavailable"`; the plugin has no offline/cloud AI fallback.

`POST /api/agents/{agentId}/repairs` accepts `{ "issueId": "..." }` and creates a centrally stored, pending-approval evidence-based proposal. The deterministic repair policy emits executable steps only for exact plugin/theme changes isolated by a completed disposable-staging comparison. Other findings include `proposal.manualGuidance` and have no executable steps. This endpoint does not use AI to invent or authorize operations; it uses the same repair state and history visible in the custom application.

Manual-only proposals have an empty `instructions.steps` array, `executionAvailable: false`, and a finding-specific `manualGuidance: string[]`. Acknowledge/reject actions update the proposal history but do not create an agent task or perform a site change.

`PATCH /api/agents/{agentId}/repairs/{repairId}` accepts `{ "decision": "approve" | "reject" }`. This records a central approval decision from the connected WordPress administrator. Approval does not execute the repair; the local administrator must still separately confirm execution in the plugin.

While central service is unavailable, the plugin keeps the latest bounded local diagnostic snapshot in a non-autoloaded option and retries on the next scheduled/manual sync. It replaces older queued snapshots to avoid replaying stale findings out of order. This queue is diagnostic data only; it does not queue or execute repair actions.

## Approved tasks

`GET /api/agents/{agentId}/tasks`

Response: `{ "tasks": [ ... ], "rollbackRequests": [ ... ], "manualRecoveryRequests": [ ... ], "diagnosticsRequired": false }`; responses are not cacheable. `diagnosticsRequired` is true until a valid diagnostic baseline has been synchronized. Centrally approved, unexecuted proposals are returned only when their WordPress fingerprint is still in the synchronized baseline or their browser-link evidence and mapped post are fresh. Each task contains `repairId`, `issue`, `issueFingerprint`, `rationale`, centrally assigned `risk`, `requiredPermissions`, baseline high-severity issue fingerprints, exactly one declarative `step`, `verificationPlan`, and `requireCloudBackup`. When an organization has connected Google Drive, `requireCloudBackup` is true and the plugin must upload a recovery snapshot before applying the task; an upload failure blocks the mutation. Otherwise, the plugin keeps its existing local-only operation-specific recovery point. Neither form is a full-site backup. A manual recovery request contains `repairId`, `backupId`, `requiresLocalApproval: true`, and display-only operation/target/reason fields. Both execution and restoration require explicit WordPress administrator confirmation and `manage_options`.

The executor validates a strict operation allowlist. Supported `steps[].operation` values and parameters:

- `disable_plugin`: `{ "plugin": "<installed plugin-relative PHP file>" }`; cannot target the agent plugin or network-activated plugins.
- `switch_theme`: `{ "stylesheet": "<installed stylesheet slug>" }`.
- `update_setting`: `{ "option": "blogname" | "blogdescription", "expectedCurrentValue": "<string>", "value": "<string>" }`; applies only if the exact old value still matches.
- `replace_post_link`: `{ "postId": "<published post/page ID>", "pageUrl": "<mapped source page>", "linkUrl": "<exact old same-origin URL>", "replacementUrl": "<verified same-origin URL>" }`; changes exactly one matching link in that post's content. A broken-link replacement must be selected by an administrator and verified as reachable before proposal creation.
- `add_scoped_css_rule`: `{ "selector": "body.page-id-<ID> #<id>" | "body.page-id-<ID> .<class>" | "body.postid-<ID> #<id>" | "body.postid-<ID> .<class>" }`; only offered for a measured horizontal overflow on an editable published page while `WP_ENVIRONMENT_TYPE=staging`. The plugin appends the fixed declaration `max-width: 100%` to theme Additional CSS, captures the exact prior CSS for guarded rollback, and rejects the operation outside staging.

No shell, PHP, SQL, arbitrary option, filesystem path, or executable instructions are accepted. Central approval is necessary but not sufficient: a local WordPress administrator must explicitly initiate execution in the plugin UI.

## Google Drive recovery points

When `requireCloudBackup` is true, the plugin posts `{ "repairId": "...", "backupId": "<UUID>", "recoveryPoint": { ... } }` to `POST /api/agents/{agentId}/backups` before applying the operation. The request is bounded to 600 KB; the server validates that the complete single-operation snapshot ID, operation, and target match the approved proposal, then encrypts and uploads it into that website's Drive folder. The response is `{ "backupId": "...", "status": "created", "sha256": "..." }`. The plugin must not apply the repair unless it receives this confirmation.

The app's website-scoped restore request is surfaced in `manualRecoveryRequests`. After a local WordPress administrator confirms, the plugin calls `GET /api/agents/{agentId}/backups/{backupId}`. This returns `{ "backupId": "...", "recoveryPoint": { ... } }` only for a pending restore request belonging to that authenticated agent and website; the server revalidates the snapshot against the approved operation before returning it. The plugin imports it into its local recovery store and uses the existing conflict-aware restore behavior. It then posts `{ "status": "restored" | "failed", "message": "..." }` to `POST /api/agents/{agentId}/backups/{backupId}/restore-result`. Both routes are authenticated, bounded, and site-scoped. The restore changes only the saved operation target and refuses to overwrite a newer value.

## Execution report and revocation

`POST /api/agents/{agentId}/executions`

Request: `{ "repairId": "...", "status": "completed" | "failed" | "rolled_back" | "rollback_failed" | "verification_failed" | "inconclusive", "result": { "message": "...", "backupId": "...", "backupStatus": "created" | "not_required" | "failed" | "unavailable", "executionStatus": "completed" | "failed", "verificationStatus": "passed" | "failed" | "inconclusive", "verificationReason": "...", "verified": true, "rollbackApplied": false, "afterEvidence": {} } }`. The `backupId` field identifies the small operation-specific undo record, not a full-site backup. When Drive is connected, the server also requires a matching successfully uploaded Drive snapshot before it accepts the backup as valid.

Before execution, the plugin records the exact operation target and previous value/content; it rechecks that the target still has the captured before-value. On verification failure, it restores only that target and only if it still matches the expected after-value, preserving unrelated or newer state. Cache flush is not an allowed repair because its prior contents cannot be restored. The central app independently compares the original issue fingerprint and high-severity findings against post-repair evidence; the agent's `verified` assertion is recorded for audit but is not trusted as the verification decision. An unresolved original issue, new high-severity finding, or missing comparable evidence can never be marked successful. The app does not issue an automatic plugin rollback task without a configured provider restore capability.

The app records proposal, approval, operation-specific undo record, execution, verification, and rollback lifecycle events against the approved proposal, invokes central AI review and before/after comparison, and moves a proposal to `rollback_required` when rollback is recommended. Google Drive recovery restores only the exact operation target stored before the change; full-site files/database backup and restore remain outside this workflow. AI unavailability is recorded and does not prevent deterministic reporting. Arbitrary PHP/SQL/shell/JavaScript and general file edits are unsupported.

`DELETE /api/agents/{agentId}` revokes credentials using the agent bearer token. An authenticated app administrator can also revoke with `POST /api/agents/{agentId}/disconnect`.

## Error behavior

JSON errors have shape `{ "error": "<message>" }`. `401` means credentials/pairing are invalid; `403` means a mismatched identity; `404` means no corresponding website/proposal; `409` means state conflict; `413` means the request exceeds limits; `5xx` indicates a service-side failure. Clients should not retry non-idempotent repair execution blindly.

The current implementation uses these routes as the v1 contract; formal OpenAPI generation and explicit `/v1` URL prefixing remain future compatibility work.

## Shared intelligence and execution lifecycle

The central web application is the only AI inference/orchestration service. The plugin never includes a model, API key for an AI provider, or independent diagnosis logic. It submits bounded diagnostic evidence, displays central findings/proposals, and performs only explicitly approved local operations. The central side stores evidence against the registered website/issue, selects relevant tool evidence, validates structured model results, applies severity/risk policy, and records review and execution outcomes.

`POST /api/issues/{issueId}/diagnose` is the authenticated administrator endpoint for central AI analysis. A successful diagnosis has a strict schema containing `issueTitle` and `issueTitleEvidenceRefs`, `category`, `description` and `descriptionEvidenceRefs`, `affectedWebsite`, `affectedPage`, `affectedComponent`, `severity`, `confidence`, `facts`, `hypotheses`, `probableRootCause` (always marked `hypothesis` or `insufficient_evidence`), `alternativeExplanations`, `recommendedFix` (including risk, approval requirement, verification procedure, and evidence references), and `evidenceReferences`. References are server-generated IDs mapped to observed evidence paths and values. Every conclusion reference must resolve to an included reference; the affected website must match its registered URL; page and component claims without matching evidence are rejected. Facts must be direct observations, while causes and explanations are hypotheses.

The central engine validates model output before returning or persisting it. Schema or evidence-reference failures trigger one structured correction attempt; a second failure is rejected. If local inference is unavailable or invalid, the response retains deterministic severity/evidence, returns `diagnosis: null`, and reports `aiStatus: "unavailable"` with an explanatory `aiError`.

The task response contains both `tasks` and `rollbackRequests`. For example:

```json
{
  "tasks": [],
  "rollbackRequests": [
    {
      "repairId": "repair-id",
      "issue": "Issue summary",
      "backupId": "local-recovery-point-id",
      "reason": "Central verification recommends restoring the local recovery point.",
      "requiresLocalApproval": true
    }
  ]
}
```

The plugin must not automatically execute either list. For a repair task, the administrator confirms the action locally. The plugin sends the post-action diagnostic evidence and result to the execution endpoint. The central engine reviews the result and compares before/after evidence. Reports use `completed`, `failed`, `verification_failed`, `rolled_back`, or `rollback_failed`. Central approval does not let the app reach or repair a WordPress server that is offline; WordPress execution requires a reachable site and agent.


The central diagnostic catalog covers independent HTTP availability, WordPress configuration/plugin inventory/WP-Cron/authorized PHP log evidence, and bounded Playwright browser evidence. Browser scans crawl same-origin pages up to 250 pages/depth 8 and 3 viewports, collect responsive/accessibility/runtime/network evidence, check up to 1,000 same-origin link candidates with at most 200 `HEAD` probes, and apply explicit lab-sample performance heuristics. Link findings are limited to confirmed same-origin 404/410 responses and missing in-page anchors; 401/403 and external links are not labeled broken. Browser performance is not Lighthouse or field Core Web Vitals, and automated accessibility checks are not a complete conformance audit. Scan limits and partial results must be retained when describing what was covered.
