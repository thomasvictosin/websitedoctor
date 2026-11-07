# Repair authorization and workflow API

This reference describes the repair-related routes implemented by the web app. The WordPress agent protocol (pairing, signed requests, task polling, and execution reports) is documented in [the WordPress Agent API contract](../contracts/wordpress-agent-api.md).

## Authentication and request rules

Web routes require an authenticated organization member and scope site, issue, and proposal lookups to that member's organization. State-changing requests also use the app's origin/CSRF validation. Only organization owners and administrators can change a site's standing repair permissions. The WordPress agent routes use the per-installation signed bearer protocol described in the agent contract.

JSON request bodies are bounded and validated. Responses containing repair state use `Cache-Control: no-store` where appropriate. Errors use `{ "error": "..." }`; scope clarification from the assistant is a successful response with a `status` field because the user can refine the request.

## Read or update a site's repair policy

### `GET /api/sites/{siteId}/repair-authorization`

Returns the current repair authorization policy for an owned site. This is read-only and available to authenticated organization members.

### `PUT /api/sites/{siteId}/repair-authorization`

Owner/admin only. Replaces the site's policy. Example:

```json
{
  "mode": "manual",
  "allowedOperations": ["replace_post_link"],
  "maxRisk": "low",
  "maxRepairsPerBatch": 10,
  "requireRecoveryPoint": true,
  "requireVerification": true,
  "paused": false
}
```

`mode` is `manual` or `auto_eligible`. `allowedOperations` accepts `disable_plugin`, `switch_theme`, `update_setting`, and `replace_post_link`, with up to four entries. Automatic mode requires at least one selected operation. `maxRisk` is `low`, `medium`, or `high`; `maxRepairsPerBatch` is 1–25. Recovery point and independent verification are mandatory and must be `true`. `paused` pauses standing authorization. Unknown fields are rejected.

Response `200` returns the normalized policy. Updating or pausing a policy revokes standing-policy approvals that have not yet been dispatched to the site; already dispatched work remains recorded for its execution report. Explicitly approved, per-repair grants are not standing-policy approvals.

## Create evidence-backed repair proposals

### `POST /api/issues/{issueId}/repairs`

Creates a proposal from the stored issue evidence. The optional request body field `replacementUrl` is accepted only for a browser broken-link finding and must be a reachable, clean URL on the same site origin.

Successful creation returns `201` with the redacted proposal. An active proposal for the same issue returns `409`. Creating a proposal does not itself approve an operation. A matching standing policy may authorize it if all policy, evidence, risk, recovery, verification, and connected-agent checks pass; otherwise it remains pending approval or guidance only.

Horizontal-overflow proposals include `add_scoped_css_rule` only when a complete browser finding identifies a uniquely selectable element that exceeds its parent, the matching published page is in the paired agent's editable-page inventory, and the agent reports `site.environmentType: "staging"`. The operation accepts only a page-scoped ID/class selector; the plugin appends a fixed `max-width: 100%` declaration to the active theme's Additional CSS and refuses to execute outside staging. It records exact CSS before/after content for guarded rollback and requires a complete central browser rescan to clear the original overflow. This does not attempt arbitrary margin/padding changes.

### `POST /api/sites/{siteId}/repair-requests`

Interprets a user's bounded request against active issue evidence. Request:

```json
{ "prompt": "Fix the broken link on the pricing page", "issueId": "optional-active-issue-id" }
```

`prompt` is required (3–1,000 characters); `issueId` is optional. At most 20 requests per user per 15 minutes are accepted. With no issue ID, the central interpreter matches active issues; if it is unavailable, a deterministic local fallback is used. A named category, page, or multi-issue scope is validated against the matching evidence.

Diagnosis requests return `status: "diagnosis_results"`; recommendation requests return `status: "recommendations"`. Neither creates a proposal. Ambiguous matching or scope returns `needs_issue_selection` or `needs_scope_clarification`, with candidates where available. Explicit repair requests return `201` with `status: "queued"` or `"plan_ready"`, per-issue results, and skipped conflicts. A result can be `queued`, `requires_approval`, or `guidance_only`. A standing policy can authorize an explicitly requested matching operation. Without that policy, the matching owner/admin may explicitly authorize the prompt-scoped repair, subject to execution safeguards. Merely asking for a diagnosis or recommendation never authorizes execution.

### `POST /api/sites/{siteId}/hosting/repairs`

Records a hosting repair request for review. The request must identify a connected, owner-scoped SFTP connection, an open issue belonging to the site, a registered repair operation, and an exact target inside the configured document root. `.htaccess` restore/regeneration proposals are limited to the root `.htaccess` file. Only one active proposal per issue is allowed. The proposal is added to the shared issue repair history with `executionAvailable: false`; it is not eligible for standing authorization or batch execution. Acknowledging it records review only: no backup or remote write occurs. `approve_and_apply` explicitly returns `501` for hosting proposals, batch authorization returns `409`, and WordPress agent approval/task routes reject or ignore hosting proposals.

## Approve, reject, or queue a proposal

### `PATCH /api/repairs/{repairId}`

Owner/admin only. Request:

```json
{ "decision": "approve" }
```

`decision` is `approve`, `approve_and_apply`, or `reject`. Only pending proposals can be changed. For WordPress proposals, `approve` records central approval for a WordPress administrator to apply locally. For hosting proposals, approval records review only and does not execute a remote change. `approve_and_apply` requests execution on the connected WordPress agent's next poll and requires a single allowlisted executable operation, a fresh agent, eligible authorization, and no overlapping active repair; it explicitly rejects hosting proposals with `501`. The response includes the new status, execution state, and message. Missing proposals return `404`; ineligible or overlapping proposals return `409`; invalid/non-executable requests return `400`.

### `POST /api/repairs/batch`

Owner/admin only. Request:

```json
{ "repairIds": ["repair-id-1", "repair-id-2"] }
```

Requires 1–25 distinct proposal IDs. Every proposal must belong to the member's organization, be pending, executable, eligible under the site's policy, and have a fresh connected agent. Incompatible targets, overlapping active proposals, or stale state reject the batch with `409`; no partial batch approval is committed. A successful response records a shared batch ID and queues the selected operations for the relevant site agents to poll. Each operation still requires local WordPress administrator confirmation.

## Agent lifecycle endpoints

The app/plugin shared state is exposed through the authenticated agent routes:

- `POST /api/agents/{agentId}/repairs` proposes a repair from a stored issue.
- `PATCH /api/agents/{agentId}/repairs/{repairId}` records the connected WordPress administrator's approval or rejection.
- `GET /api/agents/{agentId}/tasks` returns centrally approved tasks and any rollback requests.
- `POST /api/agents/{agentId}/executions` records execution results.

These routes require the signed agent authentication protocol and still require local WordPress confirmation before applying a task. See the [agent contract](../contracts/wordpress-agent-api.md) for schemas, signature rules, operation allowlist, replay protection, and execution reporting.

## Status and error summary

Common HTTP errors are `400` for malformed or out-of-policy input, `401` for missing/invalid authentication, `403` for insufficient role or identity mismatch, `404` for an unowned/missing resource, `409` for conflicting or stale workflow state, `413` for request size limits, `429` for rate limits, and `5xx` for service failures. Assistant scope clarification is represented as a `200` response with a non-final `status`; clients should present it as a request for clarification, not as a created repair.
