# One-click repair and recovery design

## Goal

From either the central dashboard or the WordPress plugin, an administrator can request a diagnosis, review a specific proposed change, and apply it with one confirmation. The system verifies the change and restores the plugin's saved WordPress settings when verification fails. The user's existing host backup process stays separate; the app does not require or manage a new backup for every repair.

## Recovery levels

Every proposed operation declares the state it can change and the recovery level required to undo it.

| Level | What it covers | Example | Use |
| --- | --- | --- | --- |
| `wordpress_state` | Explicit WordPress options and activation/theme selections captured by the plugin | A narrowly scoped option update | Eligible only when the operation is deterministic and its inverse is verified |
| `database_and_files` | Complete site database and files, created by a configured host or backup provider | Plugin/theme changes or code updates | Required for operations that can invoke hooks or alter site data/files |
| `staging_only` | Reproduction and candidate validation without production mutation | Plugin conflict isolation | Evidence only; never counts as a production recovery point |

The plugin's recovery point covers selected WordPress settings, plugin/theme activation, and (on staging only) the exact theme Additional CSS value for one scoped responsive-width rule. Staging evidence helps select a repair but is not a production restore point. Keep the scope visible so the app does not claim that it reverses unrelated hook side effects.

## One-click execution flow

1. **Collect evidence.** Run availability, browser, WordPress, and configured host-log checks. Store the scan coverage and mark partial or unavailable evidence explicitly.
2. **Propose a bounded operation.** Include the evidence that supports the suspected cause, exact target and parameters, expected effect, required permissions, recovery level, and verification checks. The AI may explain or rank candidates; deterministic policy selects allowed operations.
3. **Check prerequisites.** Confirm the agent is connected, the site identity and baseline are current, and no other repair is running. Refuse execution if evidence is stale or the exact operation is not allowlisted.
4. **Validate on staging where relevant.** Reproduce the issue, apply the same operation to disposable staging, and compare matching scans. Staging is not a substitute for production backup.
5. **Capture local undo state.** Save one exact operation target and its prior value/content. The record is specific to this change; existing host backups are managed separately by the site administrator.
6. **Apply once.** Require one local administrator confirmation. Use an idempotency key and a per-site lease so duplicate clicks or concurrent workers cannot apply the operation twice.
7. **Verify automatically.** Run the operation-specific check plus availability, relevant browser checks, WordPress diagnostics, and a regression scan. Require comparable complete evidence; partial scans cannot establish success.
8. **Recover on failure or uncertainty.** Restore only the saved operation target, and only if it still matches the expected after-value; preserve newer or unrelated changes. Rerun health checks. The administrator's existing site backup remains the broader recovery option.
9. **Record the lifecycle.** Persist evidence references, operation, approvals, recovery metadata, execution attempts, before/after scans, verification, rollback outcome, and timestamps in the central repair history and plugin UI.

## Repair-specific Google Drive snapshots

An organization owner or administrator can connect a dedicated Google account from a website's Backups tab. The app creates an organization Drive root and a website-specific folder, then stores one encrypted snapshot per repair. The snapshot contains only the exact WordPress operation's before/after state; it is not a full-site files-and-database backup.

When Drive is connected, the paired plugin must upload that snapshot before mutating WordPress. A failed or unconfirmed upload blocks the repair. Without Drive, the plugin continues to use its existing local-only operation-specific recovery record; these records are not automatically uploaded later. The app lists snapshots only for the selected website.

An administrator can request a restore from the app. The paired plugin polls that site's pending request and presents it to a local WordPress administrator. After confirmation, the plugin downloads and validates the snapshot, then uses its existing conflict-aware restore logic. It changes only the saved target and refuses to overwrite a value that no longer matches the recorded before/after state. The result is recorded in the app. Full-site backup, file/database capture, and full-site restore are intentionally out of scope.

Configure `GOOGLE_DRIVE_CLIENT_ID` and `GOOGLE_DRIVE_CLIENT_SECRET`, register `${APP_ORIGIN}/api/integrations/google-drive/callback` as the Google OAuth redirect URI, and set a private `SESSION_SECRET` of at least 32 bytes. The refresh token and snapshot content are encrypted by the app; the Drive permission uses the `drive.file` scope. Apply the Prisma schema before connecting an account.

## Safety rules

- Never describe an operation-specific undo record as a full-site backup.
- Keep production operations limited to exact allowlisted changes with evidence and a clear verification procedure.
- Do not auto-apply code, database, plugin, or theme changes while scans are partial or the site identity is stale.
- Keep local WordPress administrator confirmation for production mutations. Central approval alone is insufficient.
- Preserve the exact target and old value/content through post-change verification so a failed operation can be undone without overwriting unrelated newer state.
- Confirm multisite/network scope before any operation; a site-level repair must not affect sibling sites.

## Next implementation priorities

1. Extend browser evidence to diagnose other specific spacing problems; do not generate arbitrary margin/padding changes without a measured target and a reliable post-fix check.
2. Add a one-action approve-and-apply path in the chosen interface while retaining the local WordPress administrator as the final confirmer.
3. Add idempotency and per-site execution locks for repair tasks, then show progress and outcomes across the portfolio.
4. Extend issue-specific verification and recovery reporting without making the existing backup process a per-repair requirement.
