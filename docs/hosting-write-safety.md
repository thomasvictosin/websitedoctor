# Hosting write-safety contract

## Current boundary

Hosting repair proposals are review records only. The current SFTP adapter performs inspection and no remote writes are implemented. This is the current capability boundary, not a permanent product rule that SFTP must always be read-only. When a technically safe writer is available, the product should let the user choose whether to write/overwrite and require a clear warning plus explicit confirmation. No route, task, approval grant, or WordPress agent may execute a hosting proposal today.

SFTP host-key pinning and DNS validation authenticate the connection endpoint; configured-root checks and symlink checks constrain the requested path at the time of inspection. They do not bind later file operations to the same filesystem objects. A remote user or process can replace a checked path component between `lstat` and a subsequent SFTP write. SFTP does not provide the descriptor-relative, no-follow path traversal required to close that race, so adding another pre-write check would not make writes safe.

## WordPress agent compromise cleanup (approved 7 November 2026)

The site owner decided that the WordPress plugin may change files to clean up a compromised site. This is a separate, narrower boundary than remote hosting writes: the plugin already runs inside the site as the web-server user, so no new credential or remote write path is created. It applies only to the compromise cleanup playbook (plugin 0.3.0+); hosting adapters remain read-only and the rules below for them are unchanged.

Allowed operations, each bound to evidence the owner reviewed:

| Operation | Target and precondition | Undo data kept |
|---|---|---|
| `quarantine_file` | An unknown file in the site root, an executable file in `wp-admin`/`wp-includes`/uploads or directly in `wp-content`, or a must-use plugin; never a core file, `wp-config.php`, `.htaccess`, or plugin/theme code. SHA-256 must equal the reviewed digest. | The file itself, moved (not copied) into the quarantine |
| `restore_core_file` | A path in the WordPress.org checksum list for the installed version. The central app fetches the official MD5 independently; the site's own list must agree; the downloaded file from `core.svn.wordpress.org` must match it; the current file must match the reviewed SHA-256. | Previous bytes |
| `remove_htaccess_rules` | Only lines the integrity analyzer flags outside `# BEGIN/END WordPress`, expanded to whole rewrite rules (conditions plus their rule) so a condition is never removed alone. Whole-file SHA-256 must match. | Previous file |
| `quarantine_plugin` | An installed plugin at the reviewed version; never AI Website Doctor. Offered as an opt-in only. | Plugin directory and its active state |
| `demote_user` | A current administrator, never the signed-in user or the last administrator. Opt-in only. | Roles and password hash |
| `rotate_salts` | `wp-config.php` defining each of the eight keys exactly once. | Previous file |
| `purge_page_cache` | Known cache plugins' purge functions. | None (no state to restore) |
| `purge_quarantine` | Permanently deletes one run's quarantine; only offered after that run verified. | None: irreversible by design |
| `update_plugin` / `reinstall_plugin` | An installed WordPress.org plugin at the reviewed version (never AI Website Doctor). The package comes only from `downloads.wordpress.org` and every installed file must match the official per-file checksums for the target version. The site's home page is loaded before and after; if it breaks, the previous directory is put back immediately. | The previous plugin directory |
| `install_plugin` | A WordPress.org plugin slug that is not installed, at an exact version, verified the same way; optional activation is undone if the site breaks. | Restore deactivates it and moves it to the quarantine |
| `set_hardening` | One protection measure on or off. `.htaccess` measures write only between `# BEGIN/END AI Website Doctor hardening` markers (the injection detector trusts that block only while it matches the digest the plugin recorded), are tested on the server, and the root rules are removed again if the home page returns 5xx. Runtime measures are plugin filters. | Previous on/off state |
| `restore_run` | Requested from the app for a finished run that still has its quarantine: reverses that run's applied steps under the same conflict rule as a local restore. | None (it is the undo) |

Invariants:

- **One approval covers exactly the reviewed list.** The plan digest binds every step, path, digest and optional choice; a changed scan invalidates the approval. The grant is a one-time `RepairApproval` with method `compromise_cleanup`, consumed when dispatched. It can never authorize a normal repair (its operations are outside the repair allowlist, so `authorizeRepairExecution` reports UNSUPPORTED), and normal grants cannot authorize a cleanup.
- **The plugin revalidates everything** (shape, path confinement under the real site root, no symlinked components, digests) immediately before each change. Writes go to an exclusive temporary file in the same directory followed by `rename`; results are re-read and verified.
- **Undo before change.** The quarantine lives above the web root when that directory is writable, otherwise in a randomly named `wp-content` directory with deny rules; stored files have a `.bin` name and are never executable. Restoring a run reverses only steps whose target still has the state the cleanup left, so later edits are kept and reported as conflicts.
- **Verification from outside.** After the run the plugin rescans and syncs, and the central app re-checks the site as a browser, Googlebot and a search visitor. A run is `verified` only when every step applied, no critical or high integrity finding remains, and the outside check is clean.
- **Self-healing is opt-in per site and limited** to `quarantine_file`, `restore_core_file`, `remove_htaccess_rules`, `reinstall_plugin` and `purge_page_cache`, at most three automatic runs per 24 hours; beyond that the owner is told the site keeps being reinfected. Salt rotation, user changes, plugin removal, quarantine purges, installs and protection changes always need a person. Automatic plugin updates (opt-in) run at most daily and never while compromise findings are open. Automatic runs are recorded as `standing-policy` approvals in the audit log.
- **Maintenance runs (plugin updates and reinstalls) roll back automatically**: unlike malware removal, putting the previous plugin version back is safe, so a failed checksum check or a broken home page restores it inside the same step. They are verified by site availability and the absence of new PHP fatal errors, not by the compromise checks.
- **No automatic rollback after a failed verification.** Rolling back a partial cleanup would reinstall malware, so changes are kept and the remaining findings are reported. Restore is an explicit administrator action in the plugin.

Accepted residual risk: the plugin's check-then-rename is not compare-and-swap (see the feasibility spike below), and code running on a compromised site can interfere with the plugin itself. Both are accepted for this playbook because the competing writer is the malware being removed, every change has a stored undo copy, and success is judged from outside the site. A write that is immediately overwritten again is reported as a failure ("something on the server is rewriting it").

## Eligible future adapter

A remote write adapter must use either a provider API that documents equivalent race-safe conditional file operations, or a separately installed host-side agent. Generic SSH command execution and SFTP writes are not acceptable substitutes.

For a host-side agent, the initial supported platform should be Linux with a filesystem and kernel that support the required primitives. The agent must:

- Run as a dedicated account with access limited to one configured site root; it must not run arbitrary shell commands or accept arbitrary paths, code, or scripts.
- Open and retain a trusted root directory handle, then resolve each target relative to that handle with `openat2` constraints equivalent to `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`. Reject unsupported kernels/filesystems instead of falling back to string checks or check-then-open traversal.
- Bind the approved operation to a canonical relative target, expected pre-change object identity and content digest, exact intended content/metadata, site and connection identity, approval record, expiry, and one-time nonce. A change to any bound value invalidates the approval.
- Create an operation-specific recovery point before mutation. Store the exact prior bytes and required metadata outside the target path, durably flush it, and verify its digest and completeness before proceeding.
- Write to a new exclusive, no-follow temporary file in the already-open parent directory and flush it before commit. Commit only through a primitive that atomically enforces the approved expected pre-change object/digest, or after a mechanism has demonstrably fenced every other writer to that target. Ordinary `lstat`/hash followed by `rename` is not compare-and-swap: another process can replace the target between the check and rename. `renameat2` by itself does not solve this for replacement of an existing file. If the provider/filesystem cannot enforce the conditional commit or all-writer exclusion, refuse the operation.
- Verify the resulting object through a fresh safe open and compare its content and metadata to the approved result. Report evidence to the central app; an attempted write is never reported as successful without verification.
- Roll back only with a compare-and-swap condition against the exact post-write object, under the same writer-fencing guarantee as the original commit. If a person or process has changed it since application, preserve the current file, report rollback failure, and require manual recovery rather than overwriting newer work.
- Serialize competing changes per site target, enforce request size/time limits, redact credentials and file contents from logs, and durably audit approval, recovery, write, verification, rollback, and failure outcomes.

The central app must independently enforce the hosting operation allowlist, ownership, approval and expiry, one-time execution, and required recovery/verification states. Hosting grants must never be accepted as WordPress repair grants. The WordPress task-polling and batch APIs must continue to reject hosting proposals.

## Feasibility spike

The reproducible probe in [spikes/hosting-write-safety](../spikes/hosting-write-safety/README.md) passed on Docker Linux `7.0.14-linuxkit` (`x86_64`). It confirmed that `openat2` can constrain lookup beneath a held root and reject traversal/symlinks. It also deterministically reproduced a lost concurrent update: `rename` overwrote a non-cooperating writer's change despite an advisory `flock` on the old inode. `RENAME_NOREPLACE` refused an existing target, so it did not provide compare-and-swap replacement.

Conclusion: path confinement is feasible for a Linux host-side agent on supported kernels, but safe conditional writes are **not** established by generic filesystem operations. No production provider API or all-writer fence has been validated. Until one is independently proven for a hosting plan, that connection must not perform remote writes. This is a technical gate for the present adapter, not a requirement that users make their credentials or product workflow read-only forever.

## Release gates

Do not enable a write operation until all of these are true:

1. The adapter and central authorization path implement the invariants above; unsupported platforms fail closed.
2. Tests deterministically exercise symlink swaps, parent-directory replacement, target replacement, concurrent writers, interrupted writes, stale/replayed approvals, recovery corruption, failed verification, and rollback conflicts.
3. A disposable-host integration suite proves both the broken and healthy controls, including symlink/parent swaps and that unrelated files and concurrent user changes are preserved. The concurrency test must exercise the actual conditional-commit or writer-fencing primitive, not just an application-level lock.
4. Audit records identify the exact target and lifecycle state without storing secrets or unnecessary file contents.
5. The operation has an explicit per-operation recovery and verification strategy and a reviewed operational recovery procedure.

Until every gate is met, hosting repair operations must return an explicit not-implemented response and make no remote change. The generic lifecycle helper is not authorization to write and is not proof that an adapter satisfies this contract.
