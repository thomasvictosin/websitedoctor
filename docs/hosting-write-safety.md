# Hosting write-safety contract

## Current boundary

Hosting repair proposals are review records only. The current SFTP adapter performs inspection and no remote writes are implemented. This is the current capability boundary, not a permanent product rule that SFTP must always be read-only. When a technically safe writer is available, the product should let the user choose whether to write/overwrite and require a clear warning plus explicit confirmation. No route, task, approval grant, or WordPress agent may execute a hosting proposal today.

SFTP host-key pinning and DNS validation authenticate the connection endpoint; configured-root checks and symlink checks constrain the requested path at the time of inspection. They do not bind later file operations to the same filesystem objects. A remote user or process can replace a checked path component between `lstat` and a subsequent SFTP write. SFTP does not provide the descriptor-relative, no-follow path traversal required to close that race, so adding another pre-write check would not make writes safe.

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
