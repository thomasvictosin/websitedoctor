# Hosting write-safety feasibility spike

This disposable Linux probe tests two distinct questions without connecting to a hosting account or changing any website:

1. Can Linux resolve a target beneath a held document-root handle while refusing symlinks and traversal? The probe uses `openat2` with `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`, and `RESOLVE_NO_MAGICLINKS`; unsupported kernels fail closed.
2. Do ordinary rename and advisory locking provide compare-and-swap behavior against another writer? The probe coordinates two local processes in a fresh temporary directory. One holds `flock` on the old file, observes the original contents, and stages an approved replacement. A second process atomically replaces the target with a user change before the first process commits with `rename`. It also verifies that `RENAME_NOREPLACE` refuses to replace an existing target.

Run on a machine with Docker:

```sh
./spikes/hosting-write-safety/run-linux-spike.sh
```

Docker runs the compiler and probe in a disposable Linux container. The only test data is created under that container's `/tmp`; the source is mounted read-only. The probe does not implement a repair adapter.

## Observed result

The probe passed in the Docker Linux environment available for this spike (`Linux 7.0.14-linuxkit`, `x86_64`):

- `openat2` opened a regular file beneath the held site-root descriptor and rejected both `../` traversal and a symlink.
- A non-cooperating process replaced a validated target; the staged `rename` then overwrote that change even though `flock` was held on the original inode.
- `RENAME_NOREPLACE` returned `EEXIST` for an existing target, confirming it cannot implement conditional replacement of that target.

This is a **split feasibility result**: constrained path resolution is feasible on this tested Linux kernel, but the tested local filesystem primitives do not provide safe replacement against non-cooperating writers. The spike did not evaluate a hosting provider's conditional-write API or prove a production all-writer fence. It does not authorize or enable remote writes.

## Interpretation

`openat2` can provide a useful Linux path-resolution boundary for a host-side agent, subject to a minimum kernel and filesystem support check. It does not make a later write conditional on the contents or identity inspected earlier.

On ordinary POSIX file operations, `rename` atomically replaces an existing pathname but does not compare the destination with an approved version. `RENAME_NOREPLACE` only protects a destination that must not already exist. `flock` is advisory and tied to the opened file description/inode; it does not prevent an unrelated writer from replacing the pathname.

Therefore this spike does **not** justify enabling writes. A production design still needs a provider's documented conditional update primitive or a credible guarantee that every writer is fenced through the agent. If neither can be guaranteed for a hosting plan, remote repair is not feasible for that plan.

The probe establishes behavior only for the Linux kernel and filesystem used by its Docker engine. It is not a production security certification. The relevant syscall guarantees and limits are documented in the Linux [`openat2(2)`](https://man7.org/linux/man-pages/man2/openat2.2.html), [`rename(2)`](https://man7.org/linux/man-pages/man2/rename.2.html), and [`flock(2)`](https://man7.org/linux/man-pages/man2/flock.2.html) manual pages.
