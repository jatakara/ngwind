# Sandbox crash-recovery runbook (development only)

The recovery journal is a **detection and fail-closed gate**, not an automatic
rollback mechanism. Do not use this prototype for unattended production changes.

## Write sequence

1. Capture and fsync a mode-0600 backup.
2. Fsync a `prepared` intent record in `.state/journal-<change_id>.json`.
3. For /api/apply, verify the expected SHA-256 and atomically replace the sandbox target using a same-directory mode-preserving temporary file, fsync, rename, directory fsync, and exact-byte verification. Then verify the intended configuration.
4. Persist the change result.
5. Finalize the intent as `applied`, `verification_failed_rolled_back`,
   or `rollback_failed`.

A crash between steps 2 and 5 leaves a `prepared` journal. A failed restore
leaves `rollback_failed`. Either condition blocks subsequent `/api/apply` and `/api/rollback`
requests. Invalid, truncated, or unreadable journal files also block writes.

## Approved rollback sequence (sandbox only)

1. Require explicit approval, the shared process lock, and zero unresolved journals.
2. Validate the change record and target hash against the applied state; reject
   missing, symlinked, or corrupted original backups.
3. Persist a separate mode-0600 backup of the current (post-apply) bytes, then
   fsync a **rollback** journal with status `prepared` before modifying the target.
4. Atomically replace the target with the verified original backup using the
   expected current SHA-256 as a precondition.
5. Persist the original change record as `rolled_back`, then finalize the
   rollback journal as `rolled_back`. The journal outcome is distinct from
   an apply outcome. Historical apply journals without `operation` still load.

Any exception during or after atomic replacement leaves the rollback journal
`prepared`, blocks both new apply and rollback requests, and requires manual
inspection. A returned HTTP 503 **does not prove the original target survived**.
This workflow does not guarantee service recovery or preserve ACLs/xattrs.

## Manual investigation

1. Disable write access to the sandbox API. Do not delete journal files to
   bypass the block.
2. Make a forensic copy of the `.state` directory and sandbox target.
3. Identify unresolved records without modifying files:
   `python -c "from pathlib import Path; from recovery_journal import unresolved_changes; print(unresolved_changes(Path('.state')))"`
4. Compare the target and backup hashes against the journal and corresponding
   `change-<id>.json` record. Treat absent or mismatched backups as unsafe.
5. Review the desired target state, any partial write, and the application
   change history with an authorized operator.
6. Recover using an approved manual procedure and verify the resulting file
   bytes and service health. Journal clearance requires a separately reviewed
   recovery workflow; this PR intentionally does not expose a force-clear API.

## Limitations

- No automatic crash recovery or distributed multi-worker fencing. This PR adds a POSIX flock for cooperating local processes sharing the same .state volume; separate hosts, unshared volumes, or filesystems without reliable flock are unsupported.
- The journal is not tamper-evident; it requires trusted filesystem ownership.
- /api/apply and /api/rollback target writes use the same atomic helper only for cooperating local POSIX filesystem users. External writers, cross-host mounts, and unexpected metadata (ACLs/SELinux labels/xattrs) are not supported. The helper requires a regular single-link target owned by the sandbox process and preserves POSIX mode, uid, and gid, not extended metadata.
- An atomic replacement error may happen **after rename** (e.g., directory fsync or post-write verification). In that case the recovery journal remains prepared and the operator must inspect both the target and backup; do not assume the original file survived.
- A completed journal does not imply full service health or durable audit events.
- Plan and change JSON state records now use private (0600), same-directory
  atomic replacement with file and directory fsync. Unsafe symlink or hardlinked
  records are rejected. If change-record persistence fails, the prepared intent
  remains unresolved and further apply/rollback requests are blocked.
- The SQL audit events and JSON state/journal updates are **not one database
  transaction**. An audit commit or plan-status update can still fail after a
  verified target mutation; an HTTP error does not imply no change occurred.
  Compare target hashes, change records, journals, and audit entries manually.
  No automatic reconciliation or tamper-evident audit guarantee is provided.
- `/api/plan`, `/api/apply`, and `/api/rollback` share a non-blocking local process/file lock. Contention returns HTTP 409; an unsafe/unavailable lock returns HTTP 503. Lock files are mode 0600 and symlinks are rejected. Multiple workers on separate hosts remain **unsupported** until transactional distributed fencing is added.
- Lock ownership is advisory. Never delete/replace `.state/.remedyops.lock` while processes are active; doing so can split the lock domain.

## Rollback of this code change

Revert the PR only in an isolated development environment after verifying no
unresolved intent exists. Removing the guard without recovering interrupted
changes would reintroduce unsafe write behavior.
