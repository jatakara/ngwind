# Sandbox crash-recovery runbook (development only)

The recovery journal is a **detection and fail-closed gate**, not an automatic
rollback mechanism. Do not use this prototype for unattended production changes.

## Write sequence

1. Capture and fsync a mode-0600 backup.
2. Fsync a `prepared` intent record in `.state/journal-<change_id>.json`.
3. Change the sandbox target and verify its contents.
4. Persist the change result.
5. Finalize the intent as `applied`, `verification_failed_rolled_back`,
   or `rollback_failed`.

A crash between steps 2 and 5 leaves a `prepared` journal. A failed restore
leaves `rollback_failed`. Either condition blocks subsequent `/api/apply`
requests. Invalid, truncated, or unreadable journal files also block writes.

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

- No automatic crash recovery, process-level locking, or multi-worker fencing.
- The journal is not tamper-evident; it requires trusted filesystem ownership.
- Target writes are not atomic; an interrupted write can leave partial data.
- A completed journal does not imply full service health or durable audit events.
- The backup and journal use fsync; other state records still need durability
  hardening and transactional design.
- `/api/apply` checks pending intents under a process-local lock only.
  Multiple workers remain **unsupported** until distributed fencing is added.

## Rollback of this code change

Revert the PR only in an isolated development environment after verifying no
unresolved intent exists. Removing the guard without recovering interrupted
changes would reintroduce unsafe write behavior.
