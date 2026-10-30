"""Sandbox-only crash-recovery journal tests; no network or host access."""
import hashlib
import json
import os

import pytest

import recovery_journal as journal


CID = "a" * 32
BEFORE = hashlib.sha256(b"before").hexdigest()
AFTER = hashlib.sha256(b"after").hexdigest()


def prepare(tmp_path):
    journal.record_intent(tmp_path, CID, "LOG-001", BEFORE, AFTER)


def test_prepared_intent_survives_and_blocks(tmp_path):
    prepare(tmp_path)
    assert journal.unresolved_changes(tmp_path) == [
        {"change_id": CID, "finding_id": "LOG-001", "status": "prepared"}
    ]


@pytest.mark.parametrize("status", ["applied", "verification_failed_rolled_back"])
def test_verified_outcomes_clear_pending(tmp_path, status):
    prepare(tmp_path)
    journal.record_outcome(tmp_path, CID, status)
    assert journal.unresolved_changes(tmp_path) == []


def test_rollback_failure_requires_manual_review(tmp_path):
    prepare(tmp_path)
    journal.record_outcome(tmp_path, CID, "rollback_failed")
    assert journal.unresolved_changes(tmp_path)[0]["status"] == "rollback_failed"


def test_corrupt_or_truncated_journal_fails_closed(tmp_path):
    prepare(tmp_path)
    (tmp_path / f"journal-{CID}.json").write_text("{")
    with pytest.raises(journal.RecoveryJournalError):
        journal.unresolved_changes(tmp_path)


def test_symlink_journal_fails_closed(tmp_path):
    real = tmp_path / "outside.json"
    real.write_text("{}")
    (tmp_path / f"journal-{CID}.json").symlink_to(real)
    with pytest.raises(journal.RecoveryJournalError):
        journal.unresolved_changes(tmp_path)


def test_durable_backup_is_private_and_cannot_overwrite(tmp_path):
    path = tmp_path / "backup.bin"
    journal.write_durable_backup(path, b"secret-test-bytes")
    assert path.read_bytes() == b"secret-test-bytes"
    assert (path.stat().st_mode & 0o777) == 0o600
    with pytest.raises(journal.RecoveryJournalError):
        journal.write_durable_backup(path, b"overwritten")
    assert path.read_bytes() == b"secret-test-bytes"


def test_invalid_identifiers_and_transitions_are_rejected(tmp_path):
    with pytest.raises(journal.RecoveryJournalError):
        journal.record_intent(tmp_path, "../unsafe", "LOG-001", BEFORE, AFTER)
    prepare(tmp_path)
    with pytest.raises(journal.RecoveryJournalError):
        journal.record_outcome(tmp_path, CID, "unknown")
    journal.record_outcome(tmp_path, CID, "applied")
    with pytest.raises(journal.RecoveryJournalError):
        journal.record_outcome(tmp_path, CID, "applied")


def test_failed_atomic_replace_cleans_temp_and_never_reports_success(tmp_path, monkeypatch):
    def fail_replace(*_args):
        raise OSError("simulated disk failure")
    monkeypatch.setattr(journal.os, "replace", fail_replace)
    with pytest.raises(OSError):
        prepare(tmp_path)
    assert not (tmp_path / f"journal-{CID}.json").exists()
    assert list(tmp_path.glob(".remedyops-journal-*")) == []


def test_recovery_scan_does_not_change_target(tmp_path):
    target = tmp_path / "target.conf"
    target.write_bytes(b"partial=change\n")
    prepare(tmp_path)
    journal.unresolved_changes(tmp_path)
    assert target.read_bytes() == b"partial=change\n"


def test_rollback_intent_has_distinct_verified_outcome(tmp_path):
    journal.record_intent(
        tmp_path, CID, "LOG-001", AFTER, BEFORE, operation="rollback"
    )
    journal.record_outcome(tmp_path, CID, "rolled_back")
    assert journal.unresolved_changes(tmp_path) == []
    obj = json.loads((tmp_path / f"journal-{CID}.json").read_text())
    assert obj["operation"] == "rollback"
    assert obj["status"] == "rolled_back"


def test_mismatched_journal_operation_outcomes_fail_closed(tmp_path):
    prepare(tmp_path)
    with pytest.raises(journal.RecoveryJournalError):
        journal.record_outcome(tmp_path, CID, "rolled_back")
    assert journal.unresolved_changes(tmp_path)[0]["status"] == "prepared"
    (tmp_path / f"journal-{CID}.json").unlink()
    journal.record_intent(
        tmp_path, CID, "LOG-001", AFTER, BEFORE, operation="rollback"
    )
    with pytest.raises(journal.RecoveryJournalError):
        journal.record_outcome(tmp_path, CID, "applied")
    assert journal.unresolved_changes(tmp_path)[0]["status"] == "prepared"


def test_legacy_apply_journal_without_operation_still_loads(tmp_path):
    prepare(tmp_path)
    path = tmp_path / f"journal-{CID}.json"
    obj = json.loads(path.read_text())
    obj.pop("operation")
    path.write_text(json.dumps(obj))
    journal.record_outcome(tmp_path, CID, "applied")
    assert journal.unresolved_changes(tmp_path) == []
