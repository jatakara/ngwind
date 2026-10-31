"""Durable sandbox state regression tests; never contact SSH or production."""
import importlib.util
import json
import os
import shutil
import uuid
from pathlib import Path

import pytest
from fastapi import HTTPException

import recovery_journal as journal


@pytest.fixture
def sandbox_app(monkeypatch, tmp_path):
    source = Path(__file__).resolve().parents[1]
    isolated = tmp_path / "isolated_app"
    isolated.mkdir()
    shutil.copy2(source / "app.py", isolated / "app.py")
    monkeypatch.syspath_prepend(str(source))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.delenv("REMEDYOPS_ENABLE_SSH_DIAGNOSTICS", raising=False)
    spec = importlib.util.spec_from_file_location(
        f"remedyops_state_durability_{uuid.uuid4().hex}", isolated / "app.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_durable_state_is_private_and_fsyncs_file_and_directory(tmp_path, monkeypatch):
    path = tmp_path / "change-test.json"
    real_fsync = os.fsync
    calls = []

    def counting_fsync(fd):
        calls.append(fd)
        return real_fsync(fd)

    monkeypatch.setattr(journal.os, "fsync", counting_fsync)
    journal.write_durable_state(path, b'{"status":"applied"}')
    journal.write_durable_state(path, b'{"status":"rolled_back"}')
    assert json.loads(path.read_text()) == {"status": "rolled_back"}
    assert path.stat().st_mode & 0o777 == 0o600
    assert len(calls) == 4  # file + directory for each durable write


def test_durable_state_rejects_symlink_and_hardlink(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"outside")
    symlink = tmp_path / "change-symlink.json"
    symlink.symlink_to(outside)
    with pytest.raises(journal.RecoveryJournalError):
        journal.write_durable_state(symlink, b"bad")
    hardlink = tmp_path / "change-hardlink.json"
    os.link(outside, hardlink)
    with pytest.raises(journal.RecoveryJournalError):
        journal.write_durable_state(hardlink, b"bad")
    assert outside.read_bytes() == b"outside"


def test_durable_state_directory_fsync_error_is_not_silenced(tmp_path, monkeypatch):
    path = tmp_path / "change-test.json"
    real_fsync = os.fsync
    calls = 0

    def fail_second_fsync(fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated directory fsync failure")
        return real_fsync(fd)

    monkeypatch.setattr(journal.os, "fsync", fail_second_fsync)
    with pytest.raises(OSError, match="directory fsync"):
        journal.write_durable_state(path, b"new")
    # Rename may already have happened. Caller must treat the result as uncertain.
    assert calls == 2


def test_apply_state_persistence_failure_blocks_later_mutations(
    sandbox_app, monkeypatch
):
    app = sandbox_app
    target = app.TARGET / "logging.conf"
    plan = app.plan(app.PlanIn(finding_ids=["LOG-001"]))
    real_writer = app.write_durable_state

    def fail_change_record(path, data):
        if path.name.startswith("change-"):
            raise OSError("simulated state disk failure")
        return real_writer(path, data)

    monkeypatch.setattr(app, "write_durable_state", fail_change_record)
    with pytest.raises(HTTPException) as error:
        app.apply(app.ApplyIn(plan_id=plan["plan_id"], approved=True))
    assert error.value.status_code == 503
    assert b"audit_enabled=yes" in target.read_bytes()
    assert len(journal.unresolved_changes(app.STATE)) == 1
    second = app.plan(app.PlanIn(finding_ids=["PERM-001"]))
    with pytest.raises(HTTPException) as blocked:
        app.apply(app.ApplyIn(plan_id=second["plan_id"], approved=True))
    assert blocked.value.status_code == 409


def test_rollback_state_persistence_failure_leaves_prepared_intent(
    sandbox_app, monkeypatch
):
    app = sandbox_app
    target = app.TARGET / "logging.conf"
    original = target.read_bytes()
    plan = app.plan(app.PlanIn(finding_ids=["LOG-001"]))
    change = app.apply(app.ApplyIn(plan_id=plan["plan_id"], approved=True))["changes"][0]
    real_writer = app.write_durable_state

    def fail_change_record(path, data):
        if path.name.startswith("change-"):
            raise OSError("simulated rollback state disk failure")
        return real_writer(path, data)

    monkeypatch.setattr(app, "write_durable_state", fail_change_record)
    with pytest.raises(HTTPException) as error:
        app.rollback(app.RollbackIn(change_ids=[change["change_id"]], approved=True))
    assert error.value.status_code == 503
    assert target.read_bytes() == original
    assert app.load("change", change["change_id"])["status"] == "applied"
    pending = journal.unresolved_changes(app.STATE)
    assert len(pending) == 1 and pending[0]["status"] == "prepared"
