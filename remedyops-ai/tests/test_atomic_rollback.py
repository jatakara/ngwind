"""Sandbox-only rollback crash-safety regression tests; no SSH or network."""
import importlib.util
import json
import shutil
import uuid
from pathlib import Path

import pytest
from fastapi import HTTPException

import atomic_config
import recovery_journal


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
        f"remedyops_atomic_rollback_{uuid.uuid4().hex}", isolated / "app.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def applied_change(app):
    target = app.TARGET / "logging.conf"
    original = target.read_bytes()
    plan = app.plan(app.PlanIn(finding_ids=["LOG-001"]))
    result = app.apply(app.ApplyIn(plan_id=plan["plan_id"], approved=True))
    rec = result["changes"][0]
    assert rec["status"] == "applied"
    return target, original, rec


def test_atomic_rollback_records_completed_journal(sandbox_app):
    app = sandbox_app
    target, original, rec = applied_change(app)
    result = app.rollback(app.RollbackIn(change_ids=[rec["change_id"]], approved=True))
    assert result["results"] == [{"id": rec["change_id"], "status": "rolled_back"}]
    assert target.read_bytes() == original
    assert recovery_journal.unresolved_changes(app.STATE) == []
    journals = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in app.STATE.glob("journal-*.json")
    ]
    rollback_journals = [j for j in journals if j.get("operation") == "rollback"]
    assert len(rollback_journals) == 1
    assert rollback_journals[0]["status"] == "rolled_back"
    assert rollback_journals[0]["after_hash"] == app.sha(original)
    assert app.load("change", rec["change_id"])["status"] == "rolled_back"
    assert app.rollback(app.RollbackIn(change_ids=[rec["change_id"]], approved=True))[
        "results"
    ][0]["status"] == "not_eligible"


def test_atomic_rollback_failure_before_rename_keeps_prepared_intent(
    sandbox_app, monkeypatch
):
    app = sandbox_app
    target, _, rec = applied_change(app)
    modified = target.read_bytes()

    def fail_before_rename(*_args):
        raise atomic_config.AtomicConfigError("simulated write failure")

    monkeypatch.setattr(app, "atomic_replace_config", fail_before_rename)
    with pytest.raises(HTTPException) as error:
        app.rollback(app.RollbackIn(change_ids=[rec["change_id"]], approved=True))
    assert error.value.status_code == 503
    assert target.read_bytes() == modified
    assert app.load("change", rec["change_id"])["status"] == "applied"
    pending = recovery_journal.unresolved_changes(app.STATE)
    assert len(pending) == 1 and pending[0]["status"] == "prepared"
    assert json.loads(
        (app.STATE / f"journal-{pending[0]['change_id']}.json").read_text()
    )["operation"] == "rollback"


def test_post_rename_error_never_claims_rollback_success(sandbox_app, monkeypatch):
    app = sandbox_app
    target, original, rec = applied_change(app)
    real_atomic = app.atomic_replace_config

    def replace_then_fail(*args):
        real_atomic(*args)
        raise atomic_config.AtomicConfigError("simulated post-rename sync error")

    monkeypatch.setattr(app, "atomic_replace_config", replace_then_fail)
    with pytest.raises(HTTPException) as error:
        app.rollback(app.RollbackIn(change_ids=[rec["change_id"]], approved=True))
    assert error.value.status_code == 503
    assert target.read_bytes() == original
    assert app.load("change", rec["change_id"])["status"] == "applied"
    assert recovery_journal.unresolved_changes(app.STATE)[0]["status"] == "prepared"
    second = app.plan(app.PlanIn(finding_ids=["PERM-001"]))
    with pytest.raises(HTTPException) as blocked:
        app.apply(app.ApplyIn(plan_id=second["plan_id"], approved=True))
    assert blocked.value.status_code == 409


def test_corrupt_backup_rejected_without_mutation_or_rollback_intent(sandbox_app):
    app = sandbox_app
    target, _, rec = applied_change(app)
    modified = target.read_bytes()
    (app.STATE / f"backup-{rec['change_id']}.bin").write_bytes(b"corrupt")
    with pytest.raises(HTTPException) as error:
        app.rollback(app.RollbackIn(change_ids=[rec["change_id"]], approved=True))
    assert error.value.status_code == 409
    assert target.read_bytes() == modified
    assert recovery_journal.unresolved_changes(app.STATE) == []
    assert not any(
        json.loads(p.read_text()).get("operation") == "rollback"
        for p in app.STATE.glob("journal-*.json")
    )


def test_symlink_backup_rejected_without_reading_outside(sandbox_app, tmp_path):
    app = sandbox_app
    target, _, rec = applied_change(app)
    modified = target.read_bytes()
    backup = app.STATE / f"backup-{rec['change_id']}.bin"
    backup.unlink()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"unrelated secret bytes")
    backup.symlink_to(outside)
    with pytest.raises(HTTPException) as error:
        app.rollback(app.RollbackIn(change_ids=[rec["change_id"]], approved=True))
    assert error.value.status_code == 409
    assert target.read_bytes() == modified
    assert outside.read_bytes() == b"unrelated secret bytes"


def test_unresolved_apply_intent_blocks_rollback(sandbox_app):
    app = sandbox_app
    target, _, rec = applied_change(app)
    modified = target.read_bytes()
    recovery_journal.record_intent(
        app.STATE, uuid.uuid4().hex, "PERM-001",
        app.sha(b"before"), app.sha(b"after"),
    )
    with pytest.raises(HTTPException) as error:
        app.rollback(app.RollbackIn(change_ids=[rec["change_id"]], approved=True))
    assert error.value.status_code == 409
    assert target.read_bytes() == modified
    assert app.load("change", rec["change_id"])["status"] == "applied"
