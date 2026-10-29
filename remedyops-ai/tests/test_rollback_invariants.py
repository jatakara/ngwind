"""Regression tests for sandbox rollback behavior; no remote connections.

Post-apply verification failure must restore original bytes or report rollback_failed.
"""

import importlib.util
import shutil
import uuid
from pathlib import Path

import pytest
from fastapi import HTTPException


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
        f"remedyops_rollback_test_{uuid.uuid4().hex}", isolated / "app.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_apply_requires_explicit_approval(sandbox_app):
    app = sandbox_app
    target = app.TARGET / "logging.conf"
    original = target.read_bytes()
    plan = app.plan(app.PlanIn(finding_ids=["LOG-001"]))
    with pytest.raises(HTTPException) as exc:
        app.apply(app.ApplyIn(plan_id=plan["plan_id"], approved=False))
    assert exc.value.status_code == 400
    assert target.read_bytes() == original


def test_high_risk_rule_is_not_applied(sandbox_app):
    app = sandbox_app
    target = app.TARGET / "ssh.conf"
    original = target.read_bytes()
    plan = app.plan(app.PlanIn(finding_ids=["SSH-001"]))
    outcome = app.apply(app.ApplyIn(plan_id=plan["plan_id"], approved=True))
    assert outcome["entries"][0]["status"] == "blocked_high_risk"
    assert target.read_bytes() == original


def test_failed_verification_restores_original_bytes(sandbox_app, monkeypatch):
    app = sandbox_app
    target = app.TARGET / "logging.conf"
    original = target.read_bytes()
    plan = app.plan(app.PlanIn(finding_ids=["LOG-001"]))
    monkeypatch.setattr(app, "config", lambda _data: {})
    outcome = app.apply(app.ApplyIn(plan_id=plan["plan_id"], approved=True))
    assert outcome["changes"][0]["status"] == "verification_failed_rolled_back"
    assert target.read_bytes() == original


def test_restore_failure_is_explicit_and_not_marked_applied(sandbox_app, monkeypatch):
    app = sandbox_app
    target = app.TARGET / "logging.conf"
    original = target.read_bytes()
    plan = app.plan(app.PlanIn(finding_ids=["LOG-001"]))
    monkeypatch.setattr(app, "config", lambda _data: {})
    monkeypatch.setattr(
        app, "restore_backup_after_verification_failure",
        lambda *_args: "rollback_failed",
    )
    outcome = app.apply(app.ApplyIn(plan_id=plan["plan_id"], approved=True))
    assert outcome["changes"][0]["status"] == "rollback_failed"
    assert target.read_bytes() != original


def test_interrupted_intent_blocks_subsequent_apply(sandbox_app):
    import recovery_journal as journal

    app = sandbox_app
    target = app.TARGET / "logging.conf"
    original = target.read_bytes()
    planned = app.plan(app.PlanIn(finding_ids=["LOG-001"]))
    cid = uuid.uuid4().hex
    journal.record_intent(app.STATE, cid, "LOG-001", app.sha(original), app.sha(b"modified"))
    with pytest.raises(HTTPException) as exc:
        app.apply(app.ApplyIn(plan_id=planned["plan_id"], approved=True))
    assert exc.value.status_code == 409
    assert target.read_bytes() == original


def test_successful_apply_finalizes_intent(sandbox_app):
    import recovery_journal as journal

    app = sandbox_app
    planned = app.plan(app.PlanIn(finding_ids=["LOG-001"]))
    outcome = app.apply(app.ApplyIn(plan_id=planned["plan_id"], approved=True))
    assert outcome["changes"][0]["status"] == "applied"
    assert journal.unresolved_changes(app.STATE) == []


def test_rollback_failure_blocks_future_changes(sandbox_app, monkeypatch):
    import recovery_journal as journal

    app = sandbox_app
    first = app.plan(app.PlanIn(finding_ids=["LOG-001"]))
    monkeypatch.setattr(app, "config", lambda _data: {})
    monkeypatch.setattr(
        app, "restore_backup_after_verification_failure", lambda *_args: "rollback_failed"
    )
    outcome = app.apply(app.ApplyIn(plan_id=first["plan_id"], approved=True))
    assert outcome["changes"][0]["status"] == "rollback_failed"
    assert journal.unresolved_changes(app.STATE)[0]["status"] == "rollback_failed"
    second = app.plan(app.PlanIn(finding_ids=["PERM-001"]))
    with pytest.raises(HTTPException) as exc:
        app.apply(app.ApplyIn(plan_id=second["plan_id"], approved=True))
    assert exc.value.status_code == 409


def test_atomic_write_failure_keeps_intent_pending_and_target_unchanged(sandbox_app, monkeypatch):
    import atomic_config
    import recovery_journal as journal

    app = sandbox_app
    target = app.TARGET / "logging.conf"
    original = target.read_bytes()
    planned = app.plan(app.PlanIn(finding_ids=["LOG-001"]))

    def reject_write(*_args):
        raise atomic_config.AtomicConfigError("injected sandbox write failure")

    monkeypatch.setattr(app, "atomic_replace_config", reject_write)
    with pytest.raises(HTTPException) as exc:
        app.apply(app.ApplyIn(plan_id=planned["plan_id"], approved=True))
    assert exc.value.status_code == 503
    assert target.read_bytes() == original
    assert journal.unresolved_changes(app.STATE)[0]["status"] == "prepared"
    with pytest.raises(HTTPException) as blocked:
        app.apply(app.ApplyIn(plan_id=planned["plan_id"], approved=True))
    assert blocked.value.status_code == 409


def test_plan_rejects_symlink_config_before_resolution(sandbox_app, tmp_path):
    app = sandbox_app
    target = app.TARGET / "logging.conf"
    target.unlink()
    outside = tmp_path / "outside.conf"
    outside.write_bytes(b"outside=unchanged\\n")
    target.symlink_to(outside)
    with pytest.raises(HTTPException) as exc:
        app.plan(app.PlanIn(finding_ids=["LOG-001"]))
    assert exc.value.status_code == 400
    assert outside.read_bytes() == b"outside=unchanged\\n"
