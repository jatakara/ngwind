"""Sandbox audit/journal ordering tests; no SSH or production targets."""
import importlib.util
import shutil
import uuid
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError

from recovery_journal import unresolved_changes


@pytest.fixture
def sandbox_app(monkeypatch, tmp_path):
    source = Path(__file__).resolve().parents[1]
    isolated = tmp_path / "isolated_app"
    isolated.mkdir()
    shutil.copy2(source / "app.py", isolated / "app.py")
    monkeypatch.syspath_prepend(str(source))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'audit.db'}")
    monkeypatch.delenv("REMEDYOPS_ENABLE_SSH_DIAGNOSTICS", raising=False)
    spec = importlib.util.spec_from_file_location(
        f"remedyops_audit_{uuid.uuid4().hex}", isolated / "app.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_apply_audit_failure_leaves_intent_prepared_and_stops_batch(
    sandbox_app, monkeypatch
):
    app = sandbox_app
    second = app.TARGET / "permissions.conf"
    second_before = second.read_bytes()
    plan = app.plan(app.PlanIn(finding_ids=["LOG-001", "PERM-001"]))
    real_event = app.event

    def fail_change_audit(action, detail):
        if action == "change.outcome":
            raise SQLAlchemyError("injected audit commit failure")
        return real_event(action, detail)

    monkeypatch.setattr(app, "event", fail_change_audit)
    with pytest.raises(HTTPException) as exc:
        app.apply(app.ApplyIn(plan_id=plan["plan_id"], approved=True))
    assert exc.value.status_code == 503
    assert second.read_bytes() == second_before
    assert b"audit_enabled=yes" in (app.TARGET / "logging.conf").read_bytes()
    pending = unresolved_changes(app.STATE)
    assert len(pending) == 1 and pending[0]["status"] == "prepared"
    assert app.changes()[0]["status"] == "applied"
    with pytest.raises(HTTPException) as blocked:
        app.apply(app.ApplyIn(plan_id=plan["plan_id"], approved=True))
    assert blocked.value.status_code == 409


def test_rollback_audit_failure_keeps_rollback_intent_prepared(
    sandbox_app, monkeypatch
):
    app = sandbox_app
    target = app.TARGET / "logging.conf"
    original = target.read_bytes()
    plan = app.plan(app.PlanIn(finding_ids=["LOG-001"]))
    change = app.apply(app.ApplyIn(plan_id=plan["plan_id"], approved=True))["changes"][0]
    real_event = app.event

    def fail_rollback_audit(action, detail):
        if action == "rollback.outcome":
            raise SQLAlchemyError("injected audit commit failure")
        return real_event(action, detail)

    monkeypatch.setattr(app, "event", fail_rollback_audit)
    with pytest.raises(HTTPException) as exc:
        app.rollback(app.RollbackIn(change_ids=[change["change_id"]], approved=True))
    assert exc.value.status_code == 503
    assert target.read_bytes() == original
    pending = unresolved_changes(app.STATE)
    assert len(pending) == 1 and pending[0]["status"] == "prepared"
    assert app.load("change", change["change_id"])["status"] == "rolled_back"


def test_successful_apply_and_rollback_audit_before_finalization(sandbox_app):
    app = sandbox_app
    plan = app.plan(app.PlanIn(finding_ids=["LOG-001"]))
    change = app.apply(app.ApplyIn(plan_id=plan["plan_id"], approved=True))["changes"][0]
    assert unresolved_changes(app.STATE) == []
    applied = [row for row in app.audit() if row["action"] == "change.outcome"]
    assert len(applied) == 1
    assert applied[0]["detail"]["change_id"] == change["change_id"]
    assert applied[0]["detail"]["status"] == "applied"

    result = app.rollback(
        app.RollbackIn(change_ids=[change["change_id"]], approved=True)
    )
    assert result["results"][0]["status"] == "rolled_back"
    assert unresolved_changes(app.STATE) == []
    restored = [row for row in app.audit() if row["action"] == "rollback.outcome"]
    assert len(restored) == 1
    assert restored[0]["detail"]["change_id"] == change["change_id"]
    assert restored[0]["detail"]["status"] == "rolled_back"
