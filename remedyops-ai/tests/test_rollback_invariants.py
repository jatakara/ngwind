"""Regression tests for sandbox rollback behavior; no remote connections.

The known unsafe verification-failure path is documented as strict xfail.
Remove xfail only after the application restores original bytes on failure.
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


@pytest.mark.xfail(
    strict=True,
    reason="Known defect: failed verification leaves changed bytes and cannot be rolled back",
)
def test_failed_verification_restores_original_bytes(sandbox_app, monkeypatch):
    app = sandbox_app
    target = app.TARGET / "logging.conf"
    original = target.read_bytes()
    plan = app.plan(app.PlanIn(finding_ids=["LOG-001"]))
    monkeypatch.setattr(app, "config", lambda _data: {})
    outcome = app.apply(app.ApplyIn(plan_id=plan["plan_id"], approved=True))
    assert outcome["changes"][0]["status"] == "verification_failed_rolled_back"
    assert target.read_bytes() == original
