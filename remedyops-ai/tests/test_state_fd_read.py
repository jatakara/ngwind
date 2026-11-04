"""File-descriptor state read regression tests; sandbox only."""
import os
import pytest
from fastapi import HTTPException


def test_state_read_rejects_path_swap_to_symlink(tmp_path, monkeypatch):
    import app
    monkeypatch.setattr(app, "STATE", tmp_path)
    ident = "e" * 32
    target = tmp_path / f"plan-{ident}.json"
    outside = tmp_path / "outside.json"
    outside.write_text('{"secret":"not-authorized"}')
    target.write_text('{"status":"planned"}')
    original_open = app.os.open

    def swap_then_open(path, flags, *args, **kwargs):
        if str(path) == str(target):
            target.unlink()
            target.symlink_to(outside)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(app.os, "open", swap_then_open)
    with pytest.raises(HTTPException) as exc:
        app.load("plan", ident)
    assert exc.value.status_code == 503


def test_state_read_rejects_growth_beyond_limit(tmp_path, monkeypatch):
    import app
    monkeypatch.setattr(app, "STATE", tmp_path)
    ident = "f" * 32
    (tmp_path / f"plan-{ident}.json").write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(HTTPException) as exc:
        app.load("plan", ident)
    assert exc.value.status_code == 503


def test_state_read_rejects_directory(tmp_path, monkeypatch):
    import app
    monkeypatch.setattr(app, "STATE", tmp_path)
    ident = "1" * 32
    (tmp_path / f"plan-{ident}.json").mkdir()
    with pytest.raises(HTTPException) as exc:
        app.load("plan", ident)
    assert exc.value.status_code == 503
