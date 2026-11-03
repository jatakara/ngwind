"""Regression coverage for fail-closed sandbox state reads (no SSH)."""
import pytest
from fastapi import HTTPException


def test_state_read_rejects_malformed_identifiers(tmp_path, monkeypatch):
    import app
    monkeypatch.setattr(app, "STATE", tmp_path)
    for ident in ("../outside", "A" * 32, "abc", "0" * 33):
        with pytest.raises(HTTPException) as exc:
            app.load("plan", ident)
        assert exc.value.status_code == 400


def test_state_read_rejects_symlink(tmp_path, monkeypatch):
    import app
    monkeypatch.setattr(app, "STATE", tmp_path)
    ident = "a" * 32
    outside = tmp_path / "outside.json"
    outside.write_text('{"secret":"do-not-read"}')
    (tmp_path / f"plan-{ident}.json").symlink_to(outside)
    with pytest.raises(HTTPException) as exc:
        app.load("plan", ident)
    assert exc.value.status_code == 503


def test_state_read_rejects_hardlink(tmp_path, monkeypatch):
    import os
    import app
    monkeypatch.setattr(app, "STATE", tmp_path)
    ident = "b" * 32
    source = tmp_path / "source.json"
    source.write_text('{"secret":"do-not-read"}')
    os.link(source, tmp_path / f"plan-{ident}.json")
    with pytest.raises(HTTPException) as exc:
        app.load("plan", ident)
    assert exc.value.status_code == 503


def test_state_read_rejects_corrupt_json(tmp_path, monkeypatch):
    import app
    monkeypatch.setattr(app, "STATE", tmp_path)
    ident = "c" * 32
    (tmp_path / f"plan-{ident}.json").write_text("{broken")
    with pytest.raises(HTTPException) as exc:
        app.load("plan", ident)
    assert exc.value.status_code == 503


def test_state_read_valid_record(tmp_path, monkeypatch):
    import app
    monkeypatch.setattr(app, "STATE", tmp_path)
    ident = "d" * 32
    app.save("plan", ident, {"status": "planned"})
    assert app.load("plan", ident)["status"] == "planned"
