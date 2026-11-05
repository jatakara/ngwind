"""Regression tests for safe listing of local change records; no remote actions."""
import os
import pytest
from fastapi import HTTPException


def test_changes_lists_valid_records(tmp_path, monkeypatch):
    import app
    monkeypatch.setattr(app, "STATE", tmp_path)
    ident = "a" * 32
    app.save("change", ident, {"change_id": ident, "status": "applied"})
    assert app.changes() == [{"change_id": ident, "status": "applied"}]


def test_changes_rejects_symlink_without_disclosing_target(tmp_path, monkeypatch):
    import app
    monkeypatch.setattr(app, "STATE", tmp_path)
    ident = "b" * 32
    outside = tmp_path / "private.json"
    outside.write_text('{"change_id":"' + ident + '","secret":"private"}')
    (tmp_path / f"change-{ident}.json").symlink_to(outside)
    with pytest.raises(HTTPException) as exc:
        app.changes()
    assert exc.value.status_code == 503


def test_changes_rejects_hardlink(tmp_path, monkeypatch):
    import app
    monkeypatch.setattr(app, "STATE", tmp_path)
    ident = "c" * 32
    original = tmp_path / "original.json"
    original.write_text('{"change_id":"' + ident + '"}')
    os.link(original, tmp_path / f"change-{ident}.json")
    with pytest.raises(HTTPException) as exc:
        app.changes()
    assert exc.value.status_code == 503


@pytest.mark.parametrize("filename,contents", [
    ("change-bad.json", '{"change_id":"bad"}'),
    ("change-" + "d" * 32 + ".json", '{"change_id":"wrong"}'),
    ("change-" + "e" * 32 + ".json", "{broken"),
])
def test_changes_fails_closed_on_invalid_records(tmp_path, monkeypatch, filename, contents):
    import app
    monkeypatch.setattr(app, "STATE", tmp_path)
    (tmp_path / filename).write_text(contents)
    with pytest.raises(HTTPException) as exc:
        app.changes()
    assert exc.value.status_code in (400, 503)
