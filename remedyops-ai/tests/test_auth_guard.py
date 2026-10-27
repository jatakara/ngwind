"""Regression tests for the fail-closed API authentication boundary."""

from auth_guard import api_auth_failure


def test_missing_token_fails_closed():
    assert api_auth_failure("/api/assets", "", "") == (503, "API token not configured")


def test_missing_token_does_not_accept_caller_supplied_value():
    assert api_auth_failure("/api/apply", "", "attacker-token") == (503, "API token not configured")


def test_wrong_token_is_rejected():
    assert api_auth_failure("/api/rollback", "expected", "wrong") == (401, "Unauthorized")


def test_empty_header_is_rejected_when_configured():
    assert api_auth_failure("/api/diagnose", "expected", "") == (401, "Unauthorized")


def test_correct_token_is_accepted():
    assert api_auth_failure("/api/plan", "expected", "expected") is None


def test_api_root_is_guarded():
    assert api_auth_failure("/api", "", "") == (503, "API token not configured")


def test_non_api_ui_is_accessible_without_token():
    assert api_auth_failure("/", "", "") is None


def test_similarly_named_non_api_path_is_not_guarded():
    assert api_auth_failure("/apiary", "", "") is None
