"""Unit tests for plugins/WebPanel/secrets.py -- this module is
deliberately fail-CLOSED (missing/unparseable credentials must mean
"refuse every request", see its module docstring), unlike every other
secrets loader in this repo. No test file existed for it before
2026-08-24's bug-hunt review found the wrong-top-level-JSON-type gap
fixed below.
"""
import json

from plugins.WebPanel.secrets import load_panel_credentials


def test_missing_file_returns_none(tmp_path):
    assert load_panel_credentials(str(tmp_path / "does-not-exist.json")) is None


def test_valid_credentials_load(tmp_path):
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps({
        "web_panel_user": "alice",
        "web_panel_password_hash": "pbkdf2_sha256$100$AA==$AA==",
    }))
    creds = load_panel_credentials(str(path))
    assert creds is not None
    assert creds.username == "alice"
    assert creds.password_hash == "pbkdf2_sha256$100$AA==$AA=="


def test_missing_username_returns_none(tmp_path):
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps({"web_panel_password_hash": "pbkdf2_sha256$100$AA==$AA=="}))
    assert load_panel_credentials(str(path)) is None


def test_corrupt_json_returns_none_not_raise(tmp_path):
    path = tmp_path / "secrets.json"
    path.write_text("{not valid json")
    assert load_panel_credentials(str(path)) is None


def test_valid_json_list_at_top_level_returns_none_not_raise(tmp_path):
    """Regression, 2026-08-24: json.loads succeeds fine on "[]" -- the
    old code only guarded JSONDecodeError/OSError, so the following
    data.get(...) call raised AttributeError instead of failing closed."""
    path = tmp_path / "secrets.json"
    path.write_text("[]")
    assert load_panel_credentials(str(path)) is None


def test_valid_json_string_at_top_level_returns_none_not_raise(tmp_path):
    path = tmp_path / "secrets.json"
    path.write_text('"oops"')
    assert load_panel_credentials(str(path)) is None


def test_valid_json_number_at_top_level_returns_none_not_raise(tmp_path):
    path = tmp_path / "secrets.json"
    path.write_text("42")
    assert load_panel_credentials(str(path)) is None
