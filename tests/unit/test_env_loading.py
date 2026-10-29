"""Tests for .env loading via the custom environment module.

These tests verify that load_project_environment correctly reads .env files
and populates os.environ, without exposing or printing secret values.
"""
import os
import sys
import pathlib
import textwrap
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ddos_detector.environment import (
    BREVO_VARIABLES,
    load_project_environment,
    missing_brevo_variables,
    project_root_for_config,
)


@pytest.fixture(autouse=True)
def clean_brevo_env(monkeypatch):
    """Remove all Brevo env vars before each test; restore after."""
    for name in BREVO_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    yield


# ── project_root_for_config ──────────────────────────────────────────


def test_project_root_from_config_subdir(tmp_path):
    """config/config.yaml -> parent of config/ is the project root."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_file = config_dir / "config.yaml"
    config_file.write_text("interface: lo\n")
    assert project_root_for_config(str(config_file)) == str(tmp_path)


def test_project_root_from_flat_path(tmp_path):
    """A config file that is NOT inside a 'config/' dir uses its own parent."""
    config_file = tmp_path / "settings.yaml"
    config_file.write_text("interface: lo\n")
    assert project_root_for_config(str(config_file)) == str(tmp_path)


# ── load_project_environment ─────────────────────────────────────────


def test_loads_brevo_vars_from_dotenv(tmp_path):
    """All four BREVO_* variables are populated from a .env file."""
    env_file = tmp_path / ".env"
    env_file.write_text(textwrap.dedent("""\
        BREVO_API_KEY=test-key-abc123
        BREVO_SENDER_EMAIL=sender@example.test
        BREVO_SENDER_NAME=TestBot
        BREVO_ALERT_RECIPIENT=recipient@example.test
    """))
    config_file = tmp_path / "app.yaml"
    config_file.write_text("")

    result = load_project_environment(str(config_file))

    assert result == str(env_file)
    assert os.environ["BREVO_API_KEY"] == "test-key-abc123"
    assert os.environ["BREVO_SENDER_EMAIL"] == "sender@example.test"
    assert os.environ["BREVO_SENDER_NAME"] == "TestBot"
    assert os.environ["BREVO_ALERT_RECIPIENT"] == "recipient@example.test"


def test_does_not_overwrite_existing_env(tmp_path, monkeypatch):
    """Pre-existing environment values must survive .env loading."""
    monkeypatch.setenv("BREVO_API_KEY", "EXTERNAL_KEY")
    env_file = tmp_path / ".env"
    env_file.write_text("BREVO_API_KEY=file-key\nBREVO_SENDER_EMAIL=file@example.test\n")
    config_file = tmp_path / "app.yaml"
    config_file.write_text("")

    load_project_environment(str(config_file))

    assert os.environ["BREVO_API_KEY"] == "EXTERNAL_KEY"
    assert os.environ["BREVO_SENDER_EMAIL"] == "file@example.test"


def test_returns_none_when_no_env_file(tmp_path):
    """When .env is absent the function returns None and sets nothing."""
    config_file = tmp_path / "app.yaml"
    config_file.write_text("")
    result = load_project_environment(str(config_file))
    assert result is None
    for name in BREVO_VARIABLES:
        assert name not in os.environ


def test_ignores_comments_and_blank_lines(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(textwrap.dedent("""\
        # This is a comment
        
        BREVO_API_KEY=key-with-comments
        # Another comment
        BREVO_SENDER_EMAIL=sender@example.test
    """))
    config_file = tmp_path / "app.yaml"
    config_file.write_text("")

    load_project_environment(str(config_file))

    assert os.environ["BREVO_API_KEY"] == "key-with-comments"
    assert os.environ["BREVO_SENDER_EMAIL"] == "sender@example.test"


def test_ignores_unsupported_variables(tmp_path):
    """Only the four BREVO_* variables from the allow-list are loaded."""
    env_file = tmp_path / ".env"
    env_file.write_text(textwrap.dedent("""\
        BREVO_API_KEY=allowed-key
        RANDOM_SECRET=should-not-appear
        DATABASE_URL=postgres://localhost/db
    """))
    config_file = tmp_path / "app.yaml"
    config_file.write_text("")

    load_project_environment(str(config_file))

    assert os.environ["BREVO_API_KEY"] == "allowed-key"
    assert "RANDOM_SECRET" not in os.environ
    assert "DATABASE_URL" not in os.environ


def test_strips_surrounding_quotes(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(textwrap.dedent("""\
        BREVO_API_KEY="double-quoted-key"
        BREVO_SENDER_EMAIL='single-quoted-email'
    """))
    config_file = tmp_path / "app.yaml"
    config_file.write_text("")

    load_project_environment(str(config_file))

    assert os.environ["BREVO_API_KEY"] == "double-quoted-key"
    assert os.environ["BREVO_SENDER_EMAIL"] == "single-quoted-email"


def test_handles_values_with_equals_signs(tmp_path):
    """Values containing '=' (e.g. base64 tokens) must not be truncated."""
    env_file = tmp_path / ".env"
    env_file.write_text("BREVO_API_KEY=abc=def=ghi\n")
    config_file = tmp_path / "app.yaml"
    config_file.write_text("")

    load_project_environment(str(config_file))

    assert os.environ["BREVO_API_KEY"] == "abc=def=ghi"


def test_config_subdir_env_resolution(tmp_path):
    """When config lives in a 'config/' subdir, .env is found in the project root."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_file = config_dir / "config.yaml"
    config_file.write_text("interface: lo\n")
    env_file = tmp_path / ".env"
    env_file.write_text("BREVO_API_KEY=project-root-key\n")

    result = load_project_environment(str(config_file))

    assert result == str(env_file)
    assert os.environ["BREVO_API_KEY"] == "project-root-key"


# ── missing_brevo_variables ──────────────────────────────────────────


def test_missing_brevo_variables_all_absent():
    assert set(missing_brevo_variables()) == set(BREVO_VARIABLES)


def test_missing_brevo_variables_none_missing(monkeypatch):
    for name in BREVO_VARIABLES:
        monkeypatch.setenv(name, "dummy")
    assert missing_brevo_variables() == []


def test_missing_brevo_variables_partial(monkeypatch):
    monkeypatch.setenv("BREVO_API_KEY", "present")
    missing = missing_brevo_variables()
    assert "BREVO_API_KEY" not in missing
    assert "BREVO_SENDER_EMAIL" in missing


# ── secret safety ────────────────────────────────────────────────────


def test_env_loader_never_prints_secrets(tmp_path, capsys):
    """load_project_environment must not print or leak secret values to stdout/stderr."""
    secret = "xkeysib-supersecretvalue12345"
    env_file = tmp_path / ".env"
    env_file.write_text(f"BREVO_API_KEY={secret}\n")
    config_file = tmp_path / "app.yaml"
    config_file.write_text("")

    load_project_environment(str(config_file))

    captured = capsys.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err
