"""Safe loading of supported project-local runtime environment values."""

from __future__ import annotations

import os

BREVO_VARIABLES = (
    "BREVO_API_KEY",
    "BREVO_SENDER_EMAIL",
    "BREVO_SENDER_NAME",
    "BREVO_ALERT_RECIPIENT",
)


def project_root_for_config(config_path: str) -> str:
    path = os.path.abspath(os.path.expanduser(config_path))
    parent = os.path.dirname(path)
    return os.path.dirname(parent) if os.path.basename(parent) == "config" else parent


def load_project_environment(config_path: str) -> str | None:
    """Load only supported values without overriding inherited environment."""
    env_path = os.path.join(project_root_for_config(config_path), ".env")
    if not os.path.isfile(env_path):
        return None
    with open(env_path, encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            name = name.strip()
            if name in BREVO_VARIABLES and name not in os.environ:
                os.environ[name] = value.strip().strip("'\"")
    return env_path


def missing_brevo_variables() -> list[str]:
    return [name for name in BREVO_VARIABLES if not os.environ.get(name)]
