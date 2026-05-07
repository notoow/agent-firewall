import tomllib
from pathlib import Path

from scripts.check_version import normalize_tag, read_project_version, run


def test_project_version_is_valid() -> None:
    assert read_project_version(Path("pyproject.toml")) == "0.1.0"


def test_normalize_tag_requires_v_prefix() -> None:
    try:
        normalize_tag("0.1.0")
    except ValueError as exc:
        assert "must start with 'v'" in str(exc)
    else:
        raise AssertionError("expected tag without v prefix to fail")


def test_check_version_accepts_matching_tag() -> None:
    assert run(["--tag", "v0.1.0"]) == 0


def test_check_version_rejects_mismatched_tag() -> None:
    assert run(["--tag", "v9.9.9"]) == 1


def test_watch_console_script_is_registered() -> None:
    config = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert config["project"]["scripts"]["agent-firewall-watch"] == "agent_firewall.watch:main"
    assert config["project"]["scripts"]["agent-firewall-audit"] == "agent_firewall.audit_cli:main"
