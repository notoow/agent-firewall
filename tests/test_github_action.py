from pathlib import Path

import yaml


def test_action_metadata_is_valid_shape() -> None:
    action = yaml.safe_load(Path("action.yml").read_text(encoding="utf-8"))

    assert action["name"] == "AgentFirewall"
    assert action["runs"]["using"] == "composite"
    assert action["inputs"]["input"]["required"] is True
    assert action["inputs"]["fail-on"]["default"] == "block"
    assert action["inputs"]["python-command"]["default"] == "python"


def test_action_installs_from_action_path_and_runs_scan() -> None:
    action_text = Path("action.yml").read_text(encoding="utf-8")

    assert 'pip install "$GITHUB_ACTION_PATH"' in action_text
    assert 'agent-firewall-scan "${args[@]}"' in action_text


def test_ci_dogfoods_local_action() -> None:
    workflow = yaml.safe_load(Path(".github/workflows/ci.yml").read_text(encoding="utf-8"))

    assert "dogfood-action" in workflow["jobs"]
    steps = workflow["jobs"]["dogfood-action"]["steps"]
    assert any(step.get("uses") == "./" for step in steps)
