import json

from agent_firewall.integrations import install_agent_configs
from agent_firewall.onboarding import (
    COMMANDS,
    doctor_checks,
    format_doctor_report,
    resolve_command,
    run,
    risky_demo_payload,
    safe_demo_payload,
)


def test_demo_payloads_have_expected_verdicts() -> None:
    from agent_firewall.analyzer import analyze

    assert analyze(risky_demo_payload()).verdict == "block"
    assert analyze(safe_demo_payload()).verdict == "pass"


def test_demo_text_output(capsys) -> None:
    code = run(["demo"])

    assert code == 0
    assert "AgentFirewall: BLOCK" in capsys.readouterr().out


def test_demo_json_output(capsys) -> None:
    code = run(["demo", "--safe", "--format", "json"])

    assert code == 0
    body = json.loads(capsys.readouterr().out)
    assert body["verdict"] == "pass"


def test_doctor_non_strict_allows_warnings(tmp_path, capsys) -> None:
    code = run(["doctor", "--target", str(tmp_path)])

    assert code == 0
    output = capsys.readouterr().out
    assert "AgentFirewall Doctor" in output
    assert "warning" in output


def test_doctor_strict_fails_on_warnings(tmp_path, capsys) -> None:
    code = run(["doctor", "--target", str(tmp_path), "--strict"])

    assert code == 1
    assert "WARN" in capsys.readouterr().out


def test_doctor_detects_invalid_mcp_json(tmp_path, capsys) -> None:
    (tmp_path / ".mcp.json").write_text("{not json", encoding="utf-8")

    code = run(["doctor", "--target", str(tmp_path)])

    assert code == 1
    assert "project MCP config" in capsys.readouterr().out


def test_doctor_reports_installed_project_files(tmp_path) -> None:
    install_agent_configs(tmp_path)

    checks = doctor_checks(tmp_path)
    report = format_doctor_report(checks, target=tmp_path)

    assert "project file:AGENTS.md: found" in report
    assert "project file:.agents/rules/agent-firewall.md: found" in report
    assert "project file:.github/copilot-instructions.md: found" in report
    assert "project MCP config: valid JSON" in report
    assert "baseline: agent-firewall.baseline.json is valid with 0 finding ID(s)" in report


def test_doctor_detects_invalid_baseline(tmp_path, capsys) -> None:
    (tmp_path / "agent-firewall.baseline.json").write_text('{"schema": "bad", "finding_ids": []}', encoding="utf-8")

    code = run(["doctor", "--target", str(tmp_path)])

    assert code == 1
    assert "baseline schema" in capsys.readouterr().out


def test_resolve_command_falls_back_to_python_script_dir(monkeypatch, tmp_path) -> None:
    scripts = tmp_path / "Scripts"
    scripts.mkdir()
    command = scripts / "agent-firewall-scan.exe"
    command.write_text("", encoding="utf-8")

    monkeypatch.setattr("sys.executable", str(scripts / "python.exe"))
    monkeypatch.setattr("sys.platform", "win32")
    monkeypatch.setattr("shutil.which", lambda _: None)

    assert resolve_command("agent-firewall-scan") == command


def test_doctor_checks_watch_command() -> None:
    assert "agent-firewall-watch" in COMMANDS
    assert "agent-firewall-audit" in COMMANDS
