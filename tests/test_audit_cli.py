import json

from agent_firewall.audit import AUDIT_SCHEMA, append_audit_record
from agent_firewall.audit_cli import run


def test_audit_cli_verify_valid_log(tmp_path, capsys) -> None:
    path = tmp_path / "agent-firewall.audit.jsonl"
    append_audit_record(path, {"schema": AUDIT_SCHEMA, "result": {"verdict": "pass"}})

    code = run(["verify", str(path)])

    assert code == 0
    output = capsys.readouterr().out
    assert "AgentFirewall Audit: PASS" in output
    assert "Records: 1" in output


def test_audit_cli_verify_invalid_log_as_json(tmp_path, capsys) -> None:
    path = tmp_path / "agent-firewall.audit.jsonl"
    append_audit_record(path, {"schema": AUDIT_SCHEMA, "result": {"verdict": "pass"}})
    record = json.loads(path.read_text(encoding="utf-8"))
    record["result"]["verdict"] = "block"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    code = run(["verify", str(path), "--format", "json"])

    assert code == 1
    body = json.loads(capsys.readouterr().out)
    assert body["valid"] is False
    assert body["errors"][0]["message"] == "record hash mismatch"
