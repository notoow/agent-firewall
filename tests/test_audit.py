import json

from agent_firewall.analyzer import analyze, redact_result
from agent_firewall.audit import AUDIT_SCHEMA, append_audit_record, audit_record


def test_audit_record_summarizes_redacted_result() -> None:
    result = redact_result(analyze({"events": [{"kind": "shell", "command": "python -m pytest"}]}))

    record = audit_record(result, mode="scan", input_text='{"events":[]}', source_path="agent-events.json")

    assert record["schema"] == AUDIT_SCHEMA
    assert record["created_at"].endswith("Z")
    assert record["mode"] == "scan"
    assert record["source"]["path"] == "agent-events.json"
    assert record["input"]["sha256"]
    assert record["summary"]["verdict"] == "pass"
    assert record["result"]["verdict"] == "pass"


def test_append_audit_record_writes_jsonl(tmp_path) -> None:
    path = tmp_path / "logs" / "agent-firewall.audit.jsonl"

    append_audit_record(path, {"schema": AUDIT_SCHEMA, "result": {"verdict": "pass"}})

    assert json.loads(path.read_text(encoding="utf-8"))["schema"] == AUDIT_SCHEMA


def test_audit_record_redacts_source_path() -> None:
    token = "xoxb-" + "e" * 30
    result = redact_result(analyze({"events": [{"kind": "shell", "command": "python -m pytest"}]}))

    record = audit_record(result, mode="scan", source_path=f"logs/{token}/agent-events.json")

    assert token not in json.dumps(record)
    assert "[REDACTED:slack_token]" in record["source"]["path"]
