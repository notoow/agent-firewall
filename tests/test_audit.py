import json

from agent_firewall.analyzer import analyze, redact_result
from agent_firewall.audit import AUDIT_SCHEMA, append_audit_record, audit_record, verify_audit_log


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

    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["schema"] == AUDIT_SCHEMA
    assert record["chain"]["algorithm"] == "sha256-canonical-json-v1"
    assert record["chain"]["previous_hash"] is None
    assert record["chain"]["record_hash"]


def test_audit_record_redacts_source_path() -> None:
    token = "xoxb-" + "e" * 30
    result = redact_result(analyze({"events": [{"kind": "shell", "command": "python -m pytest"}]}))

    record = audit_record(result, mode="scan", source_path=f"logs/{token}/agent-events.json")

    assert token not in json.dumps(record)
    assert "[REDACTED:slack_token]" in record["source"]["path"]


def test_verify_audit_log_accepts_valid_hash_chain(tmp_path) -> None:
    path = tmp_path / "agent-firewall.audit.jsonl"
    append_audit_record(path, {"schema": AUDIT_SCHEMA, "result": {"verdict": "pass"}})
    append_audit_record(path, {"schema": AUDIT_SCHEMA, "result": {"verdict": "block"}})

    result = verify_audit_log(path)
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    assert result["valid"] is True
    assert result["records"] == 2
    assert records[1]["chain"]["previous_hash"] == records[0]["chain"]["record_hash"]
    assert result["last_record_hash"] == records[1]["chain"]["record_hash"]


def test_verify_audit_log_detects_tampering(tmp_path) -> None:
    path = tmp_path / "agent-firewall.audit.jsonl"
    append_audit_record(path, {"schema": AUDIT_SCHEMA, "result": {"verdict": "pass"}})

    record = json.loads(path.read_text(encoding="utf-8"))
    record["result"]["verdict"] = "block"
    path.write_text(json.dumps(record, separators=(",", ":")) + "\n", encoding="utf-8")

    result = verify_audit_log(path)

    assert result["valid"] is False
    assert result["errors"][0]["message"] == "record hash mismatch"


def test_verify_audit_log_detects_previous_hash_break(tmp_path) -> None:
    path = tmp_path / "agent-firewall.audit.jsonl"
    append_audit_record(path, {"schema": AUDIT_SCHEMA, "result": {"verdict": "pass"}})
    append_audit_record(path, {"schema": AUDIT_SCHEMA, "result": {"verdict": "warn"}})

    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    records[1]["chain"]["previous_hash"] = "0" * 64
    path.write_text("\n".join(json.dumps(record, separators=(",", ":")) for record in records) + "\n", encoding="utf-8")

    result = verify_audit_log(path)

    assert result["valid"] is False
    assert any(error["message"] == "previous hash mismatch" for error in result["errors"])
