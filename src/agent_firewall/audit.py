from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, datetime
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from agent_firewall.models import AnalysisResult
from agent_firewall.redaction import redact_text

AUDIT_SCHEMA = "agent-firewall.audit.v1"
CHAIN_ALGORITHM = "sha256-canonical-json-v1"


def audit_record(
    result: AnalysisResult,
    *,
    mode: str,
    input_text: str | None = None,
    source_path: str | None = None,
    line_number: int | None = None,
) -> dict[str, Any]:
    return {
        "schema": AUDIT_SCHEMA,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "mode": mode,
        "source": {
            "path": redact_text(source_path) if source_path is not None else None,
            "line": line_number,
        },
        "input": input_fingerprint(input_text),
        "summary": {
            "verdict": result.verdict,
            "risk_score": result.risk_score,
            "max_severity": result.max_severity,
            "finding_count": len(result.findings),
            "finding_ids": [finding.id for finding in result.findings],
        },
        "result": result.to_dict(),
    }


def input_fingerprint(input_text: str | None) -> dict[str, Any]:
    if input_text is None:
        return {"sha256": None, "bytes": None}
    encoded = input_text.encode("utf-8")
    return {
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "bytes": len(encoded),
    }


def append_audit_record(path: str | Path, record: dict[str, Any]) -> None:
    audit_path = Path(path)
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    chained_record = chain_audit_record(record, previous_hash=last_record_hash(audit_path))
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(chained_record, ensure_ascii=False, separators=(",", ":")) + "\n")


def chain_audit_record(record: dict[str, Any], *, previous_hash: str | None = None) -> dict[str, Any]:
    chained = copy.deepcopy(record)
    chained["chain"] = {
        "algorithm": CHAIN_ALGORITHM,
        "previous_hash": previous_hash,
        "record_hash": None,
    }
    chained["chain"]["record_hash"] = compute_record_hash(chained)
    return chained


def compute_record_hash(record: dict[str, Any]) -> str:
    payload = record_payload_for_hash(record)
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def record_payload_for_hash(record: dict[str, Any]) -> dict[str, Any]:
    payload = copy.deepcopy(record)
    chain = payload.get("chain")
    if isinstance(chain, dict):
        chain.pop("record_hash", None)
    return payload


def last_record_hash(path: Path) -> str | None:
    if not path.exists():
        return None
    last_hash: str | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except JSONDecodeError:
            continue
        chain = record.get("chain")
        if isinstance(chain, dict) and isinstance(chain.get("record_hash"), str):
            last_hash = chain["record_hash"]
    return last_hash


def verify_audit_log(path: str | Path) -> dict[str, Any]:
    audit_path = Path(path)
    errors: list[dict[str, Any]] = []
    previous_hash: str | None = None
    records = 0

    for line_number, line in enumerate(audit_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        records += 1
        try:
            record = json.loads(line)
        except JSONDecodeError as exc:
            errors.append({"line": line_number, "message": f"invalid JSON: {exc.msg}"})
            continue

        chain = record.get("chain")
        if not isinstance(chain, dict):
            errors.append({"line": line_number, "message": "missing chain metadata"})
            continue
        if chain.get("algorithm") != CHAIN_ALGORITHM:
            errors.append({"line": line_number, "message": "unsupported chain algorithm"})
        if chain.get("previous_hash") != previous_hash:
            errors.append({"line": line_number, "message": "previous hash mismatch"})

        expected_hash = compute_record_hash(record)
        if chain.get("record_hash") != expected_hash:
            errors.append({"line": line_number, "message": "record hash mismatch"})

        current_hash = chain.get("record_hash")
        previous_hash = current_hash if isinstance(current_hash, str) else None

    return {
        "valid": not errors,
        "records": records,
        "last_record_hash": previous_hash,
        "errors": errors,
    }
