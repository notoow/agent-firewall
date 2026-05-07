from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent_firewall.models import AnalysisResult
from agent_firewall.redaction import redact_text

AUDIT_SCHEMA = "agent-firewall.audit.v1"


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
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
