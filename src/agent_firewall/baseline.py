from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent_firewall.analyzer import recommended_controls_for, score_findings, summary_for
from agent_firewall.models import AnalysisResult, Finding
from agent_firewall.policy import AgentFirewallPolicy, policy_verdict_for

BASELINE_SCHEMA = "agent-firewall.baseline.v1"


def baseline_from_result(result: AnalysisResult) -> dict[str, Any]:
    findings = sorted(result.findings, key=lambda finding: finding.id)
    return {
        "schema": BASELINE_SCHEMA,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "finding_ids": [finding.id for finding in findings],
        "findings": [baseline_finding(finding) for finding in findings],
    }


def baseline_finding(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity,
        "category": finding.category,
        "tags": finding.tags,
    }


def write_baseline(path: str | Path, result: AnalysisResult) -> None:
    baseline_path = Path(path)
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(
        json.dumps(baseline_from_result(result), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def load_baseline(path: str | Path) -> set[str]:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    return baseline_ids_from_data(data, require_schema=True)


def baseline_ids_from_data(data: Any, *, require_schema: bool = False) -> set[str]:
    if data is None:
        return set()
    if isinstance(data, list):
        if not all(isinstance(item, str) for item in data):
            raise ValueError("baseline finding ID list must contain only strings")
        return set(data)
    if not isinstance(data, dict):
        raise ValueError("baseline must be a JSON object or a list of finding IDs")

    schema = data.get("schema")
    if require_schema and schema != BASELINE_SCHEMA:
        raise ValueError(f"baseline schema must be {BASELINE_SCHEMA}")
    if schema is not None and schema != BASELINE_SCHEMA:
        raise ValueError(f"baseline schema must be {BASELINE_SCHEMA}")

    finding_ids = data.get("finding_ids")
    if not isinstance(finding_ids, list) or not all(isinstance(item, str) for item in finding_ids):
        raise ValueError("baseline finding_ids must be a list of strings")
    return set(finding_ids)


def apply_baseline(
    result: AnalysisResult,
    baseline_ids: set[str],
    *,
    policy: AgentFirewallPolicy | None = None,
) -> AnalysisResult:
    if not baseline_ids:
        return result
    findings = [finding for finding in result.findings if finding.id not in baseline_ids]
    suppressed_count = len(result.findings) - len(findings)
    if suppressed_count == 0:
        return result

    max_severity = findings[0].severity if findings else "info"
    risk_score = score_findings(findings)
    verdict = policy_verdict_for(risk_score, max_severity, policy)
    summary = summary_for(verdict, findings)
    if not findings:
        summary = "No new security issue was detected after applying the baseline."
    return replace(
        result,
        verdict=verdict,
        risk_score=risk_score,
        max_severity=max_severity,
        findings=findings,
        summary=f"{summary} Baseline suppressed {suppressed_count} known finding(s).",
        recommended_controls=recommended_controls_for(findings),
    )
