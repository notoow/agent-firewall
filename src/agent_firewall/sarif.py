from __future__ import annotations

import re
from typing import Any

from agent_firewall.models import AnalysisResult, Evidence, Finding, Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "AgentFirewall"
TOOL_URI = "https://github.com/notoow/agent-firewall"


def result_to_sarif(result: AnalysisResult) -> dict[str, Any]:
    rules = rules_for(result.findings)
    rule_indexes = {rule["id"]: index for index, rule in enumerate(rules)}
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": [finding_to_result(finding, rule_indexes) for finding in result.findings],
                "properties": {
                    "verdict": result.verdict,
                    "riskScore": result.risk_score,
                    "maxSeverity": result.max_severity,
                    "summary": result.summary,
                    "recommendedControls": result.recommended_controls,
                },
            }
        ],
    }


def rules_for(findings: list[Finding]) -> list[dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for finding in findings:
        rule_id = base_rule_id(finding)
        if rule_id in rules:
            continue
        rules[rule_id] = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.recommendation},
            "help": {"text": finding.recommendation},
            "properties": {
                "severity": finding.severity,
                "category": finding.category,
                "tags": finding.tags,
            },
            "defaultConfiguration": {"level": level_for(finding.severity)},
        }
    return list(rules.values())


def finding_to_result(finding: Finding, rule_indexes: dict[str, int]) -> dict[str, Any]:
    rule_id = base_rule_id(finding)
    sarif_result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_indexes[rule_id],
        "level": level_for(finding.severity),
        "message": {"text": f"{finding.title}: {finding.recommendation}"},
        "locations": [location_for(evidence) for evidence in finding.evidence],
        "fingerprints": {"agentFirewallFindingId": finding.id},
        "properties": {
            "findingId": finding.id,
            "severity": finding.severity,
            "category": finding.category,
            "confidence": finding.confidence,
            "tags": finding.tags,
            "evidence": [
                {
                    "source": evidence.source,
                    "excerpt": evidence.excerpt,
                    "start": evidence.start,
                    "end": evidence.end,
                }
                for evidence in finding.evidence
            ],
        },
    }
    return sarif_result


def location_for(evidence: Evidence) -> dict[str, Any]:
    physical_location: dict[str, Any] = {
        "artifactLocation": {
            "uri": source_to_uri(evidence.source),
            "description": {"text": evidence.source},
        }
    }
    region = region_for(evidence)
    if region:
        physical_location["region"] = region
    return {"physicalLocation": physical_location}


def region_for(evidence: Evidence) -> dict[str, Any] | None:
    if evidence.start is None or evidence.end is None:
        return None
    char_length = max(0, evidence.end - evidence.start)
    return {
        "charOffset": evidence.start,
        "charLength": char_length,
        "snippet": {"text": evidence.excerpt},
    }


def source_to_uri(source: str) -> str:
    if not source:
        return "agent-event-stream"
    normalized = source.replace("[", "/").replace("]", "").replace(".", "/")
    normalized = re.sub(r"[^A-Za-z0-9/_@.+-]+", "-", normalized).strip("/-")
    return f"agent-event-stream/{normalized or 'event'}"


def base_rule_id(finding: Finding) -> str:
    return finding.id.split(":", 1)[0]


def level_for(severity: Severity) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
