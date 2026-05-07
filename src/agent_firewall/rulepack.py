from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_firewall.models import SEVERITY_ORDER, Severity

DEFAULT_RULEPACK_FILE = "agent-firewall.rules.json"
RuleTarget = str

VALID_TARGETS = {"message", "command", "file_path", "event_content"}


@dataclass(frozen=True)
class RulePackRule:
    id: str
    title: str
    severity: Severity
    category: str
    recommendation: str
    pattern: re.Pattern[str]
    targets: set[RuleTarget] = field(default_factory=lambda: set(VALID_TARGETS))
    tags: list[str] = field(default_factory=list)
    confidence: float = 0.75


def load_rulepack(path: str | Path) -> list[RulePackRule]:
    rulepack_path = Path(path)
    return rules_from_dict(json.loads(rulepack_path.read_text(encoding="utf-8")))


def maybe_load_rulepack(path: str | Path | None = None) -> list[RulePackRule]:
    rulepack_path = Path(path or DEFAULT_RULEPACK_FILE)
    if not rulepack_path.exists():
        return []
    return load_rulepack(rulepack_path)


def load_rulepacks(paths: list[str] | None) -> list[RulePackRule]:
    if not paths:
        return maybe_load_rulepack()

    rules: list[RulePackRule] = []
    for path in paths:
        rules.extend(load_rulepack(path))
    return rules


def rules_from_any(value: Any) -> list[RulePackRule]:
    if value is None:
        return []
    if isinstance(value, dict):
        return rules_from_dict(value)
    if isinstance(value, list):
        if all(isinstance(item, RulePackRule) for item in value):
            return value
        return rules_from_dict({"rules": value})
    raise ValueError("rules must be a rule-pack object or a list of rules")


def rules_from_dict(data: dict[str, Any]) -> list[RulePackRule]:
    rules_data = data.get("rules")
    if not isinstance(rules_data, list):
        raise ValueError("rule pack must contain a rules array")
    return [rule_from_dict(item) for item in rules_data]


def rule_from_dict(data: dict[str, Any]) -> RulePackRule:
    required = ["id", "title", "severity", "category", "recommendation", "pattern"]
    missing = [key for key in required if not data.get(key)]
    if missing:
        raise ValueError(f"rule is missing required field(s): {', '.join(missing)}")

    targets = set(map(str, data.get("targets", list(VALID_TARGETS))))
    invalid_targets = sorted(targets - VALID_TARGETS)
    if invalid_targets:
        raise ValueError(f"invalid rule target(s): {', '.join(invalid_targets)}")

    return RulePackRule(
        id=str(data["id"]),
        title=str(data["title"]),
        severity=validate_severity(str(data["severity"])),
        category=str(data["category"]),
        recommendation=str(data["recommendation"]),
        pattern=re.compile(str(data["pattern"])),
        targets=targets,
        tags=list(map(str, data.get("tags", []))),
        confidence=float(data.get("confidence", 0.75)),
    )


def validate_severity(value: str) -> Severity:
    if value not in SEVERITY_ORDER:
        raise ValueError(f"invalid severity: {value}")
    return value  # type: ignore[return-value]
