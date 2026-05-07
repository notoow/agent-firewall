from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from agent_firewall.models import SEVERITY_ORDER, Finding, Severity, Verdict

DEFAULT_POLICY_FILE = "agent-firewall.policy.json"


@dataclass(frozen=True)
class AllowPattern:
    reason: str = ""
    rule_id: str | None = None
    category: str | None = None
    tag: str | None = None
    source_regex: str | None = None
    excerpt_regex: str | None = None


@dataclass(frozen=True)
class VerdictPolicy:
    warn_at: int = 40
    block_at: int = 85
    warn_severities: set[str] = field(default_factory=lambda: {"medium", "high"})
    block_severities: set[str] = field(default_factory=lambda: {"critical"})


@dataclass(frozen=True)
class AgentFirewallPolicy:
    disabled_rules: set[str] = field(default_factory=set)
    disabled_categories: set[str] = field(default_factory=set)
    disabled_tags: set[str] = field(default_factory=set)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    allow_patterns: list[AllowPattern] = field(default_factory=list)
    verdict: VerdictPolicy = field(default_factory=VerdictPolicy)


def load_policy(path: str | Path | None = None) -> AgentFirewallPolicy:
    policy_path = Path(path or DEFAULT_POLICY_FILE)
    return policy_from_dict(json.loads(policy_path.read_text(encoding="utf-8")))


def maybe_load_policy(path: str | Path | None = None) -> AgentFirewallPolicy | None:
    policy_path = Path(path or DEFAULT_POLICY_FILE)
    if not policy_path.exists():
        return None
    return load_policy(policy_path)


def policy_from_dict(data: dict[str, Any] | None) -> AgentFirewallPolicy | None:
    if not data:
        return None

    verdict_data = dict(data.get("verdict") or {})
    verdict = VerdictPolicy(
        warn_at=int(verdict_data.get("warn_at", 40)),
        block_at=int(verdict_data.get("block_at", 85)),
        warn_severities=set(map(str, verdict_data.get("warn_severities", ["medium", "high"]))),
        block_severities=set(map(str, verdict_data.get("block_severities", ["critical"]))),
    )

    severity_overrides = {
        str(rule_id): validate_severity(str(severity))
        for rule_id, severity in dict(data.get("severity_overrides") or {}).items()
    }

    allow_patterns = [allow_pattern_from_dict(item) for item in data.get("allow_patterns", [])]
    return AgentFirewallPolicy(
        disabled_rules=set(map(str, data.get("disabled_rules", []))),
        disabled_categories=set(map(str, data.get("disabled_categories", []))),
        disabled_tags=set(map(str, data.get("disabled_tags", []))),
        severity_overrides=severity_overrides,
        allow_patterns=allow_patterns,
        verdict=verdict,
    )


def allow_pattern_from_dict(data: dict[str, Any]) -> AllowPattern:
    pattern = AllowPattern(
        reason=str(data.get("reason", "")),
        rule_id=optional_str(data.get("rule_id")),
        category=optional_str(data.get("category")),
        tag=optional_str(data.get("tag")),
        source_regex=optional_str(data.get("source_regex")),
        excerpt_regex=optional_str(data.get("excerpt_regex")),
    )
    for regex in (pattern.source_regex, pattern.excerpt_regex):
        if regex:
            re.compile(regex)
    return pattern


def apply_policy(findings: list[Finding], policy: AgentFirewallPolicy | None) -> list[Finding]:
    if policy is None:
        return findings

    filtered: list[Finding] = []
    for finding in findings:
        rule_id = finding_rule_id(finding)
        if rule_id in policy.disabled_rules:
            continue
        if finding.category in policy.disabled_categories:
            continue
        if set(finding.tags) & policy.disabled_tags:
            continue
        if is_allowed(finding, policy.allow_patterns):
            continue

        severity = policy.severity_overrides.get(rule_id)
        filtered.append(replace(finding, severity=severity) if severity else finding)
    return filtered


def policy_verdict_for(risk_score: int, max_severity: Severity, policy: AgentFirewallPolicy | None) -> Verdict:
    verdict_policy = policy.verdict if policy else VerdictPolicy()
    if max_severity in verdict_policy.block_severities or risk_score >= verdict_policy.block_at:
        return "block"
    if max_severity in verdict_policy.warn_severities or risk_score >= verdict_policy.warn_at:
        return "warn"
    return "pass"


def finding_rule_id(finding: Finding) -> str:
    return finding.id.split(":", 1)[0]


def is_allowed(finding: Finding, patterns: list[AllowPattern]) -> bool:
    return any(matches_allow_pattern(finding, pattern) for pattern in patterns)


def matches_allow_pattern(finding: Finding, pattern: AllowPattern) -> bool:
    if pattern.rule_id and finding_rule_id(finding) != pattern.rule_id:
        return False
    if pattern.category and finding.category != pattern.category:
        return False
    if pattern.tag and pattern.tag not in finding.tags:
        return False

    evidence = finding.evidence[0] if finding.evidence else None
    if pattern.source_regex and not (evidence and re.search(pattern.source_regex, evidence.source)):
        return False
    if pattern.excerpt_regex and not (evidence and re.search(pattern.excerpt_regex, evidence.excerpt)):
        return False
    return True


def validate_severity(value: str) -> Severity:
    if value not in SEVERITY_ORDER:
        raise ValueError(f"invalid severity: {value}")
    return value  # type: ignore[return-value]


def optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)
