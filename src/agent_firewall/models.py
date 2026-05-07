from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
Verdict = Literal["pass", "warn", "block"]

SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_WEIGHT: dict[str, int] = {
    "info": 0,
    "low": 15,
    "medium": 40,
    "high": 70,
    "critical": 100,
}


@dataclass(frozen=True)
class ConversationMessage:
    role: str
    content: str
    name: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentEvent:
    kind: str
    content: str = ""
    tool_name: str | None = None
    command: str | None = None
    file_path: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AnalysisInput:
    text: str | None = None
    messages: list[ConversationMessage] = field(default_factory=list)
    events: list[AgentEvent] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Evidence:
    source: str
    excerpt: str
    start: int | None = None
    end: int | None = None


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    confidence: float
    evidence: list[Evidence]
    recommendation: str
    tags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AnalysisResult:
    verdict: Verdict
    risk_score: int
    max_severity: Severity
    findings: list[Finding]
    summary: str
    recommended_controls: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
