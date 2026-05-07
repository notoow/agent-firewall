from __future__ import annotations

import re

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openai_key", re.compile(r"\bsk-(?:proj|svcacct|admin|live|test)?-?[A-Za-z0-9_\-]{20,}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,255}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    (
        "uri_credentials",
        re.compile(r"\b([a-z][a-z0-9+.-]{2,}://)([^:/\s]+):([^@\s]+)@([^/\s]+)", re.IGNORECASE),
    ),
    (
        "secret_assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd|pwd)\b"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{12,})"
        ),
    ),
]


def redact_text(text: str) -> str:
    """Redact likely secrets while preserving enough shape for debugging."""
    redacted = text
    for name, pattern in SECRET_PATTERNS:
        if name == "uri_credentials":
            redacted = pattern.sub(r"\1\2:[REDACTED]@\4", redacted)
            continue
        redacted = pattern.sub(f"[REDACTED:{name}]", redacted)
    return redacted


def excerpt_around(text: str, start: int, end: int, radius: int = 96) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    prefix = "..." if left > 0 else ""
    suffix = "..." if right < len(text) else ""
    return prefix + redact_text(text[left:right]).replace("\n", "\\n") + suffix
