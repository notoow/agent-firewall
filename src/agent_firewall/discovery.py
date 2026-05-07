from __future__ import annotations

from typing import Any


def discovery_manifest() -> dict[str, Any]:
    return {
        "name": "AgentFirewall",
        "id": "agent-firewall",
        "description": "Zero-config security firewall for AI coding agents.",
        "version": "0.1.0",
        "capabilities": [
            "prompt-injection-detection",
            "secret-redaction",
            "destructive-command-preflight",
            "data-exfiltration-detection",
            "mcp-tool-risk-detection",
        ],
        "rest": {
            "health": "/health",
            "analyze": "/v1/analyze",
            "redact": "/v1/redact",
            "controls": "/v1/controls",
            "discovery": "/.well-known/agent-firewall.json",
        },
        "mcp": {
            "server_name": "agent-firewall",
            "stdio": {
                "command": "agent-firewall-mcp",
                "args": [],
            },
            "tools": [
                "analyze_agent_security",
                "redact_sensitive_text",
                "recommended_agent_security_controls",
            ],
        },
        "agent_files": [
            "AGENTS.md",
            "CLAUDE.md",
            "GEMINI.md",
            "agent-firewall.policy.json",
            ".mcp.json",
            ".cursor/mcp.json",
            ".cursor/rules/agent-firewall.mdc",
            ".agents/rules/agent-firewall.md",
            ".github/copilot-instructions.md",
        ],
    }
