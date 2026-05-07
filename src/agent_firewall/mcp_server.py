from __future__ import annotations

import argparse
from typing import Any

from mcp.server.fastmcp import FastMCP

from agent_firewall.analyzer import analyze
from agent_firewall.redaction import redact_text

mcp = FastMCP(
    "agent-firewall",
    instructions=(
        "Scan AI code-agent conversations and tool events for prompt injection, "
        "secret exposure, destructive commands, exfiltration, and risky MCP/tool changes."
    ),
)


@mcp.tool()
def analyze_agent_security(payload: dict[str, Any]) -> dict[str, Any]:
    """Analyze chat messages and agent events for security issues.

    Payload shape:
    {
      "text": "...",
      "messages": [{"role": "user", "content": "..."}],
      "events": [{"kind": "shell", "command": "...", "file_path": "..."}]
    }
    """
    return analyze(payload, policy=payload.get("policy"), custom_rules=payload.get("rules")).to_dict()


@mcp.tool()
def redact_sensitive_text(text: str) -> str:
    """Redact likely secrets before storing logs or adding text to model context."""
    return redact_text(text)


@mcp.tool()
def recommended_agent_security_controls() -> dict[str, list[str]]:
    """Return practical controls for securing AI code-agent loops."""
    return {
        "controls": [
            "Scan both chat text and tool events; dangerous behavior often appears in shell commands, file paths, or tool output.",
            "Keep untrusted tool output separate from system and developer instructions.",
            "Redact secrets before storing logs, summarizing long conversations, or sending context to another model.",
            "Require explicit approval for destructive filesystem commands, git history rewrites, and outbound transfers.",
            "Review MCP server source, permissions, environment access, and network behavior before enabling it.",
        ]
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run AgentFirewall as an MCP server.")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="MCP transport to use. Use stdio for local MCP clients, streamable-http for remote clients.",
    )
    args = parser.parse_args()
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
