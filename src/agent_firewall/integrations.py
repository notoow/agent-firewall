from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

START = "<!-- AGENT-FIREWALL:START -->"
END = "<!-- AGENT-FIREWALL:END -->"


AGENT_BLOCK = """\
## AgentFirewall

AgentFirewall is the security preflight for AI coding agents in this project.

- Before high-risk shell, file, git, package, network, or MCP actions, scan the proposed action.
- Use the `agent-firewall` MCP tool `analyze_agent_security` when available.
- If MCP is not connected, scan a JSON payload with `agent-firewall-scan <file>`.
- Stop on `block`, ask for confirmation on `warn`, continue on `pass`.
- Redact secrets before summarizing logs or adding tool output to model context.
"""

CURSOR_RULE = """\
---
alwaysApply: true
description: Use AgentFirewall before high-risk AI coding agent actions.
---

# AgentFirewall

Before high-risk shell, file, git, package, network, or MCP actions, call the `agent-firewall` MCP tool `analyze_agent_security` when available.

If MCP is unavailable, scan a JSON event payload with `agent-firewall-scan <file>`.

Stop on `block`, ask for confirmation on `warn`, continue on `pass`. Never include raw secrets in generated summaries, commits, comments, or issues.
"""

AGENTS_RULE = """\
# AgentFirewall Rule

Use AgentFirewall as a preflight security check before risky AI coding agent actions.

Call `analyze_agent_security` through MCP when available. Otherwise, scan a JSON event payload with `agent-firewall-scan <file>`.

Stop on `block`, ask for confirmation on `warn`, continue on `pass`.
"""

COPILOT_INSTRUCTIONS = """\
# AgentFirewall

Use `AGENTS.md` as the source of truth for project agent instructions.

Before suggesting or applying high-risk shell, file, git, package, network, or MCP actions, prefer the AgentFirewall MCP tool `analyze_agent_security` when available.

Stop on `block`, ask for confirmation on `warn`, continue on `pass`.
"""

POLICY_TEMPLATE: dict[str, Any] = {
    "verdict": {
        "warn_at": 40,
        "block_at": 85,
        "warn_severities": ["medium", "high"],
        "block_severities": ["critical"],
    },
    "disabled_rules": [],
    "disabled_categories": [],
    "disabled_tags": [],
    "severity_overrides": {},
    "allow_patterns": [],
}

RULEPACK_TEMPLATE: dict[str, Any] = {
    "name": "project-agent-firewall-rules",
    "description": "Project-specific AgentFirewall rules. Add team rules here when built-in detections are not enough.",
    "rules": [],
}

BASELINE_TEMPLATE: dict[str, Any] = {
    "schema": "agent-firewall.baseline.v1",
    "created_at": None,
    "finding_ids": [],
    "findings": [],
}


@dataclass(frozen=True)
class InstallAction:
    path: str
    action: str


def install_agent_configs(
    target: Path,
    *,
    python_command: str | None = None,
    dry_run: bool = False,
) -> list[InstallAction]:
    target = target.resolve()
    actions: list[InstallAction] = []
    command, args = mcp_command(python_command)

    actions.append(upsert_markdown(target / "AGENTS.md", AGENT_BLOCK, dry_run=dry_run))
    actions.append(upsert_markdown(target / "CLAUDE.md", "Use `AGENTS.md` as the source of truth.\n\n" + AGENT_BLOCK, dry_run=dry_run))
    actions.append(upsert_markdown(target / "GEMINI.md", "Use `AGENTS.md` as the shared project instruction file.\n\n" + AGENT_BLOCK, dry_run=dry_run))

    actions.append(write_file(target / ".cursor" / "rules" / "agent-firewall.mdc", CURSOR_RULE, dry_run=dry_run))
    actions.append(write_file(target / ".agents" / "rules" / "agent-firewall.md", AGENTS_RULE, dry_run=dry_run))
    actions.append(upsert_markdown(target / ".github" / "copilot-instructions.md", COPILOT_INSTRUCTIONS, dry_run=dry_run))
    actions.append(merge_mcp_config(target / ".mcp.json", command=command, args=args, dry_run=dry_run))
    actions.append(merge_mcp_config(target / ".cursor" / "mcp.json", command=command, args=args, dry_run=dry_run))
    actions.append(write_json_template(target / "agent-firewall.policy.json", POLICY_TEMPLATE, dry_run=dry_run))
    actions.append(write_json_template(target / "agent-firewall.rules.json", RULEPACK_TEMPLATE, dry_run=dry_run))
    actions.append(write_json_template(target / "agent-firewall.baseline.json", BASELINE_TEMPLATE, dry_run=dry_run))

    return actions


def mcp_command(python_command: str | None) -> tuple[str, list[str]]:
    if python_command:
        return python_command, ["-m", "agent_firewall.mcp_server", "--transport", "stdio"]
    return "agent-firewall-mcp", []


def upsert_markdown(path: Path, block: str, *, dry_run: bool) -> InstallAction:
    wrapped = f"{START}\n{block.rstrip()}\n{END}\n"
    if path.exists():
        existing = path.read_text(encoding="utf-8")
        if START in existing and END in existing:
            before, rest = existing.split(START, 1)
            _, after = rest.split(END, 1)
            new_text = before.rstrip() + "\n\n" + wrapped + after.lstrip()
            action = "updated"
        elif has_agent_firewall_guidance(existing):
            return InstallAction(str(path), "unchanged")
        else:
            new_text = existing.rstrip() + "\n\n" + wrapped
            action = "appended"
    else:
        new_text = wrapped
        action = "created"

    if not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(new_text, encoding="utf-8")
    return InstallAction(str(path), action)


def has_agent_firewall_guidance(text: str) -> bool:
    lowered = text.lower()
    return "agentfirewall" in lowered and any(
        marker in lowered
        for marker in ("analyze_agent_security", "agent-firewall", "high-risk", "risky", "block")
    )


def write_file(path: Path, content: str, *, dry_run: bool) -> InstallAction:
    action = "updated" if path.exists() else "created"
    if not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content.rstrip() + "\n", encoding="utf-8")
    return InstallAction(str(path), action)


def write_json_template(path: Path, content: dict[str, Any], *, dry_run: bool) -> InstallAction:
    if path.exists():
        return InstallAction(str(path), "unchanged")
    if not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8")
    return InstallAction(str(path), "created")


def merge_mcp_config(path: Path, *, command: str, args: list[str], dry_run: bool) -> InstallAction:
    config: dict[str, Any] = {}
    action = "created"
    if path.exists():
        config = json.loads(path.read_text(encoding="utf-8"))
        action = "updated"

    servers = config.setdefault("mcpServers", {})
    servers["agent-firewall"] = {
        "type": "stdio",
        "command": command,
        "args": args,
    }

    if not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return InstallAction(str(path), action)


def main() -> None:
    parser = argparse.ArgumentParser(description="Install AgentFirewall auto-discovery files into an AI coding project.")
    parser.add_argument("--target", default=".", help="Project directory to configure.")
    parser.add_argument(
        "--python",
        dest="python_command",
        default=None,
        help="Use a specific Python executable instead of the agent-firewall-mcp console command.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Show files that would be changed without writing them.")
    args = parser.parse_args()

    actions = install_agent_configs(Path(args.target), python_command=args.python_command, dry_run=args.dry_run)
    for item in actions:
        print(f"{item.action}: {item.path}")


if __name__ == "__main__":
    main()
