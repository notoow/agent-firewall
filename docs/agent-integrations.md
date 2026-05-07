# Agent Integrations

AgentFirewall supports three layers of auto-discovery:

1. Shared project instructions through `AGENTS.md`.
2. Tool-specific instruction files such as `CLAUDE.md`, `GEMINI.md`, Cursor rules, and Copilot instructions.
3. Project-scoped MCP configuration where the client supports it.

Scans also auto-load project `agent-firewall.policy.json`, `agent-firewall.rules.json`, and `agent-firewall.baseline.json` files when they exist in the agent working directory.

## Files Installed By `agent-firewall-init`

- `AGENTS.md`: shared instructions for Codex, Cursor, and other AGENTS-aware tools.
- `CLAUDE.md`: Claude Code project memory.
- `GEMINI.md`: Gemini and Antigravity-style project guidance.
- `.mcp.json`: Claude Code project MCP configuration.
- `.cursor/mcp.json`: Cursor project MCP configuration.
- `.cursor/rules/agent-firewall.mdc`: always-applied Cursor project rule.
- `.agents/rules/agent-firewall.md`: generic agent-rule fallback.

## Install Into Another Project

After installing AgentFirewall globally or in a project environment:

```powershell
agent-firewall-init --target C:\path\to\your\project
```

If the MCP command is not on PATH, generate configs that call a specific Python executable:

```powershell
agent-firewall-init --target C:\path\to\your\project --python C:\path\to\python.exe
```

## Important Security Note

Some agent clients intentionally require a one-time approval before trusting project-scoped MCP servers. That is a good security boundary, not a bug. AgentFirewall can make setup automatic, but it should not bypass the client user's trust prompt.

## References

- OpenAI Codex `AGENTS.md`: https://developers.openai.com/codex/guides/agents-md
- Claude Code memory and project `CLAUDE.md`: https://docs.claude.com/en/docs/claude-code/memory
- Claude Code MCP project scope and `.mcp.json`: https://code.claude.com/docs/en/mcp
- Cursor rules and `AGENTS.md`: https://docs.cursor.com/en/context
- Cursor MCP project config: https://docs.cursor.com/advanced/model-context-protocol
