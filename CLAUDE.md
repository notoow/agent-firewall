# AgentFirewall

Use the rules in `AGENTS.md` as the source of truth for this repository.

Claude Code should load the project MCP server from `.mcp.json` when available. Use the `agent-firewall` MCP tools before high-risk shell, file, network, package, git, or MCP actions.

If the MCP server is not connected, fall back to:

```powershell
python -m agent_firewall.cli examples/risky-agent-session.json
```

Never include raw secrets in summaries, comments, or generated examples.
