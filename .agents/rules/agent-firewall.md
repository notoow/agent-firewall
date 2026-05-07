# AgentFirewall Rule

Use AgentFirewall as a preflight security check before risky AI coding agent actions.

Call `analyze_agent_security` through MCP when available. Otherwise, scan a JSON event payload with `python -m agent_firewall.cli`.

Stop on `block`, ask for confirmation on `warn`, continue on `pass`.
