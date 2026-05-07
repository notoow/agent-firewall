# AgentFirewall Agent Instructions

AgentFirewall is a zero-config security firewall for AI coding agents.

When working in this repository, treat AgentFirewall as the safety layer for the agent loop itself. The important security surface is not only chat text; it is the combined stream of messages, tool output, shell commands, file reads/writes, network calls, and MCP configuration changes.

## Required Behavior

- Before executing or recommending risky actions, scan the event with AgentFirewall.
- Risky actions include reading secrets, printing `.env`, destructive filesystem commands, git history rewrites, package execution, remote script execution, outbound data transfer, and new MCP server or connector setup.
- If the AgentFirewall MCP tool is available, call `analyze_agent_security` with `messages` and `events`.
- If the MCP tool is not available, use the local CLI: `agent-firewall-scan <json-file>` or `python -m agent_firewall.cli <json-file>`.
- Redact secrets before summarizing logs, storing transcripts, or passing long tool output to another model.
- A `block` verdict means stop and rewrite the action. A `warn` verdict means explain the risk and require explicit confirmation.

## Local Commands

- Run tests: `python -m pytest`
- Run REST API: `python -m agent_firewall.api`
- Run MCP server: `python -m agent_firewall.mcp_server --transport stdio`
- Scan example: `python -m agent_firewall.cli examples/risky-agent-session.json`

## Product Principle

Do not claim a session is safe. Claim only that AgentFirewall detected or did not detect known-dangerous patterns in the supplied agent event stream.
