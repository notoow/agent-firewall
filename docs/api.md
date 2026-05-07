# API

## `POST /v1/analyze`

Scans chat messages and agent events.

Request:

```json
{
  "text": "optional raw text",
  "messages": [{"role": "user", "content": "message text"}],
  "events": [{"kind": "shell", "command": "rm -rf ."}],
  "context": {"workspace": "repo-name"}
}
```

Response:

```json
{
  "verdict": "block",
  "risk_score": 100,
  "max_severity": "critical",
  "findings": [],
  "summary": "Blocking risk detected.",
  "recommended_controls": []
}
```

Verdicts:

- `pass`: No obvious issue found.
- `warn`: Show warning and require deliberate confirmation.
- `block`: Stop the agent until the issue is redacted, rewritten, or explicitly resolved.

## `POST /v1/redact`

Redacts likely secrets from text.

Request:

```json
{"text": "OPENAI_API_KEY=sk-proj-fakefakefakefakefakefakefakefake"}
```

Response:

```json
{"text": "[REDACTED:openai_key]"}
```

## `GET /v1/controls`

Returns practical security controls that a host product can display or enforce.

## `GET /.well-known/agent-firewall.json`

Returns a discovery manifest for agent hosts, IDE extensions, and MCP-aware clients.

It includes REST endpoints, the MCP stdio command, exposed MCP tools, and the project files AgentFirewall can install for automatic loading.
