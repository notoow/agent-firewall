# API

## `POST /v1/analyze`

Scans chat messages and agent events.

Request:

```json
{
  "text": "optional raw text",
  "messages": [{"role": "user", "content": "message text"}],
  "events": [{"kind": "shell", "command": "rm -rf ."}],
  "policy": {"disabled_rules": []},
  "rules": {"rules": []},
  "baseline": {"finding_ids": ["remote-code-exec-command:..."]},
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

Responses are redacted by default. Evidence excerpts and source fields are sanitized before they leave the API so dashboards and logs do not become another place where secrets leak.

When `policy`, `rules`, or `baseline` is omitted, the API auto-loads `./agent-firewall.policy.json`, `./agent-firewall.rules.json`, and `./agent-firewall.baseline.json` when those files exist in the server working directory.

`baseline` can be either a full AgentFirewall baseline object or a direct list of finding IDs. Baseline findings are suppressed before the API returns a verdict, so host products can show failures only for newly introduced issues.

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
