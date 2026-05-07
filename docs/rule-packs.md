# Rule Packs

AgentFirewall ships with built-in rules, but teams often need local checks for their own infrastructure, deployment names, or agent workflows.

Rule packs let you add regex-based rules without changing Python code.

Default file name:

```text
agent-firewall.rules.json
```

CLI usage:

```bash
agent-firewall-scan agent-events.json --rules agent-firewall.rules.json
```

You can pass `--rules` multiple times.

When `--rules` is omitted, AgentFirewall automatically loads `./agent-firewall.rules.json` if it exists.

## Schema

```json
{
  "name": "team-rules",
  "description": "Rules for team-specific agent risks.",
  "rules": [
    {
      "id": "team-production-database-command",
      "title": "Production database command",
      "severity": "high",
      "category": "production_access",
      "recommendation": "Require explicit approval before production database access.",
      "tags": ["database", "production"],
      "targets": ["command"],
      "pattern": "(?i)\\b(psql|mysql)\\b.{0,120}\\b(prod|production)\\b"
    }
  ]
}
```

Rule fields:

- `id`: stable rule id. Use a prefix such as `team-`, `org-`, or `community-`.
- `title`: short finding title.
- `severity`: `info`, `low`, `medium`, `high`, or `critical`.
- `category`: machine-readable category.
- `recommendation`: concrete remediation text.
- `tags`: optional list of tags.
- `targets`: one or more of `message`, `command`, `file_path`, `event_content`.
- `pattern`: Python regular expression.
- `confidence`: optional number, defaults to `0.75`.

## Targets

- `message`: raw chat message content.
- `command`: proposed or executed shell command.
- `file_path`: file read/write path.
- `event_content`: tool output, browser content, MCP output, email content, issue text, and similar event bodies.

## API And MCP

`POST /v1/analyze` accepts inline rule packs:

```json
{
  "events": [{"kind": "shell", "command": "psql postgresql://prod-db.example/app"}],
  "rules": {
    "rules": [
      {
        "id": "team-production-database-command",
        "title": "Production database command",
        "severity": "high",
        "category": "production_access",
        "recommendation": "Require explicit approval before production database access.",
        "targets": ["command"],
        "pattern": "(?i)\\bpsql\\b.{0,80}\\bprod\\b"
      }
    ]
  }
}
```

The MCP `analyze_agent_security` tool accepts the same `rules` field.

## Policy Interaction

Policies can tune custom rules the same way they tune built-in rules:

```json
{
  "disabled_rules": ["team-production-database-command"],
  "severity_overrides": {
    "team-production-database-command": "critical"
  }
}
```

This keeps rule packs shareable while letting each project choose its own enforcement level.
