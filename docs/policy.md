# Policy

AgentFirewall is zero-config by default. A policy file lets a project tune noisy findings without changing code.

Default file name:

```text
agent-firewall.policy.json
```

CLI usage:

```bash
agent-firewall-scan agent-events.json --policy agent-firewall.policy.json
```

The REST API also accepts an inline `policy` object in `POST /v1/analyze`.

## Example

```json
{
  "verdict": {
    "warn_at": 35,
    "block_at": 85,
    "warn_severities": ["medium", "high"],
    "block_severities": ["critical"]
  },
  "disabled_rules": [],
  "disabled_categories": [],
  "disabled_tags": [],
  "severity_overrides": {
    "mcp-server-install": "high"
  },
  "allow_patterns": [
    {
      "reason": "Allow documentation sample env files, but not real .env files.",
      "rule_id": "sensitive-file-access",
      "source_regex": "file_path$",
      "excerpt_regex": "\\.env\\.example$"
    }
  ]
}
```

## Fields

- `disabled_rules`: rule ids to suppress, such as `unsigned-package-exec`.
- `disabled_categories`: categories to suppress, such as `supply_chain`.
- `disabled_tags`: tags to suppress, such as `package-manager`.
- `severity_overrides`: map rule ids to `info`, `low`, `medium`, `high`, or `critical`.
- `allow_patterns`: precise allowlist entries matched against rule id, category, tag, evidence source, and evidence excerpt.
- `verdict`: tune risk-score thresholds and severity levels that trigger `warn` or `block`.

## Guidance

Prefer `allow_patterns` over broad disables. A narrow allow pattern keeps the dangerous rule active everywhere else.

Good:

```json
{
  "allow_patterns": [
    {
      "rule_id": "sensitive-file-access",
      "excerpt_regex": "\\.env\\.example$"
    }
  ]
}
```

Risky:

```json
{
  "disabled_categories": ["credential_exposure"]
}
```

If a rule is too noisy, add a narrow policy entry and a test fixture that explains the intended workflow.
