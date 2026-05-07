# CLI

`agent-firewall-scan` is the fastest way to try AgentFirewall locally or add it to CI.

## Human-Readable Report

```bash
agent-firewall-scan examples/risky-agent-session.json
```

Output:

```text
AgentFirewall: BLOCK
Risk score: 100/100
Max severity: critical

Blocking risk detected. Highest severity is critical; review and mitigate before continuing.
```

## JSON Output

```bash
agent-firewall-scan examples/risky-agent-session.json --format json
```

Compact JSON:

```bash
agent-firewall-scan examples/risky-agent-session.json --format json --compact
```

## CI Exit Codes

By default, scans exit with `0` so local exploration does not break scripts unexpectedly.

Use `--fail-on` in automation:

```bash
agent-firewall-scan agent-events.json --fail-on block
agent-firewall-scan agent-events.json --fail-on warn
```

Exit codes:

- `0`: scan completed and did not meet the fail threshold
- `1`: input or JSON parsing error
- `2`: `warn` verdict failed a `--fail-on warn` threshold
- `3`: `block` verdict failed a `--fail-on warn` or `--fail-on block` threshold

## Policy

Use `--policy` to tune a project:

```bash
agent-firewall-scan agent-events.json --policy agent-firewall.policy.json
```

When `--policy` is omitted, AgentFirewall automatically uses `./agent-firewall.policy.json` if it exists.

## Rule Packs

Use `--rules` to add custom team rules:

```bash
agent-firewall-scan agent-events.json --rules agent-firewall.rules.json
```

When `--rules` is omitted, AgentFirewall automatically uses `./agent-firewall.rules.json` if it exists.

## Redaction

```bash
agent-firewall-scan suspicious-output.txt --redact
```

This masks likely API keys, tokens, JWTs, cloud credentials, URI credentials, and secret assignments before the text is stored or passed to another model.
