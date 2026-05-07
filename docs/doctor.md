# Doctor And Demo

AgentFirewall includes onboarding helpers for first-run confidence.

## Demo

Run a built-in risky scan:

```bash
agent-firewall demo
```

Use a clean payload:

```bash
agent-firewall demo --safe
```

JSON output:

```bash
agent-firewall demo --format json
```

Alias:

```bash
agent-firewall-demo
```

## Doctor

Check the local installation and project setup:

```bash
agent-firewall doctor --target /path/to/project
```

Alias:

```bash
agent-firewall-doctor --target /path/to/project
```

Doctor checks:

- Python version
- package version
- console commands on `PATH`
- smoke scan behavior
- project discovery files
- `.mcp.json`
- `.cursor/mcp.json`
- `agent-firewall.policy.json`
- `agent-firewall.rules.json`

Warnings are allowed by default so a fresh project can still pass while telling you what to install next.

Use strict mode in automation:

```bash
agent-firewall doctor --target /path/to/project --strict
```

If discovery files are missing:

```bash
agent-firewall-init --target /path/to/project
```
