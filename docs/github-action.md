# GitHub Action

AgentFirewall can run directly inside GitHub Actions as a composite action.

## Basic Usage

```yaml
name: Agent security

on:
  pull_request:
  push:
    branches: [main]

jobs:
  agent-firewall:
    runs-on: ubuntu-latest
    permissions:
      contents: read

    steps:
      - uses: actions/checkout@v6

      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"

      - uses: notoow/agent-firewall@v0.1.0
        with:
          input: agent-events.json
          fail-on: block
```

## With Policy And Rule Packs

```yaml
- uses: notoow/agent-firewall@v0.1.0
  with:
    input: agent-events.json
    fail-on: warn
    policy: agent-firewall.policy.json
    rules: |
      agent-firewall.rules.json
      .github/agent-firewall-extra.rules.json
```

## Inputs

- `input`: path to an AgentFirewall JSON event payload. Required.
- `fail-on`: `never`, `warn`, or `block`. Defaults to `block`.
- `format`: `text` or `json`. Defaults to `text`.
- `compact`: compact JSON output when `format` is `json`. Defaults to `false`.
- `policy`: optional path to `agent-firewall.policy.json`.
- `rules`: optional newline-separated list of custom rule-pack JSON files.
- `python-command`: Python command used to install AgentFirewall. Defaults to `python`.

## Notes

The action installs AgentFirewall from the checked-out action source and then runs `agent-firewall-scan`.

Use `actions/setup-python` before the action for predictable Python versions and pip behavior.
