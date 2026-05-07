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

## SARIF Report

```yaml
- uses: notoow/agent-firewall@v0.1.0
  with:
    input: agent-events.json
    fail-on: block
    format: sarif
    output: agent-firewall.sarif
```

## With Baseline

```yaml
- uses: notoow/agent-firewall@v0.1.0
  with:
    input: agent-events.json
    fail-on: block
    baseline: agent-firewall.baseline.json
```

## Inputs

- `input`: path to an AgentFirewall JSON or JSONL event payload. Required.
- `fail-on`: `never`, `warn`, or `block`. Defaults to `block`.
- `format`: `text`, `json`, or `sarif`. Defaults to `text`.
- `compact`: compact JSON or SARIF output. Defaults to `false`.
- `output`: optional file path to write the scan report.
- `baseline`: optional AgentFirewall baseline file whose finding IDs should be suppressed.
- `update-baseline`: optional path to write a baseline from the current unfiltered scan.
- `policy`: optional path to `agent-firewall.policy.json`.
- `rules`: optional newline-separated list of custom rule-pack JSON files.
- `python-command`: Python command used to install AgentFirewall. Defaults to `python`.

## Notes

The action installs AgentFirewall from the checked-out action source and then runs `agent-firewall-scan`.

Use `actions/setup-python` before the action for predictable Python versions and pip behavior.
