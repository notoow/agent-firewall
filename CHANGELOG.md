# Changelog

All notable changes to AgentFirewall will be documented in this file.

This project follows semantic versioning before `1.0.0` with the usual alpha caveat: minor versions may still adjust APIs while the product shape settles.

## 0.1.0 - Unreleased

- Initial REST API, MCP server, and CLI scanner.
- Built-in detection for prompt injection, secret exposure, destructive commands, exfiltration, supply-chain risk, and MCP/tool risk.
- Project auto-discovery files for Codex, Claude Code, Cursor, Antigravity/Gemini-style agents, and GitHub Copilot.
- Human-readable CLI reports, JSON output, and CI exit-code thresholds.
- Project policy file support.
- Custom JSON rule-pack support.
- `agent-firewall demo` and `agent-firewall doctor` onboarding commands.
- SARIF and `--output` report support for CI/security tooling.
- JSONL agent log parsing for append-only event streams.
- Default report redaction across CLI, SARIF, REST API, and MCP outputs.
- JSONL watch mode with an `agent-firewall-watch` command for continuous log scanning.
