# Security Policy

AgentFirewall is a security tool, so vulnerability reports are especially welcome.

## Supported Versions

Until the first stable release, security fixes target the latest `main` branch and the newest published package version.

## Reporting A Vulnerability

Please do not open a public issue for a vulnerability that includes working exploit details, secrets, or private target information.

Preferred reporting path:

1. Open a private GitHub security advisory for this repository.
2. Include the affected version or commit, reproduction steps, expected impact, and any safe proof-of-concept input.
3. Redact real credentials, customer data, private repository names, and hostnames.

If private advisories are unavailable, open a minimal public issue that says you have a security report to share, without exploit details.

## Scope

In scope:

- Secret redaction bypasses
- Prompt-injection detection bypasses with clear impact
- Dangerous command classification mistakes
- MCP configuration or tool-risk handling flaws
- API behavior that leaks raw secrets in responses or logs

Out of scope:

- Generic false positives without a realistic agent workflow
- Social engineering against maintainers
- Vulnerabilities in third-party services not caused by AgentFirewall

## Safety Promise

AgentFirewall does not claim that a session is safe. It flags known-dangerous patterns in the supplied agent event stream so the host can block, warn, redact, or ask for confirmation.
