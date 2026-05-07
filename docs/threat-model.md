# Threat Model

## Serious Risks In AI Code-Agent Sessions

Long AI coding sessions create a new attack surface because the model is not only chatting. It may be reading files, calling tools, installing packages, editing code, sending network requests, summarizing logs, and connecting to MCP servers.

The core failure mode is privilege confusion: untrusted content from a web page, email, GitHub issue, dependency script, or tool result gets treated like trusted user or system instruction.

## Assets

- Source code and private repositories
- `.env` files, API keys, tokens, SSH keys, cloud credentials
- Local filesystem and git history
- Connected accounts exposed through MCP tools or connectors
- Conversation history that may contain secrets or operational details

## Attacker Paths

- Prompt injection inside a README, issue, web page, email, or dependency output
- Tool result instructing the agent to ignore policies or reveal hidden prompts
- Remote script execution hidden inside setup instructions
- Data exfiltration through `curl`, `scp`, paste services, webhooks, or analytics endpoints
- Destructive commands framed as cleanup
- Malicious or over-scoped MCP server gaining access to secrets, filesystem, or accounts

## Control Points

- Before adding external content to model context
- Before executing shell commands
- Before reading sensitive files
- Before writing CI, dependency, auth, or secret-related config
- Before enabling a new MCP server or connector
- Before sending data to external network destinations

## MVP Scope

The MVP uses deterministic rules and redaction. That gives immediate value, testability, and explainable warnings.

Later versions should add:

- Repository-aware allowlists and deny-lists
- Secret manager integration
- LLM-assisted semantic review for ambiguous findings
- Per-agent policy profiles
- Audit log signing
- MCP server reputation and permission review
- Browser/email/GitHub content isolation labels
