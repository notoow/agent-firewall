from __future__ import annotations

from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from agent_firewall.analyzer import analyze, redact_result
from agent_firewall.baseline import apply_baseline, baseline_ids_from_data
from agent_firewall.discovery import discovery_manifest
from agent_firewall.policy import maybe_load_policy, policy_from_dict
from agent_firewall.redaction import redact_text


class AnalyzeRequest(BaseModel):
    text: str | None = Field(default=None, description="Raw conversation or tool output to scan.")
    messages: list[dict[str, Any]] = Field(default_factory=list, description="Chat messages with role/content fields.")
    events: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Tool, shell, file, MCP, browser, email, or repository events emitted by an AI code agent.",
    )
    context: dict[str, Any] = Field(default_factory=dict)
    policy: dict[str, Any] | None = Field(default=None, description="Optional inline AgentFirewall policy overrides.")
    rules: dict[str, Any] | list[dict[str, Any]] | None = Field(
        default=None,
        description="Optional inline custom rule pack.",
    )
    baseline: dict[str, Any] | list[str] | None = Field(
        default=None,
        description="Optional baseline object or finding ID list whose findings should be suppressed.",
    )


class RedactRequest(BaseModel):
    text: str


app = FastAPI(
    title="AgentFirewall",
    version="0.1.0",
    description="Security scanner for AI code-agent conversations, shell commands, file changes, and MCP/tool events.",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "agent-firewall"}


@app.get("/.well-known/agent-firewall.json")
def discovery() -> dict[str, Any]:
    return discovery_manifest()


@app.post("/v1/analyze")
def analyze_agent_security(request: AnalyzeRequest) -> dict[str, Any]:
    payload = request.model_dump(exclude={"policy", "rules", "baseline"})
    policy = policy_from_dict(request.policy) if request.policy is not None else maybe_load_policy()
    try:
        baseline_ids = baseline_ids_from_data(request.baseline)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid baseline: {exc}") from exc
    result = redact_result(analyze(payload, policy=policy, custom_rules=request.rules))
    return apply_baseline(result, baseline_ids, policy=policy).to_dict()


@app.post("/v1/redact")
def redact(request: RedactRequest) -> dict[str, str]:
    return {"text": redact_text(request.text)}


@app.get("/v1/controls")
def controls() -> dict[str, list[dict[str, str]]]:
    return {
        "controls": [
            {
                "name": "event-stream scanning",
                "description": "Scan messages, shell commands, tool results, file paths, and MCP events before they become model-visible context.",
            },
            {
                "name": "secret redaction",
                "description": "Redact likely API keys, tokens, JWTs, cloud credentials, and URI credentials before storage or display.",
            },
            {
                "name": "approval gates",
                "description": "Block or require human approval for destructive commands, outbound data transfers, and credential access.",
            },
            {
                "name": "MCP trust review",
                "description": "Treat new MCP servers and connector scopes as privileged code with filesystem, network, and secret access.",
            },
        ]
    }


def main() -> None:
    uvicorn.run("agent_firewall.api:app", host="127.0.0.1", port=8787, reload=False)


if __name__ == "__main__":
    main()
