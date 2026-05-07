import json

from agent_firewall.integrations import install_agent_configs


def test_install_agent_configs_creates_discovery_files(tmp_path) -> None:
    actions = install_agent_configs(tmp_path)

    assert len(actions) == 7
    assert (tmp_path / "AGENTS.md").exists()
    assert (tmp_path / "CLAUDE.md").exists()
    assert (tmp_path / "GEMINI.md").exists()
    assert (tmp_path / ".cursor" / "rules" / "agent-firewall.mdc").exists()
    assert (tmp_path / ".agents" / "rules" / "agent-firewall.md").exists()

    mcp_config = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert mcp_config["mcpServers"]["agent-firewall"]["command"] == "agent-firewall-mcp"


def test_install_agent_configs_preserves_existing_agents_file(tmp_path) -> None:
    agents = tmp_path / "AGENTS.md"
    agents.write_text("# Existing\n\nKeep this.\n", encoding="utf-8")

    install_agent_configs(tmp_path)

    content = agents.read_text(encoding="utf-8")
    assert "Keep this." in content
    assert "AgentFirewall is the security preflight" in content


def test_install_agent_configs_can_use_python_command(tmp_path) -> None:
    install_agent_configs(tmp_path, python_command="python")

    mcp_config = json.loads((tmp_path / ".cursor" / "mcp.json").read_text(encoding="utf-8"))
    server = mcp_config["mcpServers"]["agent-firewall"]
    assert server["command"] == "python"
    assert server["args"] == ["-m", "agent_firewall.mcp_server", "--transport", "stdio"]


def test_install_agent_configs_is_idempotent_for_existing_agentfirewall_docs(tmp_path) -> None:
    agents = tmp_path / "AGENTS.md"
    agents.write_text("AgentFirewall uses analyze_agent_security before risky actions.\n", encoding="utf-8")

    actions = install_agent_configs(tmp_path)

    assert actions[0].action == "unchanged"
    assert agents.read_text(encoding="utf-8").count("AgentFirewall") == 1


def test_install_agent_configs_detects_broader_agentfirewall_guidance(tmp_path) -> None:
    gemini = tmp_path / "GEMINI.md"
    gemini.write_text("AgentFirewall should block risky agent actions.\n", encoding="utf-8")

    actions = install_agent_configs(tmp_path)

    assert actions[2].action == "unchanged"
