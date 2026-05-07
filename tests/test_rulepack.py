import json

from agent_firewall.analyzer import analyze
from agent_firewall.rulepack import load_rulepack, rules_from_dict


CUSTOM_RULE_PACK = {
    "rules": [
        {
            "id": "team-production-database-command",
            "title": "Production database command",
            "severity": "high",
            "category": "production_access",
            "recommendation": "Require explicit approval before production database access.",
            "tags": ["database", "production"],
            "targets": ["command"],
            "pattern": "(?i)\\bpsql\\b.{0,80}\\bprod\\b",
        }
    ]
}


def test_custom_rule_pack_matches_targeted_command() -> None:
    result = analyze(
        {"events": [{"kind": "shell", "command": "psql postgresql://prod-db.example/app"}]},
        custom_rules=CUSTOM_RULE_PACK,
    )

    assert result.verdict == "warn"
    assert any(finding.id.startswith("team-production-database-command") for finding in result.findings)


def test_custom_rule_pack_respects_targets() -> None:
    result = analyze(
        {"messages": [{"role": "user", "content": "psql postgresql://prod-db.example/app"}]},
        custom_rules=CUSTOM_RULE_PACK,
    )

    assert result.verdict == "pass"
    assert result.findings == []


def test_custom_rule_pack_can_be_disabled_by_policy() -> None:
    result = analyze(
        {"events": [{"kind": "shell", "command": "psql postgresql://prod-db.example/app"}]},
        custom_rules=CUSTOM_RULE_PACK,
        policy={"disabled_rules": ["team-production-database-command"]},
    )

    assert result.verdict == "pass"
    assert result.findings == []


def test_custom_rule_pack_loads_from_file(tmp_path) -> None:
    rulepack = tmp_path / "agent-firewall.rules.json"
    rulepack.write_text(json.dumps(CUSTOM_RULE_PACK), encoding="utf-8")

    rules = load_rulepack(rulepack)
    result = analyze(
        {"events": [{"kind": "shell", "command": "psql postgresql://prod-db.example/app"}]},
        custom_rules=rules,
    )

    assert result.verdict == "warn"


def test_custom_rule_pack_rejects_invalid_target() -> None:
    try:
        rules_from_dict(
            {
                "rules": [
                    {
                        "id": "bad-target",
                        "title": "Bad target",
                        "severity": "low",
                        "category": "test",
                        "recommendation": "Fix the target.",
                        "pattern": "x",
                        "targets": ["terminal"],
                    }
                ]
            }
        )
    except ValueError as exc:
        assert "invalid rule target" in str(exc)
    else:
        raise AssertionError("expected invalid target to fail")


def test_custom_rule_pack_rejects_missing_rules_array() -> None:
    try:
        rules_from_dict({"name": "empty"})
    except ValueError as exc:
        assert "rules array" in str(exc)
    else:
        raise AssertionError("expected missing rules array to fail")
