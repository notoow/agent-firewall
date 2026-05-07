from __future__ import annotations

import argparse
import json
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from agent_firewall.analyzer import analyze
from agent_firewall.models import AnalysisResult, Finding
from agent_firewall.policy import load_policy, maybe_load_policy
from agent_firewall.redaction import redact_text
from agent_firewall.rulepack import load_rulepacks
from agent_firewall.sarif import result_to_sarif


def main() -> None:
    raise SystemExit(run())


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        raw = read_input(args.input)
    except OSError as exc:
        print(f"agent-firewall: could not read input: {exc}", file=sys.stderr)
        return 1

    if args.redact:
        try:
            emit_output(redact_text(raw), args.output)
        except OSError as exc:
            print(f"agent-firewall: could not write output: {exc}", file=sys.stderr)
            return 1
        return 0

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"agent-firewall: invalid JSON input: {exc}", file=sys.stderr)
        return 1

    try:
        policy = load_policy(args.policy) if args.policy else maybe_load_policy()
        custom_rules = load_rulepacks(args.rules)
    except OSError as exc:
        print(f"agent-firewall: could not read policy or rules: {exc}", file=sys.stderr)
        return 1
    except (TypeError, ValueError) as exc:
        print(f"agent-firewall: invalid policy or rules: {exc}", file=sys.stderr)
        return 1

    result = analyze(payload, policy=policy, custom_rules=custom_rules)
    try:
        emit_output(render_result(result, args), args.output)
    except OSError as exc:
        print(f"agent-firewall: could not write output: {exc}", file=sys.stderr)
        return 1

    return exit_code_for(result, fail_on=args.fail_on)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan AI code-agent conversation and tool-event logs.")
    parser.add_argument("input", nargs="?", help="JSON file to scan. Reads stdin when omitted.")
    parser.add_argument("--redact", action="store_true", help="Redact stdin or file text instead of running analysis.")
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format. Defaults to a human-readable text report.",
    )
    parser.add_argument("--compact", action="store_true", help="Emit compact JSON or SARIF for machine output.")
    parser.add_argument("--output", default=None, help="Write the report to a file instead of stdout.")
    parser.add_argument(
        "--policy",
        default=None,
        help="Policy file to apply. Defaults to ./agent-firewall.policy.json when present.",
    )
    parser.add_argument(
        "--rules",
        action="append",
        default=None,
        help="Custom JSON rule pack to load. Can be passed multiple times. Defaults to ./agent-firewall.rules.json when present.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["never", "warn", "block"],
        default="never",
        help="Return a non-zero exit code when the verdict reaches this level.",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=5,
        help="Maximum findings to show in text output. Use 0 to show all findings.",
    )
    parser.add_argument("--version", action="version", version=f"agent-firewall {package_version()}")
    return parser


def read_input(path: str | None) -> str:
    if path:
        return Path(path).read_text(encoding="utf-8-sig")
    return sys.stdin.read()


def render_result(result: AnalysisResult, args: argparse.Namespace) -> str:
    if args.format == "json":
        return format_machine_report(result.to_dict(), compact=args.compact)
    if args.format == "sarif":
        return format_machine_report(result_to_sarif(result), compact=args.compact)
    return format_text_report(result, max_findings=args.max_findings)


def format_machine_report(payload: dict, *, compact: bool = False) -> str:
    indent = None if compact else 2
    separators = (",", ":") if compact else None
    return json.dumps(payload, indent=indent, ensure_ascii=False, separators=separators)


def emit_output(text: str, output: str | None) -> None:
    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text + "\n", encoding="utf-8")
        print(f"agent-firewall: wrote report to {output_path}", file=sys.stderr)
        return
    print(text)


def format_text_report(result: AnalysisResult, *, max_findings: int = 5) -> str:
    lines = [
        f"AgentFirewall: {result.verdict.upper()}",
        f"Risk score: {result.risk_score}/100",
        f"Max severity: {result.max_severity}",
        "",
        result.summary,
    ]

    if not result.findings:
        lines.extend(["", "Findings: none"])
        return "\n".join(lines)

    visible_findings = result.findings if max_findings == 0 else result.findings[:max_findings]
    lines.extend(["", "Findings:"])
    for index, finding in enumerate(visible_findings, start=1):
        lines.extend(format_finding(index, finding))

    remaining = len(result.findings) - len(visible_findings)
    if remaining > 0:
        lines.append(f"  ... {remaining} more finding(s). Use --max-findings 0 or --format json to show all.")

    if result.recommended_controls:
        lines.extend(["", "Recommended controls:"])
        lines.extend(f"- {control}" for control in result.recommended_controls)

    return "\n".join(lines)


def format_finding(index: int, finding: Finding) -> list[str]:
    evidence = finding.evidence[0] if finding.evidence else None
    lines = [
        f"{index}. [{finding.severity}] {finding.title}",
        f"   category: {finding.category}",
        f"   confidence: {finding.confidence:.2f}",
    ]
    if evidence:
        lines.extend(
            [
                f"   source: {evidence.source}",
                f"   evidence: {evidence.excerpt}",
            ]
        )
    lines.append(f"   fix: {finding.recommendation}")
    return lines


def exit_code_for(result: AnalysisResult, *, fail_on: str) -> int:
    if fail_on == "never":
        return 0
    if fail_on == "warn" and result.verdict in {"warn", "block"}:
        return 2 if result.verdict == "warn" else 3
    if fail_on == "block" and result.verdict == "block":
        return 3
    return 0


def package_version() -> str:
    try:
        return version("agent-firewall")
    except PackageNotFoundError:
        return "0.1.0"


if __name__ == "__main__":
    main()
