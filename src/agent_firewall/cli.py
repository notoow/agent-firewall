from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from agent_firewall.analyzer import analyze, redact_result
from agent_firewall.audit import append_audit_record, audit_record
from agent_firewall.baseline import apply_baseline, load_baseline, write_baseline
from agent_firewall.inputs import InputParseError, parse_analysis_input, parse_jsonl_input
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

    if args.watch:
        return run_watch(args)

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
        payload = parse_analysis_input(raw)
    except InputParseError as exc:
        print(f"agent-firewall: invalid input: {exc}", file=sys.stderr)
        return 1

    loaded = load_scan_config(args)
    if isinstance(loaded, int):
        return loaded
    policy, custom_rules, baseline_ids = loaded

    result = scan_payload(payload, policy=policy, custom_rules=custom_rules)
    try:
        maybe_write_baseline(args, result)
        result = apply_baseline(result, baseline_ids, policy=policy)
        maybe_write_audit(args, result, mode="scan", input_text=raw, source_path=args.input)
        emit_output(render_result(result, args), args.output)
    except OSError as exc:
        print(f"agent-firewall: could not write output: {exc}", file=sys.stderr)
        return 1

    return exit_code_for(result, fail_on=args.fail_on)


def run_watch(args: argparse.Namespace) -> int:
    if args.input is None:
        print("agent-firewall: --watch requires a JSONL file path", file=sys.stderr)
        return 1
    if args.redact:
        print("agent-firewall: --watch cannot be combined with --redact", file=sys.stderr)
        return 1
    if args.update_baseline:
        print("agent-firewall: --watch cannot be combined with --update-baseline", file=sys.stderr)
        return 1

    loaded = load_scan_config(args)
    if isinstance(loaded, int):
        return loaded
    policy, custom_rules, baseline_ids = loaded

    path = Path(args.input)
    try:
        return watch_jsonl_file(path, args=args, policy=policy, custom_rules=custom_rules, baseline_ids=baseline_ids)
    except OSError as exc:
        print(f"agent-firewall: watch failed: {exc}", file=sys.stderr)
        return 1


def load_scan_config(args: argparse.Namespace) -> tuple[object, object, set[str]] | int:
    try:
        policy = load_policy(args.policy) if args.policy else maybe_load_policy()
        custom_rules = load_rulepacks(args.rules)
    except OSError as exc:
        print(f"agent-firewall: could not read policy or rules: {exc}", file=sys.stderr)
        return 1
    except (TypeError, ValueError) as exc:
        print(f"agent-firewall: invalid policy or rules: {exc}", file=sys.stderr)
        return 1

    try:
        baseline_ids = load_baseline(args.baseline) if args.baseline else set()
    except OSError as exc:
        print(f"agent-firewall: could not read baseline: {exc}", file=sys.stderr)
        return 1
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"agent-firewall: invalid baseline: {exc}", file=sys.stderr)
        return 1
    return policy, custom_rules, baseline_ids


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan AI code-agent conversation and tool-event logs.")
    parser.add_argument("input", nargs="?", help="JSON or JSONL file to scan. Reads stdin when omitted.")
    parser.add_argument("--redact", action="store_true", help="Redact stdin or file text instead of running analysis.")
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format. Defaults to a human-readable text report.",
    )
    parser.add_argument("--compact", action="store_true", help="Emit compact JSON or SARIF for machine output.")
    parser.add_argument("--output", default=None, help="Write the report to a file instead of stdout.")
    parser.add_argument("--audit-log", default=None, help="Append redacted audit records to a JSONL file.")
    parser.add_argument("--baseline", default=None, help="Suppress finding IDs listed in an AgentFirewall baseline file.")
    parser.add_argument("--update-baseline", default=None, help="Write a baseline file from the current unfiltered scan result.")
    parser.add_argument("--watch", action="store_true", help="Follow a JSONL file and scan records as they are appended.")
    parser.add_argument("--watch-from-end", action="store_true", help="Start watching from the current end of the file.")
    parser.add_argument(
        "--watch-interval",
        type=float,
        default=0.5,
        help="Seconds to sleep between watch polls. Defaults to 0.5.",
    )
    parser.add_argument(
        "--watch-idle-timeout",
        type=float,
        default=None,
        help="Stop watching after this many idle seconds. Mostly useful for automation tests.",
    )
    parser.add_argument(
        "--watch-report",
        choices=["findings", "all"],
        default="findings",
        help="In watch mode, print only warn/block scans or every scanned record.",
    )
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


def emit_output(text: str, output: str | None, *, append: bool = False) -> None:
    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if append else "w"
        with output_path.open(mode, encoding="utf-8") as handle:
            handle.write(text + "\n")
        action = "appended report to" if append else "wrote report to"
        print(f"agent-firewall: {action} {output_path}", file=sys.stderr)
        return
    print(text)


def maybe_write_audit(
    args: argparse.Namespace,
    result: AnalysisResult,
    *,
    mode: str,
    input_text: str | None = None,
    source_path: str | None = None,
    line_number: int | None = None,
) -> None:
    if not args.audit_log:
        return
    append_audit_record(
        args.audit_log,
        audit_record(
            result,
            mode=mode,
            input_text=input_text,
            source_path=source_path,
            line_number=line_number,
        ),
    )


def maybe_write_baseline(args: argparse.Namespace, result: AnalysisResult) -> None:
    if not args.update_baseline:
        return
    write_baseline(args.update_baseline, result)
    print(f"agent-firewall: wrote baseline to {args.update_baseline}", file=sys.stderr)


def watch_jsonl_file(
    path: Path,
    *,
    args: argparse.Namespace,
    policy: object,
    custom_rules: object,
    baseline_ids: set[str],
) -> int:
    position = path.stat().st_size if args.watch_from_end else 0
    buffer = ""
    line_number = 0 if not args.watch_from_end else count_existing_lines(path)
    idle_since = time.monotonic()

    while True:
        if path.stat().st_size < position:
            position = 0
            buffer = ""
        chunk, position = read_new_chunk(path, position)
        if chunk:
            idle_since = time.monotonic()
            buffer, code = process_watch_chunk(
                buffer + chunk,
                args=args,
                policy=policy,
                custom_rules=custom_rules,
                baseline_ids=baseline_ids,
                start_line=line_number,
            )
            line_number += code.processed_lines
            if code.exit_code:
                return code.exit_code
        elif args.watch_idle_timeout is not None and time.monotonic() - idle_since >= args.watch_idle_timeout:
            if buffer.strip():
                _, code = process_watch_chunk(
                    buffer + "\n",
                    args=args,
                    policy=policy,
                    custom_rules=custom_rules,
                    baseline_ids=baseline_ids,
                    start_line=line_number,
                )
                line_number += code.processed_lines
                if code.exit_code:
                    return code.exit_code
            return 0

        sleep_for = max(0.0, args.watch_interval)
        if sleep_for:
            time.sleep(sleep_for)


@dataclass(frozen=True)
class WatchChunkResult:
    processed_lines: int = 0
    exit_code: int = 0


def read_new_chunk(path: Path, position: int) -> tuple[str, int]:
    with path.open("rb") as handle:
        handle.seek(position)
        data = handle.read()
        new_position = handle.tell()
    return data.decode("utf-8-sig" if position == 0 else "utf-8"), new_position


def process_watch_chunk(
    text: str,
    *,
    args: argparse.Namespace,
    policy: object,
    custom_rules: object,
    baseline_ids: set[str],
    start_line: int,
) -> tuple[str, WatchChunkResult]:
    complete, pending = split_complete_lines(text)
    processed = 0
    for offset, line in enumerate(complete, start=1):
        if not line.strip():
            processed += 1
            continue
        line_number = start_line + offset
        try:
            payload = parse_jsonl_input(line, start_line=line_number)
        except InputParseError as exc:
            print(f"agent-firewall: invalid JSONL watch input at line {line_number}: {exc}", file=sys.stderr)
            return pending, WatchChunkResult(processed_lines=processed + 1, exit_code=1)
        result = scan_payload(payload, policy=policy, custom_rules=custom_rules)
        result = apply_baseline(result, baseline_ids, policy=policy)
        try:
            maybe_write_audit(args, result, mode="watch", input_text=line, source_path=args.input, line_number=line_number)
        except OSError as exc:
            print(f"agent-firewall: could not write audit log: {exc}", file=sys.stderr)
            return pending, WatchChunkResult(processed_lines=processed + 1, exit_code=1)
        if args.watch_report == "all" or result.verdict != "pass":
            try:
                emit_watch_result(result, args=args, line_number=line_number)
            except OSError as exc:
                print(f"agent-firewall: could not write watch output: {exc}", file=sys.stderr)
                return pending, WatchChunkResult(processed_lines=processed + 1, exit_code=1)
        processed += 1
        exit_code = exit_code_for(result, fail_on=args.fail_on)
        if exit_code:
            return pending, WatchChunkResult(processed_lines=processed, exit_code=exit_code)
    return pending, WatchChunkResult(processed_lines=processed, exit_code=0)


def split_complete_lines(text: str) -> tuple[list[str], str]:
    lines = text.splitlines(keepends=True)
    if not lines:
        return [], ""
    if not lines[-1].endswith(("\n", "\r")):
        return [line.rstrip("\r\n") for line in lines[:-1]], lines[-1]
    return [line.rstrip("\r\n") for line in lines], ""


def emit_watch_result(result: AnalysisResult, *, args: argparse.Namespace, line_number: int) -> None:
    rendered = render_result(result, args)
    if args.format == "text":
        rendered = f"AgentFirewall watch: {args.input}:{line_number}\n{rendered}"
    emit_output(rendered, args.output, append=True)


def scan_payload(payload: dict, *, policy: object, custom_rules: object) -> AnalysisResult:
    return redact_result(analyze(payload, policy=policy, custom_rules=custom_rules))


def count_existing_lines(path: Path) -> int:
    with path.open("rb") as handle:
        return sum(1 for _ in handle)


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
