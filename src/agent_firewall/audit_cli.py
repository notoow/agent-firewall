from __future__ import annotations

import argparse
import json

from agent_firewall.audit import verify_audit_log
from agent_firewall.cli import package_version


def main() -> None:
    raise SystemExit(run())


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "verify":
        return run_verify(args.audit_log, format=args.format)

    parser.print_help()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect AgentFirewall audit logs.")
    parser.add_argument("--version", action="version", version=f"agent-firewall {package_version()}")
    subparsers = parser.add_subparsers(dest="command")

    verify = subparsers.add_parser("verify", help="Verify a tamper-evident audit JSONL log.")
    verify.add_argument("audit_log", help="Path to an AgentFirewall audit JSONL file.")
    verify.add_argument("--format", choices=["text", "json"], default="text", help="Verification output format.")
    return parser


def run_verify(audit_log: str, *, format: str = "text") -> int:
    result = verify_audit_log(audit_log)
    if format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(format_verify_report(result, audit_log=audit_log))
    return 0 if result["valid"] else 1


def format_verify_report(result: dict, *, audit_log: str) -> str:
    status = "PASS" if result["valid"] else "FAIL"
    lines = [
        f"AgentFirewall Audit: {status}",
        f"Log: {audit_log}",
        f"Records: {result['records']}",
        f"Last hash: {result['last_record_hash'] or 'none'}",
    ]
    if result["errors"]:
        lines.append("")
        lines.append("Errors:")
        lines.extend(f"- line {error['line']}: {error['message']}" for error in result["errors"])
    return "\n".join(lines)


if __name__ == "__main__":
    main()
