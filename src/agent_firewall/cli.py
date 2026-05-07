from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_firewall.analyzer import analyze
from agent_firewall.redaction import redact_text


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan AI code-agent conversation and tool-event logs.")
    parser.add_argument("input", nargs="?", help="JSON file to scan. Reads stdin when omitted.")
    parser.add_argument("--redact", action="store_true", help="Redact stdin or file text instead of running analysis.")
    args = parser.parse_args()

    raw = read_input(args.input)
    if args.redact:
        print(redact_text(raw))
        return

    payload = json.loads(raw)
    result = analyze(payload)
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))


def read_input(path: str | None) -> str:
    if path:
        return Path(path).read_text(encoding="utf-8")
    return sys.stdin.read()


if __name__ == "__main__":
    main()
