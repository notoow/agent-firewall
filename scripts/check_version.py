from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path


def main() -> None:
    raise SystemExit(run())


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check AgentFirewall release version consistency.")
    parser.add_argument("--tag", help="Optional git tag such as v0.1.0.")
    parser.add_argument("--pyproject", default="pyproject.toml", help="Path to pyproject.toml.")
    args = parser.parse_args(argv)

    try:
        version = read_project_version(Path(args.pyproject))
        if args.tag:
            tag_version = normalize_tag(args.tag)
            if tag_version != version:
                print(f"version mismatch: tag {args.tag} != pyproject {version}", file=sys.stderr)
                return 1
    except (OSError, ValueError, KeyError) as exc:
        print(f"version check failed: {exc}", file=sys.stderr)
        return 1

    print(f"version ok: {version}")
    return 0


def read_project_version(path: Path) -> str:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    version = str(data["project"]["version"])
    validate_version(version)
    return version


def normalize_tag(tag: str) -> str:
    if not tag.startswith("v"):
        raise ValueError("release tag must start with 'v', for example v0.1.0")
    version = tag[1:]
    validate_version(version)
    return version


def validate_version(version: str) -> None:
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:[a-zA-Z0-9_.-]+)?", version):
        raise ValueError(f"invalid version: {version}")


if __name__ == "__main__":
    main()
