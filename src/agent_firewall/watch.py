from __future__ import annotations

import sys

from agent_firewall.cli import run


def main() -> None:
    raise SystemExit(run(["--watch", *sys.argv[1:]]))


if __name__ == "__main__":
    main()
