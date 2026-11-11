"""Cross-platform developer tasks (plain Python, so they also run on Windows).

Usage:
    python scripts/dev.py lint     # ruff check, then mypy
    python scripts/dev.py format   # ruff format
    python scripts/dev.py test     # pytest -q
    python scripts/dev.py all      # lint, then test
"""

from __future__ import annotations

import subprocess
import sys

TASKS: dict[str, list[list[str]]] = {
    "lint": [[sys.executable, "-m", "ruff", "check", "."], [sys.executable, "-m", "mypy"]],
    "format": [[sys.executable, "-m", "ruff", "format", "."]],
    "test": [[sys.executable, "-m", "pytest", "-q"]],
}
TASKS["all"] = TASKS["lint"] + TASKS["test"]


def main(argv: list[str]) -> int:
    """Run the named task and return the first non-zero exit code, or 0."""
    if len(argv) != 1 or argv[0] not in TASKS:
        print(f"usage: python scripts/dev.py {{{','.join(TASKS)}}}", file=sys.stderr)
        return 2
    for cmd in TASKS[argv[0]]:
        print("+", " ".join(cmd[2:] if cmd[0] == sys.executable else cmd), flush=True)
        code = subprocess.call(cmd)
        if code != 0:
            return code
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
