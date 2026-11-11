"""Golden determinism check of the Responder Check (see ``cyberarena.rc.golden``).

Prints the rules-1 fingerprint and compares every hash with tests/rc/golden.json (rules 1, the
original world) and tests/rc/golden2.json (rules 2, the shipped company files); exits 1 on any
difference and names what moved. ``--write`` rewrites both files after a deliberate change that is
recorded in docs/METHODOLOGY.md (a new generator version or rules hash).

Usage: python scripts/golden_check.py [--write]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cyberarena.rc.golden import golden, golden2  # noqa: E402

GOLDEN = ROOT / "tests" / "rc" / "golden.json"
GOLDEN2 = ROOT / "tests" / "rc" / "golden2.json"


def _moved(want: dict, fresh: dict, prefix: str = "") -> list[str]:
    out = [
        prefix + k
        for k in sorted(set(want) | set(fresh))
        if k != "programs" and want.get(k) != fresh.get(k)
    ]
    wp, fp = want.get("programs", {}), fresh.get("programs", {})
    out += [f"{prefix}programs.{p}" for p in sorted(set(wp) | set(fp)) if wp.get(p) != fp.get(p)]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="rewrite the golden files")
    args = ap.parse_args()
    fresh, fresh2 = golden(), golden2()
    if args.write:
        for path, doc in ((GOLDEN, fresh), (GOLDEN2, fresh2)):
            text = json.dumps(doc, sort_keys=True, indent=1) + "\n"
            path.write_text(text, encoding="utf-8", newline="\n")
            print(f"wrote {path.relative_to(ROOT).as_posix()}")
    print(fresh["fingerprint"])
    if args.write:
        return 0
    moved = _moved(json.loads(GOLDEN.read_text(encoding="utf-8")), fresh)
    moved += _moved(json.loads(GOLDEN2.read_text(encoding="utf-8")), fresh2, "rules 2: ")
    for k in moved:
        print(f"moved: {k}", file=sys.stderr)
    return 1 if moved else 0


if __name__ == "__main__":
    raise SystemExit(main())
