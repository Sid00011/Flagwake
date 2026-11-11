"""Weight sensitivity: does the ordering of the shipped programs survive other damage weights?

Usage: python scripts/sensitivity.py [--seeds N] [--json]

Each scoring constant (W_HOLD, W_DOWN, W_ISOLATE, W_EXPOSURE, W_REACH, PAYROLL_MULT and the
records weight) is scaled by 0.5 and by 1.5, one at a time, on the practice pack (default 20
seeds per family). For each variant it prints the clipped mean damage index of every shipped
program except the oracle and do-nothing (which are the index's 0 and 100) and every pair whose
order flips against the published weights. Deterministic.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cyberarena.rc import sanity  # noqa: E402
from cyberarena.rc.packs import build_pack  # noqa: E402

PROGRAMS = sanity.ACTING


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    rows = sanity.finished_shifts(build_pack("practice", per_family=args.seeds), PROGRAMS)
    res = sanity.sensitivity(rows, PROGRAMS)
    if args.json:
        print(json.dumps(res, sort_keys=True, indent=1))
        return 0
    print(f"{len(rows)} live incidents; published order (best first):")
    print("  " + " < ".join(f"{p} {res['base'][p]}" for p in res["order"]))
    flipped: dict[tuple[str, str], list[str]] = {}
    for name, v in res["variants"].items():
        flips = ", ".join(f"{a}/{b}" for a, b in v["flips"]) or "none"
        print(f"{name:18} flips: {flips}")
        for pair in v["flips"]:
            flipped.setdefault(tuple(pair), []).append(name)
    print("\nnot robust (order flips in some variant):" if flipped else "\nevery pair is robust")
    for (a, b), names in sorted(flipped.items()):
        print(f"  {a} vs {b}: {', '.join(names)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
