"""Check the checker on the shipped companies (rules 2): the counterpart of sanity_checks.py.

Usage: python scripts/company_checks.py [--world NAME|FILE ...] [--seeds N] [--part a|b|c|d|e|f]
                                        [--pack heldout|practice] [--json]

a: four null programs (do nothing, an empty report, always all-clear, seeded random valid
   commands) next to the careful reference program: index and quiet incidents closed cleanly.
b: the reference response: families where it is no better than doing nothing, touches a clean
   target or acts without approval (none expected).
c: every observation and tool response sent to three programs, scanned for ground-truth tokens.
d: the careful program run twice under one run key: the same report hash.
e: the order of the shipped programs under half and double of each damage weight.
f: per family, careful against rule-bot and the incidents where the acting programs tie.
Defaults: both shipped companies, the held-out pack, 5 seeds per family (under a minute).
Deterministic; prints plain tables (or JSON). Exit code 1 if a, b, c or d finds a problem.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cyberarena.rc import rules, sanity2  # noqa: E402
from cyberarena.rc.packs import build_pack  # noqa: E402
from cyberarena.rc.world import SHIPPED, resolve_world  # noqa: E402

PARTS = "abcdef"


def run(world_arg: str, pack: str, seeds: int, parts: str) -> dict:
    world = resolve_world(world_arg)
    specs = build_pack(pack, per_family=seeds, families=rules.families(world))
    out: dict = {"incidents": len(specs)}
    if "a" in parts:
        out["a_null_programs"] = sanity2.null_programs(world, specs)
    if "b" in parts:
        out["b_reference_problems"] = sanity2.reference_problems(world, specs)
    if "c" in parts:
        out["c_leaks"] = sanity2.leaks(world, specs)
    if "d" in parts:
        out["d_retest_identical"] = sanity2.retest_identical(world, specs[:30])
    if "e" in parts:
        out["e_weights"] = sanity2.weight_orders(world, specs)
    if "f" in parts:
        out["f_separation"] = sanity2.separation(world, specs)
    return out


def failed(res: dict) -> bool:
    nulls = res.get("a_null_programs", {})
    scored_well = any((nulls[n]["index"] or 0) < 90 for n in sanity2.NULLS if n in nulls)
    return bool(scored_well or res.get("b_reference_problems") or res.get("c_leaks")
                or res.get("d_retest_identical") is False)  # fmt: skip


def show(name: str, res: dict) -> None:
    print(f"== {name}: {res['incidents']} incidents")
    if "a_null_programs" in res:
        print("a  null programs (index; quiet incidents closed cleanly)")
        for prog, row in res["a_null_programs"].items():
            print(
                f"   {prog:<14}{row['index']!s:>7}   {row['quiet_closed_cleanly']}/{row['quiet']}"
            )
    if "b_reference_problems" in res:
        print(f"b  reference response: {res['b_reference_problems'] or 'no problem in any family'}")
    if "c_leaks" in res:
        print(f"c  leak scan: {res['c_leaks'] or 'no ground-truth token found'}")
    if "d_retest_identical" in res:
        print(f"d  same run key, same report hash: {res['d_retest_identical']}")
    if "e_weights" in res:
        e = res["e_weights"]
        print("e  order by mean index: " + ", ".join(f"{n} {e['means'][n]}" for n in e["default"]))
        print(f"   first two keep their order under every change: {e['top_two_stable']}")
        for change, order in e["changes"].items():
            print(f"   {change:<16} first four: {', '.join(order[:4])}")
    if "f_separation" in res:
        print("f  family                          careful  rule-bot  all three tie")
        for fam, row in res["f_separation"].items():
            print(f"   {fam:<32}{row['careful']!s:>7}{row['rule-bot']!s:>10}"
                  f"   {row['all_three_tie']}/{row['incidents']}")  # fmt: skip


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--world", action="append", help="a shipped company or a company file")
    ap.add_argument("--seeds", type=int, default=5, help="seeds per family (default 5)")
    ap.add_argument("--pack", choices=("heldout", "practice"), default="heldout")
    ap.add_argument("--part", default=PARTS, help="which parts to run, e.g. ab (default all)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if not set(args.part) <= set(PARTS):
        ap.error(f"--part takes letters from {PARTS}")
    results = {w: run(w, args.pack, args.seeds, args.part) for w in args.world or SHIPPED}
    if args.json:
        print(json.dumps(results, indent=1, sort_keys=True))
    else:
        for name, res in results.items():
            show(name, res)
    return 1 if any(failed(r) for r in results.values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
