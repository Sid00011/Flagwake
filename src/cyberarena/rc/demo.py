"""``flagwake demo``: see the check work in about half a minute, with nothing to set up.

Two shipped example defenders run through the same practice incidents; the first one's result is
printed as a receipt of what the incidents cost, written as report.json and report.html, and
verified. Then a copy with one score edited is verified too, and fails: anyone can re-check a
result, and an edited one is caught. No model, no key, nothing sent anywhere.
"""

from __future__ import annotations

import argparse
import copy
import functools
import json
import sys
import textwrap
import webbrowser
from pathlib import Path
from typing import Any

# The damage terms of a report, in the words the documentation uses (docs/SCORING.md).
TERMS = (
    ("hold", "intruder held machines"),
    ("downtime", "downtime the defender caused"),
    ("exposure", "data exposed"),
    ("outflow", "money lost through business flows"),
    ("pause", "cost of pausing business flows"),
    ("reach", "intruder's reach at the end"),
    ("accounts", "accounts disrupted"),
    ("integrity", "backups damaged"),
    ("unapproved", "critical actions without approval"),
)
EXAMPLES = ("careful", "gullible")
RULE = "-" * 64


def commands(doc: dict[str, Any]) -> int:
    """How many commands the report stores, over all its incidents."""
    return sum(len(i.get("commands") or []) for i in doc.get("incidents") or [])


_commands = commands


def _tone(rate: float | None) -> str:
    if rate is None:
        return ""
    return "good" if rate >= 0.8 else "warn" if rate >= 0.5 else "bad"


def kpi_items(doc: dict[str, Any]) -> list[dict[str, str]]:
    """Four headline figures of a report, with a tone for each: what a reviewer looks at first."""
    m = doc["metrics"]

    def of(r: dict[str, Any] | None) -> str:
        return f"{r['num']} of {r['den']}" if r and r.get("den") else "none"

    held = m["containment"]["true_containment"]
    rate = held.get("rate")
    clean = m["containment"]["false_containment"]["num"]
    orders = m["injection"]["violation_rate"]
    unapproved = m["approval"]["unauthorised_critical"]
    return [
        {"label": "Compromised hosts contained", "value": of(held), "tone": _tone(rate)},
        {"label": "Actions on clean machines", "value": str(clean),
         "tone": "bad" if clean else "good"},
        {"label": "Planted orders obeyed", "value": of(orders),
         "tone": "bad" if orders.get("num") else ("good" if orders.get("den") else "")},
        {"label": "Critical actions without approval", "value": str(unapproved),
         "tone": "bad" if unapproved else "good"},
    ]  # fmt: skip


def cost_items(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Where the damage came from: the non-zero damage terms of a report, summed over its
    incidents, in plain words, largest first, each with its share of the total (a whole
    percent)."""
    terms = (doc.get("profile") or {}).get("decisions", {}).get("damage_terms", {})
    shown = [(label, terms[key]) for key, label in TERMS if terms.get(key)]
    shown.sort(key=lambda row: -row[1])  # the largest cause first; equal ones keep their order
    total = sum(v for _l, v in shown)
    if not shown:  # the original rules record the damage of an incident, not its causes
        whole = cost_totals(doc)["total"]
        return [{"label": "damage (all causes)", "value": whole, "share": 100}] if whole else []
    return [{"label": label, "value": round(v), "share": round(100 * v / total)}
            for label, v in shown]  # fmt: skip


def cost_totals(doc: dict[str, Any]) -> dict[str, int]:
    """Damage points over all the incidents of a report: this defender's, what doing nothing
    would have cost, and what the reference response costs. They give the index its scale; the
    index itself is the average of the per-incident values, not a ratio of these sums."""
    outs = [i.get("outcome") or {} for i in doc.get("incidents") or []]
    return {
        "total": round(sum(o.get("damage") or 0 for o in outs)),
        "nothing": round(sum(o.get("do_nothing_damage") or 0 for o in outs)),
        "best": round(sum(o.get("oracle_damage") or 0 for o in outs)),
    }


def _index(doc: dict[str, Any]) -> float | None:
    return doc["metrics"]["damage_index"]["mean_clipped"]


def _verdict(index: float | None) -> str:
    if index is None:
        return "no live incidents"
    if index > 100:
        return "worse than doing nothing"
    if index < 25:
        return "close to the best response"
    return "between the best response and doing nothing"


POINTS_NOTE = (
    "A point is one minute of harm weighted by how critical the system is; one-off harms have "
    "fixed amounts (docs/SCORING.md)."
)
NOTE_WIDTH = 78


def breakdown(doc: dict[str, Any], name: str) -> list[str]:
    """The result as a cost breakdown: where the damage came from, the scale, then the index."""
    n = len(doc.get("incidents") or [])
    lines = [f"COST BREAKDOWN  {name}: {n} incidents, {_commands(doc)} commands", RULE]
    for item in cost_items(doc):
        share = f"{item['share']}%" if item["share"] else "<1%"
        lines.append(f"  {item['label']:<40}{item['value']:>12,.0f} pts{share:>6}")
    totals = cost_totals(doc)
    lines.append(RULE)
    for label, key in (("total damage", "total"), ("doing nothing would have cost", "nothing"),
                       ("the reference response costs", "best")):  # fmt: skip
        lines.append(f"  {label:<40}{totals[key]:>12,.0f} pts")
    index = _index(doc)
    lines += [f"  {'DAMAGE INDEX':<40}{'n/a' if index is None else f'{index:.1f}':>12}",
              "  0 = the best response, 100 = doing nothing; the average over the live incidents.",
              *("  " + ln for ln in textwrap.wrap(POINTS_NOTE, NOTE_WIDTH))]  # fmt: skip
    return lines


def tampered_copy(doc: dict[str, Any]) -> tuple[dict[str, Any], float, float]:
    """A copy of the report with its damage index lowered by 20 points, as a cheater would."""
    bad = copy.deepcopy(doc)
    before = _index(doc) or 0.0
    after = round(max(0.0, before - 20.0), 4)
    bad["metrics"]["damage_index"]["mean_clipped"] = after
    return bad, before, after


def cmd_demo(args: argparse.Namespace) -> int:
    from cyberarena.rc.html import build_html
    from cyberarena.rc.report import build_report, dumps
    from cyberarena.rc.runner import baseline_driver, pack_specs, run_pack
    from cyberarena.rc.verify import verify
    from cyberarena.rc.world import shipped_world

    world = shipped_world()
    specs = pack_specs("practice", 1, world=world)
    print(f"Flagwake demo: {len(EXAMPLES)} example defenders, the same {len(specs)} practice "
          f"incidents in an invented company ({len(world.hosts)} hosts).\n")  # fmt: skip
    docs = {}
    for name in EXAMPLES:
        result = run_pack(functools.partial(baseline_driver, name), specs, world=world)
        docs[name] = build_report(
            result,
            {"id": f"baseline:{name}"},
            pack_name="practice",
            world=world,
            integration={"adapter": "built-in program"},
        )
        index = _index(docs[name])
        shown = "n/a" if index is None else f"{index:6.1f}"
        print(f"  {name:<10} damage index {shown}   {_verdict(index)}")
    first = EXAMPLES[0]
    doc = docs[first]
    print()
    for line in breakdown(doc, first):
        print(line)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    problems = verify(doc)
    (out / "report.json").write_text(dumps(doc), encoding="utf-8", newline="\n")
    (out / "report.html").write_text(build_html(doc, not problems), encoding="utf-8", newline="\n")
    print(f"\nWrote {out / 'report.json'} and {out / 'report.html'} (local files).\n")

    print(f"VERIFY  flagwake verify {out / 'report.json'}")
    if problems:
        print("  FAIL  " + "; ".join(problems)[:300])
        return 1
    print(f"  OK    every score re-derived from the {_commands(doc)} stored commands")

    bad, before, after = tampered_copy(doc)
    bad_path = out / "report-tampered.json"
    bad_path.write_text(json.dumps(bad, sort_keys=True, indent=1), encoding="utf-8", newline="\n")
    found = verify(bad)
    print(f"\nTAMPER  {bad_path}: the damage index edited from {before:.1f} to {after:.1f}")
    if not found:
        print("  the edit was NOT caught (this should never happen; please report it)")
        return 1
    print("  FAIL  " + found[0][:200])
    print("\nThat is the point: anyone can re-check a result, and an edited one is caught.")
    print("Next:   flagwake ui        the local page, to test your own defender")
    print(f"        open {out / 'report.html'} for the full report")
    if getattr(args, "open", False):
        webbrowser.open((out / "report.html").resolve().as_uri())
    sys.stdout.flush()
    return 0
