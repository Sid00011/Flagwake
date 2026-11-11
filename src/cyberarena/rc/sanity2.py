"""Checks of the checker on a company file (rules 2), the counterpart of ``sanity.py``.

Six parts, each a plain function over one company and a list of incident specs:

a  null programs (do nothing, an empty report, always all-clear, seeded random valid commands)
   must not score well;
b  the reference response is never worse than doing nothing and never touches a clean target;
c  nothing a program is sent (observations, and the tool responses of the same decisions) carries
   a ground-truth token;
d  the same run under the same run key gives the same report hash;
e  the order of the shipped programs under half and double of each damage weight;
f  per family, careful against rule-bot, and incidents where the acting programs tie.

``scripts/company_checks.py`` prints them; the test suite runs them on a small slice. Everything is
deterministic: the random program draws from a stream seeded by the company's name, and a weight
is changed only inside a context manager.
"""

from __future__ import annotations

import contextlib
import functools
import json
import random
import re
import statistics as st
from collections.abc import Iterator
from typing import Any

from cyberarena.rc import rules, scoring
from cyberarena.rc.baselines import ALL_AGENTS, run_baseline
from cyberarena.rc.engine import RULES2_COMMANDS, Shift
from cyberarena.rc.report import build_report
from cyberarena.rc.runner import baseline_driver, run_pack
from cyberarena.rc.world import World

PROGRAMS = ("do-nothing", "isolate-on-first-alert", "rule-bot", "careful", "thorough", "gullible",
            "paranoid", "slow")  # fmt: skip
NULLS = ("do-nothing", "empty-report", "all-clear", "random-valid")
SCANNED = ("careful", "gullible", "paranoid")
FACTORS = (0.5, 2.0)
RETEST_KEY = "5eed" * 8

Spec = dict[str, Any]


def incidents(world: World, specs: list[Spec]) -> list[dict[str, Any]]:
    return [rules.generate(world, s["family"], s["seed"], s["difficulty"]) for s in specs]


def mean_index(outcomes: list[dict[str, Any]]) -> float | None:
    """The clipped mean damage index over the live incidents (None when there is none)."""
    values = [min(200, o["index"]) for o in outcomes if o["index"] is not None]
    return round(st.mean(values), 1) if values else None


def _score(world: World, incident: dict[str, Any], commands: list[str]) -> dict[str, Any]:
    return scoring.score_shift(scoring._run(incident, commands, world))


def random_commands(world: World, rng: random.Random) -> list[str]:
    """Twenty valid commands on random targets, then a report naming up to two random hosts."""
    hosts, accounts, flows = world.host_names, world.accounts, list(world.flows)
    out = ["look"]
    for _ in range(20):
        verb = rng.choice(RULES2_COMMANDS[:-1])
        target = {
            "logs": rng.choice(hosts), "who": rng.choice(accounts), "isolate": rng.choice(hosts),
            "restore": rng.choice(hosts), "patch": rng.choice(hosts), "release": rng.choice(hosts),
            "block": rng.choice(accounts), "reset": rng.choice(accounts),
            "pause": rng.choice(flows), "resume": rng.choice(flows),
            "wait": str(rng.randint(1, 30)),
            "notify": rng.choice(list(world.roles) or ["x"]) + " update",
            "ask": rng.choice(list(world.people)) + " signed-in",
        }.get(verb, "")  # fmt: skip
        out.append(f"{verb} {target}".strip())
    claimed = rng.sample(hosts, rng.randint(0, 2))
    out.append("report " + json.dumps({"compromised": claimed}))
    return out


def null_programs(world: World, specs: list[Spec]) -> dict[str, dict[str, Any]]:
    """Part a: each null program's index and how many quiet incidents it closed cleanly, with
    the careful reference program beside them."""
    incs = incidents(world, specs)
    rng = random.Random(f"cyberarena/rc/sanity2/{world.name}")
    lists = {
        "do-nothing": lambda: ["look"],
        "empty-report": lambda: ["report {}"],
        "all-clear": lambda: ['report {"compromised": [], "summary": "all clear"}'],
        "random-valid": lambda: random_commands(world, rng),
    }
    rows: dict[str, list[dict[str, Any]]] = {
        name: [_score(world, inc, lists[name]()) for inc in incs] for name in NULLS
    }
    rows["careful"] = [scoring.score_shift(run_baseline(i, "careful", world=world)) for i in incs]
    out = {}
    for name, outcomes in rows.items():
        quiet = [o for o in outcomes if o["quiet"]]
        out[name] = {
            "index": mean_index(outcomes),
            "quiet": len(quiet),
            "quiet_closed_cleanly": sum(1 for o in quiet if o["restraint_ok"]),
        }
    return out


def reference_problems(world: World, specs: list[Spec]) -> dict[str, dict[str, int]]:
    """Part b: families where the reference response did no better than doing nothing on a live
    incident, acted on a clean target, or acted without approval (empty when all is well)."""
    out: dict[str, dict[str, int]] = {}
    for spec, inc in zip(specs, incidents(world, specs), strict=True):
        o = scoring.score_shift(run_baseline(inc, "oracle", world=world))
        row = out.setdefault(spec["family"], {"not_better": 0, "clean_targets": 0, "unapproved": 0})
        row["not_better"] += bool(not o["quiet"] and o["oracle_damage"] >= o["do_nothing_damage"])
        row["clean_targets"] += o["containment"]["false_containment_actions"]
        row["unapproved"] += o["approval"]["unauthorised"]
    return {fam: row for fam, row in out.items() if any(row.values())}


def leaks(world: World, specs: list[Spec], programs: tuple[str, ...] = SCANNED) -> list[str]:
    """Part c: ground-truth tokens in what a program is sent, as observations and as the tool
    responses of the same decisions (empty when nothing leaks)."""
    from cyberarena.rc.toolsapi import ToolIncident
    from cyberarena.rc.toolsrun import native_to_call

    sources = frozenset(x["source"] for x in world.log_sources)
    found = []
    for spec, inc in zip(specs, incidents(world, specs), strict=True):
        tokens = [re.escape(spec["family"]), re.escape(inc["truth"]["notes"][:30]),
                  r'"truth"', r'"siphons"', r'"required_evidence"']  # fmt: skip
        for name in programs:
            seen = list(run_baseline(inc, name, world=world).observations)
            served = ToolIncident(Shift(inc, world), "i-000000000000")
            program = ALL_AGENTS[name]()
            seen.append(json.dumps(served.opening))
            while not served.done:
                line = program.next_command(served.shift)
                if line is None:
                    break
                seen.append(json.dumps(served.call(*native_to_call(line, sources))))
            text = "\n".join(seen)
            found += [f"{spec['family']}:{spec['seed']} {name}: {tok[:30]}"
                      for tok in tokens if re.search(tok, text)]  # fmt: skip
    return found


def retest_identical(world: World, specs: list[Spec]) -> bool:
    """Part d: two runs of the careful program under one run key give the same report hash."""
    hashes = []
    for _ in range(2):
        result = run_pack(functools.partial(baseline_driver, "careful"), specs, world=world,
                          key=RETEST_KEY)  # fmt: skip
        hashes.append(build_report(result, {"id": "retest"}, world=world)["report_hash"])
    return hashes[0] == hashes[1]


@contextlib.contextmanager
def weight(key: str, factor: float) -> Iterator[None]:
    """One default damage weight scaled by ``factor`` (at least 1) while the block runs."""
    old = scoring.DEFAULT_WEIGHTS[key]
    scoring.DEFAULT_WEIGHTS[key] = max(1, round(old * factor))
    try:
        yield
    finally:
        scoring.DEFAULT_WEIGHTS[key] = old


def weight_orders(world: World, specs: list[Spec]) -> dict[str, Any]:
    """Part e: the shipped programs ordered by mean index under the default weights, and every
    half or double of one weight under which the first four change places."""
    incs = incidents(world, specs)
    shifts = {n: [run_baseline(inc, n, world=world) for inc in incs] for n in PROGRAMS}

    def order() -> tuple[list[str], dict[str, float | None]]:
        means = {n: mean_index([scoring.score_shift(s) for s in shifts[n]]) for n in PROGRAMS}
        ranked = sorted(means, key=lambda n: (means[n] is None, means[n]))
        return ranked, means

    default, means = order()
    changes: dict[str, list[str]] = {}
    for key in scoring.DEFAULT_WEIGHTS:
        for factor in FACTORS:
            with weight(key, factor):
                ranked, _m = order()
            if ranked[:4] != default[:4]:
                changes[f"{key} x{factor:g}"] = ranked
    return {"default": default, "means": means, "changes": changes,
            "top_two_stable": all(r[:2] == default[:2] for r in changes.values())}  # fmt: skip


def separation(world: World, specs: list[Spec]) -> dict[str, dict[str, Any]]:
    """Part f: per family, the careful and rule-bot indexes and how many incidents the three
    acting reference programs (rule-bot, careful, thorough) finish with the same damage."""
    by_family: dict[str, list[dict[str, Any]]] = {}
    for spec, inc in zip(specs, incidents(world, specs), strict=True):
        by_family.setdefault(spec["family"], []).append(inc)
    out = {}
    for family, incs in by_family.items():
        scores = {n: [scoring.score_shift(run_baseline(i, n, world=world)) for i in incs]
                  for n in ("rule-bot", "careful", "thorough")}  # fmt: skip
        ties = sum(1 for k in range(len(incs))
                   if len({scores[n][k]["damage"] for n in scores}) == 1)  # fmt: skip
        out[family] = {"careful": mean_index(scores["careful"]),
                       "rule-bot": mean_index(scores["rule-bot"]),
                       "all_three_tie": ties, "incidents": len(incs)}  # fmt: skip
    return out
