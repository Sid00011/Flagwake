"""The reference response that fixes the 0 of the damage index (company files, rules 2).

It must respect the approval policy it is the yardstick for, and no shipped program may do better
than it: otherwise "0 = the best response" is not true. The original rules keep the list as first
published (the golden fingerprint guards that).
"""

from __future__ import annotations

import pytest

from cyberarena.rc import rules, scoring
from cyberarena.rc.baselines import ALL_AGENTS, run_baseline
from cyberarena.rc.gen2 import DIFFICULTIES
from cyberarena.rc.packs import PRACTICE
from cyberarena.rc.world import SHIPPED, shipped_world


def _incidents(wname: str):
    """One practice seed per family and tier (a different seed for each tier)."""
    w = shipped_world(wname)
    for fam in rules.families(w):
        for i, tier in enumerate(DIFFICULTIES):
            yield w, rules.generate(w, fam, PRACTICE.start + i, tier)


@pytest.mark.parametrize("wname", SHIPPED)
def test_the_reference_never_acts_without_approval(wname):
    for w, inc in _incidents(wname):
        o = scoring.score_shift(run_baseline(inc, "oracle", world=w))
        where = f"{wname}/{inc['family']}/{inc['seed']}/{inc['difficulty']}"
        assert o["approval"]["unauthorised"] == 0, where
        assert o["containment"]["false_containment_actions"] == 0, where


@pytest.mark.parametrize("wname", SHIPPED)
def test_no_shipped_program_does_better_than_the_reference(wname):
    for w, inc in _incidents(wname):
        if inc["truth"].get("quiet"):
            continue
        floor = scoring.oracle_damage(inc, w)
        for name in ALL_AGENTS:
            got = scoring.damage(run_baseline(inc, name, world=w))
            where = f"{wname}/{inc['family']}/{inc['seed']}/{inc['difficulty']} {name}"
            assert got >= floor, f"{where}: {got} < {floor}"


def test_the_reference_is_the_cheapest_of_its_candidate_lists():
    w = shipped_world("harlow-pine")
    live = (rules.generate(w, "approval-required", seed, "standard") for seed in PRACTICE)
    inc = next(i for i in live if not i["truth"].get("quiet"))
    lists = scoring.oracle_candidates(inc, w)
    costs = [scoring.damage(scoring._run(inc, cmds, w)) for cmds in lists]
    assert len(lists) >= 2 and lists[0] == scoring.oracle_base(inc, w)
    assert scoring.oracle_damage(inc, w) == min(costs)
    assert scoring.oracle_commands(inc, w) == lists[costs.index(min(costs))]
    assert min(costs) < costs[0]  # here the published order pays for an action it is denied


def test_the_original_rules_keep_the_published_reference_list():
    w = rules.legacy_world()
    for fam in rules.families(w):
        inc = rules.generate(w, fam, PRACTICE.start, "standard")
        assert scoring.oracle_commands(inc, w) == scoring.oracle_base(inc, w)
        assert scoring.oracle_candidates(inc, w) == [scoring.oracle_base(inc, w)]
