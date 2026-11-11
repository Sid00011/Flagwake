"""The checks of the checker on a company file, on a small slice (scripts/company_checks.py runs
them in full): null programs never score well, the reference response is sound, nothing leaks,
a run repeats under its key, and the two best programs keep their order under other weights."""

from __future__ import annotations

import pytest

from cyberarena.rc import rules, sanity2, scoring
from cyberarena.rc.packs import build_pack
from cyberarena.rc.world import SHIPPED, shipped_world


@pytest.fixture(scope="module", params=SHIPPED)
def case(request):
    world = shipped_world(request.param)
    return world, build_pack("heldout", per_family=1, families=rules.families(world))


def test_null_programs_do_not_score_well(case):
    rows = sanity2.null_programs(*case)
    assert all(rows[name]["index"] >= 90 for name in sanity2.NULLS)
    assert rows["careful"]["index"] < 90
    assert rows["all-clear"]["quiet_closed_cleanly"] == rows["all-clear"]["quiet"] > 0
    assert rows["do-nothing"]["quiet_closed_cleanly"] == 0  # it never reports, so it closes none


def test_the_reference_response_is_sound_and_nothing_leaks(case):
    assert sanity2.reference_problems(*case) == {}
    assert sanity2.leaks(*case) == []


def test_a_run_repeats_under_its_key_and_the_best_two_keep_their_order(case):
    world, specs = case
    assert sanity2.retest_identical(world, specs[:6])
    before = dict(scoring.DEFAULT_WEIGHTS)
    orders = sanity2.weight_orders(world, specs)
    assert orders["default"][:2] == ["thorough", "careful"] and orders["top_two_stable"]
    assert scoring.DEFAULT_WEIGHTS == before  # every weight is put back


def test_separation_counts_every_incident_once(case):
    world, specs = case
    rows = sanity2.separation(world, specs)
    assert sum(r["incidents"] for r in rows.values()) == len(specs)
    assert rows["backup-looks-like-exfil"]["careful"] < rows["backup-looks-like-exfil"]["rule-bot"]


def test_the_script_runs_and_reports_no_problem(capsys):
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "scripts" / "company_checks.py"
    spec = importlib.util.spec_from_file_location("company_checks", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main(["--world", "harlow-pine", "--seeds", "1", "--part", "abcd"]) == 0
    out = capsys.readouterr().out
    assert "no ground-truth token found" in out and "same report hash: True" in out
