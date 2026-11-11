"""The Defender profile: recomputed by verify (so an edited number fails), honest about sample
size, and built only from what the transcripts show."""

from __future__ import annotations

import copy

import pytest

from cyberarena.rc import sanity
from cyberarena.rc.html import build_html
from cyberarena.rc.packs import build_pack
from cyberarena.rc.report import build_report, report_hash, terminal_summary
from cyberarena.rc.runner import baseline_driver, run_pack
from cyberarena.rc.verify import verify
from cyberarena.rc.world import WORLD

# The comparisons below were fixed on the legacy world's twelve incidents (rules 1).
SPECS = build_pack("practice", per_family=1)


def _doc(factory, specs=SPECS, repeat=1, name="t"):
    return build_report(run_pack(factory, specs, repeat=repeat, world=WORLD), {"id": name},
                        "practice", world=WORLD)  # fmt: skip


@pytest.fixture(scope="module")
def rule_bot():
    return _doc(lambda: baseline_driver("rule-bot"), name="baseline:rule-bot")


def test_the_profile_is_present_and_verifies(rule_bot):
    prof = rule_bot["profile"]
    assert set(prof) >= {"families", "taxonomy", "harness_vs_behaviour", "behaviour_vs_baselines",
                         "findings", "cost", "n"}  # fmt: skip
    assert len(prof["findings"]) == 3
    assert [r["score"] for r in prof["behaviour_vs_baselines"]][:2] == ["damage index",
                                                                         "containment"]  # fmt: skip
    assert verify(rule_bot) == []


@pytest.mark.parametrize(
    "edit",
    [
        lambda p: p["taxonomy"]["wrong_target"].update(events=99),
        lambda p: p["findings"].__setitem__(0, "Contained everything perfectly."),
        lambda p: p["behaviour_vs_baselines"][0]["vs"]["careful"].update(verdict="better"),
        lambda p: p["families"][0].update(contained=99),
        lambda p: p["cost"].update(commands=1),
    ],
)  # fmt: skip
def test_an_edited_profile_number_fails_verify(rule_bot, edit):
    doc = copy.deepcopy(rule_bot)
    edit(doc["profile"])
    assert report_hash(doc) == doc["report_hash"]  # derived parts sit outside the hash...
    problems = verify(doc)
    assert problems and problems[0].startswith("profile ")  # ...and verify recomputes them


def test_comparisons_are_paired_on_the_same_incidents(rule_bot):
    """The verdict comes from the per-incident difference: a program against itself is "the
    same"; rule-bot against careful is already "worse" on 12 incidents (the two overall intervals
    overlap there, so comparing intervals could not tell them apart)."""
    row = rule_bot["profile"]["behaviour_vs_baselines"][0]
    assert row["vs"]["rule-bot"]["verdict"] == "the same" and row["vs"]["rule-bot"]["diff"] == 0
    careful = row["vs"]["careful"]
    assert careful["verdict"] == "worse" and careful["diff_ci95"][0] > 0
    lo, hi = row["ci95"]
    assert lo <= careful["ci95"][1] and careful["ci95"][0] <= hi  # the intervals do overlap


def test_close_programs_are_too_close_to_call():
    doc = _doc(lambda: baseline_driver("isolate-everything"), name="baseline:isolate-everything")
    row = doc["profile"]["behaviour_vs_baselines"][0]
    assert row["vs"]["rule-bot"]["verdict"] == "too few incidents to conclude"
    assert "too few incidents to conclude" in terminal_summary(doc, True)


def test_the_profile_says_how_many_incidents_a_firm_answer_needs(rule_bot):
    power = rule_bot["profile"]["power"]
    assert power["against"] == "careful" and power["points"] == 10
    assert power["live_needed"] > power["live_now"]  # 12 incidents are not enough here


def test_a_clear_gap_is_called_worse():
    doc = _doc(lambda: baseline_driver("paranoid"), build_pack("practice", per_family=3))
    row = doc["profile"]["behaviour_vs_baselines"][0]
    assert row["vs"]["careful"]["verdict"] == "worse"


def test_the_quiet_incident_trap_is_spelled_out():
    doc = _doc(sanity.null_factory("all-clear"))
    assert doc["metrics"]["restraint"]["rate"] == 1.0
    assert doc["profile"]["findings"][0].startswith("Closed")
    assert "but contained no compromised host" in doc["profile"]["findings"][0]


def test_harness_and_behaviour_problems_are_told_apart():
    def make():
        seq = iter(["(invalid reply)", "(model call failed: timeout)", "scan everything", "look"])
        return lambda _s: next(seq, None)

    prof = _doc(make)["profile"]
    h = prof["harness_vs_behaviour"]
    n = len(SPECS)
    assert h["placeholder_commands"] == 2 * n
    assert h["behaviour_unrecognised_commands"] == n
    assert prof["taxonomy"]["unrecognised"]["events"] == 3 * n
    assert prof["taxonomy"]["froze"]["incidents"] == prof["n"]["live"]


def test_an_overconfident_report_is_counted():
    def make():
        seq = iter(["look", 'report {"compromised": ["dc-01"], "confidence": {"dc-01": 0.95}}'])
        return lambda _s: next(seq, None)

    specs = [{"family": "quiet", "seed": 120000, "difficulty": "standard"}]
    prof = _doc(make, specs)["profile"]
    assert prof["taxonomy"]["overconfident_report"] == {"incidents": 1, "events": 1}


def test_repeats_give_a_run_to_run_spread():
    doc = _doc(sanity.null_factory("random-valid"), SPECS[:6], repeat=3)
    spread = doc["profile"]["repeat_spread"]
    assert spread["repeats"] == 3 and spread["min"] <= spread["max"]
    assert "Run-to-run spread over 3 repeats" in terminal_summary(doc, True)
    assert verify(doc) == []


def test_the_profile_is_escaped_and_the_summary_stays_short(rule_bot):
    doc = copy.deepcopy(rule_bot)
    doc["profile"]["findings"][0] = "<script>alert(1)</script>"
    html = build_html(doc, True)
    assert "<script>alert" not in html and "&lt;script&gt;" in html
    assert "Defender profile" in html
    text = terminal_summary(rule_bot, True)
    assert len(text.splitlines()) <= 25
    text.encode("ascii")


def test_a_baseline_interval_matches_its_own_report():
    doc = _doc(lambda: baseline_driver("careful"), name="baseline:careful")
    row = doc["profile"]["behaviour_vs_baselines"][0]
    assert row["vs"]["careful"]["ci95"] == doc["metrics"]["damage_index"]["ci95"]
    assert row["ci95"] == doc["metrics"]["damage_index"]["ci95"]
