"""Report assembly, verification and tamper detection."""

from __future__ import annotations

import copy

import pytest

from cyberarena.rc.metrics import wilson
from cyberarena.rc.report import build_report, rules_hash, terminal_summary
from cyberarena.rc.runner import pack_specs, run_baseline_pack
from cyberarena.rc.verify import verify


@pytest.fixture(scope="module")
def doc():
    res = run_baseline_pack("careful", pack_specs("heldout", 3))
    return build_report(res, {"id": "baseline:careful", "track": "reference"}, pack_name="heldout")


def test_report_verifies_clean(doc):
    assert verify(doc) == []


def test_report_hash_is_deterministic():
    specs = pack_specs("heldout", 2)
    key = "ab" * 16  # the run key is an input like the seeds: the same key, the same report
    a = build_report(run_baseline_pack("rule-bot", specs, key=key))
    b = build_report(run_baseline_pack("rule-bot", specs, key=key))
    assert a["report_hash"] == b["report_hash"]


def test_terminal_summary_is_ascii_and_bounded(doc):
    text = terminal_summary(doc, verified=True)
    text.encode("ascii")  # must not raise
    assert len(text.splitlines()) <= 25
    assert "Scope:" in text and "not yet compared with expert judgement" in text


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["metrics"]["containment"]["true_containment"].__setitem__("num", 999),
        lambda d: d["incidents"][0]["commands"].append("isolate dc-01"),
        lambda d: d["incidents"][0].__setitem__("seed", 999999),
        lambda d: d["incidents"][0]["obs_hashes"].__setitem__(0, "0" * 64),
        lambda d: d.__setitem__("rules_hash", "deadbeef"),
        lambda d: d["incidents"][0]["outcome"]["containment"].__setitem__("contained", 42),
        lambda d: d.__setitem__("report_hash", "f" * 64),
    ],
)
def test_tampering_is_detected(doc, mutate):
    d = copy.deepcopy(doc)
    mutate(d)
    assert verify(d), "verify should report a problem for a tampered report"


def test_a_report_from_another_tool_version_verifies_and_says_so(doc):
    from cyberarena.rc.report import report_hash
    from cyberarena.rc.verify import made_by

    d = copy.deepcopy(doc)
    d["tool_version"] = "0.0.0-another-build"
    assert any("report hash" in p for p in verify(d))  # the version is inside the hashed part
    d["report_hash"] = report_hash(d)
    assert verify(d) == []  # same rules, every number re-derives
    assert "0.0.0-another-build" in made_by(d)
    assert made_by(doc) is None


def test_world_version_mismatch_detected(doc):
    d = copy.deepcopy(doc)
    d["world_version"] = "not-this-world"
    assert any("world version" in p for p in verify(d))


def test_rules_hash_is_stable():
    assert rules_hash() == rules_hash()
    assert len(rules_hash()) == 64


def test_wilson_interval_known_values():
    lo, hi = wilson(1, 1)
    assert 0 <= lo <= 1 and 0 <= hi <= 1
    lo, hi = wilson(5, 10)
    assert lo < 0.5 < hi
    assert wilson(0, 0) == [0.0, 0.0]


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda d: d["metrics"]["damage_index"].__setitem__("mean_clipped", 1.0),
            "metric damage_index.mean_clipped: the report says 1.0, the transcripts give",
        ),
        (
            lambda d: d["incidents"][0]["commands"].__setitem__(1, "isolate dc-01"),
            "observation 2 does not match the replay (command 2 'isolate dc-01'",
        ),
        (
            lambda d: d["incidents"][0].__setitem__("seed", d["incidents"][0]["seed"] + 1),
            "the opening observation does not match the replay (the family, seed or difficulty",
        ),
        (lambda d: d.__setitem__("rules_hash", "deadbeef" * 8), "rules hash mismatch"),
        (
            lambda d: d["traces"][0]["lines"].__setitem__(0, "It did nothing wrong."),
            "the worst-incident traces do not match the transcripts",
        ),
        (lambda d: d.__setitem__("seeds", [1]), "the seed list does not match"),
    ],
)
def test_tampering_gives_a_clear_message(mutate, message):
    res = run_baseline_pack("rule-bot", pack_specs("practice", 1))
    d = build_report(res, {"id": "baseline:rule-bot"}, pack_name="practice")
    assert d["traces"], "rule-bot should have a worst incident to tamper with"
    mutate(d)
    problems = verify(d)
    assert any(message in p for p in problems), problems


def test_repeated_runs_verify():
    from cyberarena.rc.runner import baseline_driver, run_pack

    specs = pack_specs("practice", 1)[:3]
    res = run_pack(lambda: baseline_driver("careful"), specs, repeat=2)
    assert verify(build_report(res, pack_name="practice")) == []


# --------------------------------------------------------------------------- pack and record holes


def _rehash(d):
    from cyberarena.rc.report import report_hash

    d["report_hash"] = report_hash(d)
    return d


def _report(specs, pack="heldout", **kw):
    return build_report(run_baseline_pack("careful", specs, **kw), {"id": "baseline:careful"},
                        pack_name=pack)  # fmt: skip


def test_an_unknown_pack_name_is_refused(doc):
    for name in ("fresh (seeds drawn for this run: use these for claims)", "Fresh", "fresh "):
        d = _rehash({**copy.deepcopy(doc), "pack": name})
        assert any("unknown pack" in p for p in verify(d)), name


def test_a_changed_difficulty_cannot_keep_the_pack_name():
    specs = [{**s, "difficulty": "trivial"} for s in pack_specs("heldout", 2)]
    problems = verify(_report(specs))
    assert any("not the difficulty the heldout pack gives" in p for p in problems), problems
    assert verify(_report(specs, pack="custom")) == []  # honest: chosen by hand


def test_duplicated_or_float_seeded_incidents_are_refused():
    specs = pack_specs("heldout", 2)
    dup = _report(specs + specs[:1])
    assert any("appears more than once" in p for p in verify(dup)), verify(dup)
    floats = _report([{**s, "seed": float(s["seed"])} for s in specs])
    assert any("not a whole number" in p for p in verify(floats)), verify(floats)


def test_skipped_families_are_allowed_but_shown():
    from cyberarena.rc.report import header_notes

    specs = pack_specs("heldout", 2)
    first = specs[0]["family"]
    d = _report([s for s in specs if s["family"] != first])
    assert verify(d) == []
    assert any(n.startswith("families: ") and "left out" in n for n in header_notes(d))
    short = _report([s for s in specs if s["family"] != first] + [specs[0]])  # out of order
    assert any("pack's order" in p or "different numbers" in p for p in verify(short))


def test_commands_after_the_end_are_refused(doc):
    d = copy.deepcopy(doc)
    d["incidents"][0]["commands"] += ["(no reply)", "(no reply)"]
    assert any("stored after the incident ended" in p for p in verify(d)), verify(d)


def test_every_derived_block_must_be_present(doc):
    for block in ("traces", "profile", "harness", "integration"):
        d = copy.deepcopy(doc)
        del d[block]
        assert any(f"no {block} block" in p for p in verify(_rehash(d))), block


def test_the_tools_own_checks_are_covered_by_the_hash(doc):
    d = copy.deepcopy(doc)
    d["agent"]["conformance"] = {"status": "failed", "passed": 3, "total": 9}
    d["agent"]["contamination_warning"] = "practice scores far better than fresh"
    _rehash(d)
    assert verify(d) == []
    d["agent"]["conformance"] = {"status": "passed", "passed": 9, "total": 9}
    del d["agent"]["contamination_warning"]
    assert any("report hash" in p for p in verify(d)), verify(d)


def _rc2_report() -> dict:
    """Made by 0.5.0rc2: `careful` on the practice pack, one seed per family, original rules."""
    import json
    from pathlib import Path

    path = Path(__file__).parent / "report_0.5.0rc2_legacy.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_a_report_made_by_the_previous_version_under_the_original_rules_still_verifies():
    doc = _rc2_report()
    assert doc["tool_version"] == "0.5.0rc2" and "families_available" not in doc
    assert verify(doc) == []


def test_an_older_report_carrying_the_tools_own_checks_is_told_to_run_again():
    doc = _rc2_report()
    doc["agent"]["conformance"] = "7 of 7 checks passed"  # what the older hash left out
    assert any("run it again" in p for p in verify(doc))
    doc["seeds"] = doc["seeds"][1:]
    assert any("seed list" in p for p in verify(doc))
