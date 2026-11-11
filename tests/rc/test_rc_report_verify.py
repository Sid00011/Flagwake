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
