"""Checks of the checker on small slices: no leak in what a program is sent (and the scan catches
the old family:seed label), null agents never score well, and a seeded agent re-runs identically."""

from __future__ import annotations

from cyberarena.rc import protocol, sanity
from cyberarena.rc.generator import FAMILIES
from cyberarena.rc.packs import build_pack
from cyberarena.rc.report import build_report, report_hash
from cyberarena.rc.runner import run_pack

SPECS = [{"family": f, "seed": 130000, "difficulty": "standard"} for f in FAMILIES]


def test_no_ground_truth_reaches_a_program():
    assert sanity.leak_scan(SPECS, ("careful", "gullible", "random-valid")) == []


def test_the_scan_catches_a_family_and_seed_label(monkeypatch):
    monkeypatch.setattr(protocol, "incident_label", lambda f, s, d, key: f"{f}:{s}")
    assert sanity.leak_scan(SPECS[:3], ("careful",))


def test_null_agents_do_not_score_well():
    specs = build_pack("heldout", per_family=1)
    for name in sanity.NULL_AGENTS:
        m = build_report(run_pack(sanity.null_factory(name), specs), {"id": name})["metrics"]
        assert m["damage_index"]["mean_clipped"] >= 90, name


def test_a_seeded_random_agent_reruns_identically():
    specs = build_pack("heldout", per_family=1)
    key = "5eed" * 8  # the run key is an input like the seeds: the same key, the same report
    a, b = (build_report(run_pack(sanity.null_factory("random-valid"), specs, key=key),
                         {"id": "r"}) for _ in range(2))  # fmt: skip
    assert report_hash(a) == report_hash(b)


def test_a_weight_variant_moves_the_index_and_is_undone():
    from cyberarena.rc import scoring

    rows = sanity.finished_shifts(build_pack("practice", per_family=1), ("careful", "rule-bot"))
    before = sanity.mean_index(rows, "careful")
    with sanity.weights("W_HOLD", 0.5):
        assert sanity.mean_index(rows, "careful") != before
    assert scoring.W_HOLD == 2 and sanity.mean_index(rows, "careful") == before
    res = sanity.sensitivity(rows, ("careful", "rule-bot"))
    assert len(res["variants"]) == 2 * len(sanity.WEIGHTS)
    assert res["order"] == ["careful", "rule-bot"]


def test_the_check_scripts_run():
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    runs = (
        ("sensitivity.py", ["--seeds", "1"]),
        ("sanity_checks.py", ["--part", "c", "--part", "d", "--seeds", "1"]),
    )
    for script, args in runs:
        proc = subprocess.run([sys.executable, str(root / "scripts" / script), *args],
                              capture_output=True, text=True, timeout=300)  # fmt: skip
        assert proc.returncode == 0, proc.stderr
    assert "hits: []" in proc.stdout and "same_commands: true" in proc.stdout


def test_skipping_an_approval_never_pays():
    """An unapproved critical action costs a change-control review: without that cost the same
    command lists are never worse, and the oracle without its approvals is now worse than with."""
    rows = sanity.finished_shifts(build_pack("practice", per_family=2), sanity.ACTING)
    for program in sanity.ACTING:
        with sanity.weights("W_UNAPPROVED", 0):
            free = sanity.mean_index(rows, program)
        assert sanity.mean_index(rows, program) >= free, program
    effect = sanity.approval_effect(build_pack("practice", per_family=5))
    for family in ("late-staging", "approval-required"):
        assert effect[family]["skip"] > effect[family]["oracle"], (family, effect[family])
