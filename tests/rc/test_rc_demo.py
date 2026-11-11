"""``flagwake demo``: runs offline, writes a report that verifies, and an edited copy fails."""

from __future__ import annotations

import json

from cyberarena.cli import main
from cyberarena.rc.demo import breakdown, cost_items, cost_totals, tampered_copy
from cyberarena.rc.verify import verify


def test_demo_writes_a_verified_report_and_catches_the_edited_copy(tmp_path, capsys):
    out = tmp_path / "demo"
    assert main(["demo", "--out", str(out)]) == 0
    text = capsys.readouterr().out
    assert "COST BREAKDOWN  careful" in text and "DAMAGE INDEX" in text
    assert "doing nothing would have cost" in text and " pts" in text and "%" in text
    assert "  OK    every score re-derived" in text
    assert "  FAIL  metric damage_index.mean_clipped" in text
    doc = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert verify(doc) == []
    bad = json.loads((out / "report-tampered.json").read_text(encoding="utf-8"))
    assert verify(bad)
    assert (out / "report.html").read_text(encoding="utf-8").startswith("<!doctype html>")
    # the CLI verify agrees: the real report passes, the edited one fails
    assert main(["verify", str(out / "report.json")]) == 0
    assert main(["verify", str(out / "report-tampered.json")]) == 1


def test_breakdown_and_tamper_helpers():
    doc = {
        "incidents": [
            {"commands": ["look", "hosts"],
             "outcome": {"damage": 1200, "do_nothing_damage": 4000, "oracle_damage": 100}},
            {"commands": ["look"],
             "outcome": {"damage": 30, "do_nothing_damage": 0, "oracle_damage": 0}},
        ],
        "metrics": {"damage_index": {"mean_clipped": 12.5}},
        "profile": {"decisions": {"damage_terms": {"hold": 1200, "downtime": 0, "exposure": 30}}},
    }  # fmt: skip
    lines = breakdown(doc, "x")
    assert lines[0] == "COST BREAKDOWN  x: 2 incidents, 3 commands"
    assert any("intruder held machines" in ln and "1,200 pts" in ln and "98%" in ln for ln in lines)
    assert not any("downtime" in line for line in lines)  # zero terms are left out
    assert any("doing nothing would have cost" in ln and "4,000 pts" in ln for ln in lines)
    assert cost_totals(doc) == {"total": 1230, "nothing": 4000, "best": 100}
    assert [i["share"] for i in cost_items(doc)] == [98, 2]
    bad, before, after = tampered_copy(doc)
    assert (before, after) == (12.5, 0.0) and doc["metrics"]["damage_index"]["mean_clipped"] == 12.5


def test_a_report_without_cost_causes_still_shows_its_total():
    """The original rules record an incident's damage but not its causes."""
    doc = {"incidents": [{"commands": [], "outcome": {"damage": 50, "do_nothing_damage": 90,
                                                      "oracle_damage": 10}}],
           "metrics": {"damage_index": {"mean_clipped": 50.0}}}  # fmt: skip
    assert cost_items(doc) == [{"label": "damage (all causes)", "value": 50, "share": 100}]
    assert cost_items({"incidents": [], "metrics": {}}) == []


def test_a_missing_program_is_named_plainly(tmp_path, capsys):
    argv = ["check", "--agent", "no-such-program-xyz --flag", "--pack", "practice", "--seeds", "1",
            "--family", "quiet", "--out", str(tmp_path / "o")]  # fmt: skip
    assert main(argv) == 2
    err = capsys.readouterr().err
    assert "'no-such-program-xyz' was not found" in err and "WinError" not in err
