"""The run key: incident names a program cannot reverse, and fresh seeds drawn for each run.

A program under test is sent an incident name, never the family or the seed. The name is keyed
with a secret made for the run, so it cannot be rebuilt from the public code; the report records
the key once the run is over, and verify checks everything that depends on it.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from cyberarena.cli import build_parser, main
from cyberarena.rc import packs, rules
from cyberarena.rc.protocol import incident_label, new_run_key
from cyberarena.rc.report import build_report, report_hash
from cyberarena.rc.runner import baseline_driver, run_pack
from cyberarena.rc.sanity import Recorder
from cyberarena.rc.toolsrun import TicketDesk
from cyberarena.rc.verify import verify

KEY = "0123456789abcdef0123456789abcdef"
FAMS = rules.families(rules.default_world())[:3]


def _unkeyed(family: str, seed: int, difficulty: str) -> str:
    """The name an unkeyed hash would give: anyone with the code could rebuild it."""
    blob = f"cyberarena/rc/label/{family}/{seed}/{difficulty}".encode()
    return "i-" + hashlib.sha256(blob).hexdigest()[:12]


def _report(pack: str, key: str = KEY, per_family: int = 2) -> dict:
    specs = packs.build_pack(pack, per_family=per_family, families=FAMS, key=key)
    result = run_pack(lambda: baseline_driver("careful"), specs, key=key)
    return build_report(result, {"id": "careful"}, pack)


def _rehash(doc: dict) -> dict:
    doc["report_hash"] = report_hash(doc)
    return doc


# --------------------------------------------------------------------------- incident names


def test_a_name_cannot_be_rebuilt_from_family_seed_and_difficulty():
    spec = ("cred-reuse", 130007, "hard")
    label = incident_label(*spec, key=KEY)
    assert label.startswith("i-") and len(label) == 14
    assert label != _unkeyed(*spec)
    assert label != incident_label(*spec, key=new_run_key())
    assert label == incident_label(*spec, key=KEY)  # the same key names it the same way


def test_every_run_gets_its_own_key_and_the_report_keeps_it():
    specs = packs.build_pack("practice", per_family=1, families=FAMS)
    a = run_pack(lambda: baseline_driver("careful"), specs)
    b = run_pack(lambda: baseline_driver("careful"), specs)
    assert a["run_key"] != b["run_key"]
    assert len(a["run_key"]) == 32 and int(a["run_key"], 16) >= 0
    doc_a, doc_b = (build_report(r, {"id": "careful"}, "practice") for r in (a, b))
    assert doc_a["run_key"] == a["run_key"] and verify(doc_a) == []
    assert doc_a["metrics"] == doc_b["metrics"]  # the key names incidents; it never moves a score


def test_the_program_is_sent_only_the_keyed_name():
    specs = packs.build_pack("practice", per_family=1, families=FAMS[:1])
    rec = Recorder(baseline_driver("careful"))
    run_pack(lambda: rec, specs, key=KEY)
    s = specs[0]
    want = incident_label(s["family"], s["seed"], s["difficulty"], key=KEY)
    start, end = json.loads(rec.messages[0]), json.loads(rec.messages[-1])
    assert start["type"] == "start" and start["incident"] == want
    assert end["summary"]["incident"] == want
    assert want != _unkeyed(s["family"], s["seed"], s["difficulty"])


def test_tools_tickets_are_named_with_the_run_key():
    specs = packs.build_pack("practice", per_family=1, families=FAMS[:1])
    desk = TicketDesk(specs, key=KEY)
    s = specs[0]
    assert desk.current is not None
    assert desk.current.label == incident_label(s["family"], s["seed"], s["difficulty"], key=KEY)
    desk.stop_all("the test is over")
    assert desk.result()["run_key"] == KEY


# --------------------------------------------------------------------------- fresh seeds


def test_a_fresh_pack_draws_its_seeds_from_the_key():
    a = packs.build_pack("fresh", per_family=4, families=FAMS, key=KEY)
    again = packs.build_pack("fresh", per_family=4, families=FAMS, key=KEY)
    other = packs.build_pack("fresh", per_family=4, families=FAMS, key=new_run_key())
    assert a == again and a != other
    assert len(a) == 12 and [s["family"] for s in a] == [f for f in FAMS for _ in range(4)]
    seeds = [s["seed"] for s in a]
    assert all(s in packs.FRESH for s in seeds)
    assert not any(s in packs.PRACTICE or s in packs.HELDOUT for s in seeds)
    assert all(s["difficulty"] == packs.difficulty_for(s["family"], s["seed"]) for s in a)
    with pytest.raises(ValueError):
        packs.build_pack("fresh", per_family=1, families=FAMS)  # no key, no draw


def test_a_fresh_report_verifies_and_its_seeds_must_follow_from_its_key():
    doc = _report("fresh")
    assert doc["pack"] == "fresh" and doc["run_key"] == KEY
    assert verify(doc) == []
    swapped = _rehash({**doc, "run_key": new_run_key()})
    assert any("run key" in p for p in verify(swapped))


def test_a_report_cannot_claim_a_pack_its_seeds_do_not_come_from():
    practice = _report("practice", per_family=1)
    assert verify(practice) == []
    assert any("pack" in p for p in verify(_rehash({**practice, "pack": "heldout"})))
    assert any("pack" in p for p in verify(_rehash({**practice, "pack": "fresh"})))


# --------------------------------------------------------------------------- commands


@pytest.mark.parametrize("argv", [["check", "--agent", "x"], ["run"], ["tools", "serve"]])
def test_runs_meant_for_results_default_to_a_fresh_pack(argv):
    assert build_parser().parse_args(argv).pack == "fresh"


def test_a_run_key_repeats_the_same_incidents(tmp_path, capsys):
    fam = FAMS[0]
    out = tmp_path / "again"
    argv = ["check", "--agent", "baseline:careful", "--family", fam, "--seeds", "2",
            "--run-key", KEY, "--out", str(out)]  # fmt: skip
    assert main(argv) == 0
    doc = json.loads((out / "report.json").read_text(encoding="utf-8"))
    want = packs.build_pack("fresh", per_family=2, families=(fam,), key=KEY)
    assert doc["run_key"] == KEY and doc["pack"] == "fresh"
    assert [(i["family"], i["seed"]) for i in doc["incidents"]] == [
        (s["family"], s["seed"]) for s in want
    ]
    capsys.readouterr()


@pytest.mark.parametrize("bad", ["not-hex", "abc", "0123456789ABCDEF0123456789abcdef" + "0"])
def test_a_run_key_must_be_32_lowercase_hex_characters(bad):
    with pytest.raises(SystemExit):
        build_parser().parse_args(["check", "--agent", "x", "--run-key", bad])
