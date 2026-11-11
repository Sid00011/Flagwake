"""The golden determinism check: fixed baselines on fixed seeds reproduce tests/rc/golden.json."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from cyberarena.rc import golden as golden_mod
from cyberarena.rc.golden import golden

ROOT = Path(__file__).resolve().parents[2]
WANT = json.loads((ROOT / "tests" / "rc" / "golden.json").read_text(encoding="utf-8"))


def test_baselines_reproduce_the_golden_hashes():
    fresh = golden()
    assert fresh["programs"] == WANT["programs"]
    assert fresh == WANT


def test_the_golden_check_passes_under_another_hash_seed():
    env = {**os.environ, "PYTHONHASHSEED": "12345"}
    res = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "golden_check.py")],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == WANT["fingerprint"]


def test_a_changed_weight_moves_the_fingerprint(monkeypatch):
    monkeypatch.setattr(golden_mod, "score_shift", _shifted_score)
    assert golden()["fingerprint"] != WANT["fingerprint"]


def _shifted_score(shift):
    from cyberarena.rc.scoring import score_shift

    out = score_shift(shift)
    return {**out, "damage": out["damage"] + 1}


def test_rules2_programs_reproduce_their_golden_hashes():
    from cyberarena.rc.golden import golden2

    want2 = json.loads((ROOT / "tests" / "rc" / "golden2.json").read_text(encoding="utf-8"))
    assert golden2() == want2
