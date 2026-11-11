"""The original world answers every ordinary and malformed command exactly as the release that
first published rules 1 did, so transcripts stored under rules 1 keep replaying."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_rules1_observations_are_byte_identical_to_the_first_release():
    want = json.loads((ROOT / "tests" / "rc" / "rules1_texts.json").read_text(encoding="utf-8"))
    spec = importlib.util.spec_from_file_location("rules1_texts", ROOT / "scripts" /
                                                  "rules1_texts.py")  # fmt: skip
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.COMMANDS == want["commands"]
    fresh = mod.texts()
    for fam, hashes in want["hashes"].items():
        for i, (a, b) in enumerate(zip(fresh[fam], hashes, strict=True)):
            what = "the opening" if i == 0 else repr(want["commands"][i - 1])
            assert a == b, f"{fam}: the answer to {what} changed"
