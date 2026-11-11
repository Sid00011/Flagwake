"""Hashes of the original world's answers to ordinary and malformed commands (rules 1).

Stored transcripts made under rules 1 replay only if every observation text is unchanged, including
the error and usage messages no scripted program ever triggers. This script runs a fixed list of
commands, in one fresh incident per family, and prints the SHA-256 of each observation;
tests/rc/rules1_texts.json keeps the values computed by the release that first published rules 1,
and tests/rc/test_rc_rules1_texts.py compares.

Usage: python scripts/rules1_texts.py > tests/rc/rules1_texts.json   (only from that release)
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cyberarena.rc.engine import Shift  # noqa: E402
from cyberarena.rc.generator import FAMILIES, generate  # noqa: E402

COMMANDS = [
    "look", "hosts", "logs", "logs no-such-host", "logs web-01 abc", "logs web-01 99999",
    "logs db-01 30", "who", "who nobody", "who svc-backup", "ask", "ask k.mori",
    "ask k.mori nothing", "ask nobody travelling", "isolate", "isolate no-such-host",
    "isolate web-01 xx", "block", "block 1.2.3.4", "block 203.0.113.55", "reset", "reset nobody",
    "patch no-such-host", "restore no-such-host", "escalate", "escalate patch web-01 5",
    "escalate isolate", "escalate isolate no-such-host", "escalate isolate dc-01",
    "escalate isolate dc-01", "escalate reset k.mori", "wait", "wait 0", "wait abc", "wait 200",
    "pause orders", "resume orders", "notify security-lead hello", "release web-01",
    "frobnicate now", "isolate ws-ops-01 300", "look", "report not json",
]  # fmt: skip


def texts() -> dict[str, list[str]]:
    out = {}
    for fam in FAMILIES:
        s = Shift(generate(fam, 120000, "standard"))
        hashes = [hashlib.sha256(s.reset()["text"].encode("utf-8")).hexdigest()]
        for c in COMMANDS:
            if s.done:
                break
            obs, _ = s.step(c)
            hashes.append(hashlib.sha256(obs["text"].encode("utf-8")).hexdigest())
        out[fam] = hashes
    return out


if __name__ == "__main__":
    print(json.dumps({"commands": COMMANDS, "hashes": texts()}, indent=1, sort_keys=True))
