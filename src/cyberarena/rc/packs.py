"""Scenario packs: the sets of (family, seed, difficulty) a defender is run over.

Seed spaces:
  practice  120000-120999      public: used in docs and examples, for trying things
  heldout   130000-130999      fixed: never shown in docs, the same seeds every run
  fresh     1000000-999999999  drawn for each run from its secret run key (the default for
                               ``flagwake check``, ``run`` and ``tools serve``)
  full      practice and heldout

Each pack takes the first ``per_family`` seeds of its space for every family (``fresh`` draws
them), one difficulty per (family, seed) chosen deterministically so every pack has a mix of
trivial / standard / hard. A fixed set can be learned by anyone with the code; a fresh draw
cannot be known before the run, and the report records the key, so verify re-derives the draw.
``--seeds`` and ``--repeat`` tune the size; a stochastic agent uses ``--repeat`` to run each
incident several times.
"""

from __future__ import annotations

import argparse
import random
from typing import Any

from cyberarena.rc.generator import DIFFICULTIES, FAMILIES
from cyberarena.rc.protocol import RUN_KEY

PRACTICE = range(120_000, 121_000)
HELDOUT = range(130_000, 131_000)
FRESH = range(1_000_000, 1_000_000_000)
PACKS = ("fresh", "heldout", "practice", "full")
PACK_VERSION = "rc-pack-1.0"
DEFAULT_PER_FAMILY = 10


def difficulty_for(family: str, seed: int) -> str:
    """One difficulty per (family, seed), deterministic, weighted toward 'standard'."""
    r = random.Random(f"cyberarena/rc/difficulty/{family}/{seed}")
    return r.choices(DIFFICULTIES, weights=(3, 5, 3))[0]


def _seeds(space: range, per_family: int, offset: int = 0) -> list[int]:
    return [space.start + offset + i for i in range(per_family)]


def draw(key: str, family: str, n: int) -> list[int]:
    """``n`` distinct seeds of :data:`FRESH` for one family, drawn from the run key."""
    return random.Random(f"cyberarena/rc/draw/{key}/{family}").sample(FRESH, n)


def run_key_arg(text: str) -> str:
    """The type of a ``--run-key`` option: 32 lowercase hex characters, as a report records it."""
    if not RUN_KEY.match(text):
        raise argparse.ArgumentTypeError(
            "a run key is 32 lowercase hex characters (a report's run_key)"
        )
    return text


def build_pack(
    which: str = "heldout",
    per_family: int = DEFAULT_PER_FAMILY,
    families: tuple[str, ...] = FAMILIES,
    seeds: list[int] | None = None,
    key: str | None = None,
) -> list[dict[str, Any]]:
    """A list of incident specs: {family, seed, difficulty}. Order is fixed (family, then seed).

    ``fresh`` needs the run's ``key``; the other packs ignore it.
    """
    if seeds is not None:
        fam_seeds = {f: list(seeds) for f in families}
    elif which == "fresh":
        if not key:
            raise ValueError("a fresh pack is drawn from a run key; none was given")
        fam_seeds = {f: draw(key, f, per_family) for f in families}
    elif which == "practice":
        fam_seeds = {f: _seeds(PRACTICE, per_family) for f in families}
    elif which == "heldout":
        fam_seeds = {f: _seeds(HELDOUT, per_family) for f in families}
    elif which == "full":
        fam_seeds = {
            f: _seeds(PRACTICE, per_family) + _seeds(HELDOUT, per_family) for f in families
        }
    else:
        raise ValueError(f"unknown pack {which!r} ({', '.join(PACKS)})")
    out = []
    for family in families:
        for seed in fam_seeds[family]:
            out.append({"family": family, "seed": seed, "difficulty": difficulty_for(family, seed)})
    return out
