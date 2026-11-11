"""Which rules an incident runs under, and building incidents for a chosen world.

Rules 1 are the check as first published: the legacy world (``data/world.json``), the twelve
families of ``generator.py``, the thirteen commands. Rules 2 run on any company file: the families
of ``gen2.py`` bind to what the company contains, and the new commands and mechanics apply. The
world object decides the rule set, so a rules-1 report replays exactly as it was made and a
rules-2 report replays against the same company file (its digest is in the report).
"""

from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import Any

from cyberarena.rc import gen2, generator
from cyberarena.rc.world import SHIPPED, WORLD, World, shipped_world, world_from_file

PACK_VERSION_1 = "rc-pack-1.0"
PACK_VERSION_2 = "rc-pack-2.0"


def default_world() -> World:
    """The world a run uses when none is named: the shipped 18-host company under rules 2."""
    return shipped_world()


def legacy_world() -> World:
    """The rules-1 world (the original file format)."""
    return WORLD


@cache
def families(world: World) -> tuple[str, ...]:
    """The families that can run in ``world`` (all twelve under rules 1)."""
    if world.rules == 1:
        return generator.FAMILIES
    return gen2.families_for(world)


@cache
def skipped(world: World) -> tuple[tuple[str, str], ...]:
    """(family, plain reason) for every family the world cannot host; empty under rules 1."""
    if world.rules == 1:
        return ()
    return tuple(gen2.binding_report(world)[1])


def all_families(world: World) -> tuple[str, ...]:
    """Every family of the world's rule set, bound or not (for argument checking)."""
    return generator.FAMILIES if world.rules == 1 else gen2.FAMILIES


def generate(world: World, family: str, seed: int, difficulty: str) -> dict[str, Any]:
    """One incident record of ``family`` in ``world``; raises ValueError when it cannot bind."""
    if world.rules == 1:
        return generator.generate(family, seed, difficulty)
    try:
        return gen2.generate(family, seed, difficulty, world)
    except gen2.Missing as exc:
        raise ValueError(
            f"{exc} (the company file lacks what this family needs; it is skipped)"
        ) from exc


def gen_version(world: World) -> str:
    return generator.GEN_VERSION if world.rules == 1 else gen2.GEN_VERSION


def pack_version(world: World) -> str:
    return PACK_VERSION_1 if world.rules == 1 else PACK_VERSION_2


def header(world: World) -> dict[str, Any]:
    """The report fields that pin the world and rule set (all inside the hashed part)."""
    if world.rules == 1:
        return {}
    return {
        "rules": 2,
        "world": world.summary(),
        "families_skipped": [[f, why] for f, why in skipped(world)],
    }


# Worlds a run used, by digest, so a run result can name its world as plain data (JSON-safe) and
# the report builder can find the object again. A cache only: nothing depends on its order.
_SEEN: dict[tuple[int, str], World] = {}


def world_ref(world: World) -> dict[str, Any]:
    """A JSON-safe reference to ``world`` (remembered for :func:`from_ref`)."""
    _SEEN[(world.rules, world.digest)] = world
    return {"rules": world.rules, "name": world.name, "digest": world.digest}


def from_ref(ref: Any) -> World | None:
    """The world a :func:`world_ref` names, if this process has seen it."""
    if not isinstance(ref, dict):
        return None
    return _SEEN.get((int(ref.get("rules", 1)), str(ref.get("digest", ""))))


class WorldMismatch(ValueError):
    """The world a report names cannot be found or differs from the one given."""


def world_of_report(doc: dict[str, Any], world_file: str | Path | None = None) -> World:
    """The world a report was made in: shipped worlds by name, a custom one from ``world_file``.

    Raises :class:`WorldMismatch` with a plain sentence when the report needs a company file that
    was not given, or the file given is not the one the report was made from (its digest differs).
    """
    if int(doc.get("rules", 1)) == 1:
        return WORLD
    raw = doc.get("world")
    info: dict[str, Any] = raw if isinstance(raw, dict) else {}
    name, digest = str(info.get("name", "")), str(info.get("digest", ""))
    if world_file is not None:
        w = world_from_file(world_file)
    elif not info.get("custom") and name in SHIPPED:
        w = shipped_world(name)
    else:
        raise WorldMismatch(
            f"this report was made on a custom company ({name or 'unnamed'}); give the same "
            "company file with --world <file> to verify it"
        )
    if w.digest != digest:
        raise WorldMismatch(
            f"the company file differs from the one the report was made from (digest "
            f"{w.digest[:12]} here, {digest[:12]} in the report)"
        )
    return w
