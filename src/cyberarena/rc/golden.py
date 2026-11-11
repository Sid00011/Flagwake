"""The golden determinism check: fixed baselines on fixed seeds must reproduce the same hashes.

Every shipped scripted program runs the first two practice seeds of every family (24 incidents
each, at the difficulty the pack assigns). For each incident the hash covers the commands, the
hash of every observation and the full scored outcome; each program's hash covers its incidents
in order, and the fingerprint covers the programs. A change anywhere in the generator, the
interpreter, the baselines or the scoring moves the fingerprint. ``tests/rc/golden.json`` keeps
the expected values; ``scripts/golden_check.py`` compares (CI) or rewrites them after a
deliberate, recorded change.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cyberarena.rc.baselines import ALL_AGENTS, run_baseline
from cyberarena.rc.generator import GEN_VERSION, WORLD_VERSION, generate
from cyberarena.rc.packs import build_pack
from cyberarena.rc.report import rules_hash
from cyberarena.rc.runner import obs_hash
from cyberarena.rc.scoring import score_shift

SEEDS_PER_FAMILY = 2


def _sha(obj: Any) -> str:
    blob = json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


def golden() -> dict[str, Any]:
    """The versions, each program's hash over its incidents, and the overall fingerprint."""
    specs = build_pack("practice", per_family=SEEDS_PER_FAMILY)
    incidents = {s["family"] + ":" + str(s["seed"]): s for s in specs}
    programs: dict[str, str] = {}
    for name in sorted(ALL_AGENTS):
        per_incident = []
        for key, spec in incidents.items():
            shift = run_baseline(generate(spec["family"], spec["seed"], spec["difficulty"]), name)
            per_incident.append(
                _sha(
                    {
                        "incident": key,
                        "commands": shift.commands,
                        "observations": [obs_hash(t) for t in shift.observations],
                        "outcome": score_shift(shift),
                    }
                )
            )
        programs[name] = _sha(per_incident)
    return {
        "gen_version": GEN_VERSION,
        "world_version": WORLD_VERSION,
        "rules_hash": rules_hash(),
        "incidents": len(incidents),
        "programs": programs,
        "fingerprint": _sha(programs),
    }


def golden2() -> dict[str, Any]:
    """The rules-2 fingerprint: every shipped program on the first practice seed of every family
    of both shipped companies (tests/rc/golden2.json; the rules-1 file above never changes)."""
    from cyberarena.rc import rules
    from cyberarena.rc.world import SHIPPED, shipped_world

    programs: dict[str, str] = {}
    worlds = {}
    for wname in SHIPPED:
        w = shipped_world(wname)
        worlds[wname] = w.digest
        specs = build_pack("practice", per_family=1, families=rules.families(w))
        for name in sorted(ALL_AGENTS):
            per_incident = []
            for spec in specs:
                inc = rules.generate(w, spec["family"], spec["seed"], spec["difficulty"])
                shift = run_baseline(inc, name, world=w)
                per_incident.append(_sha({
                    "incident": f"{wname}:{spec['family']}:{spec['seed']}",
                    "commands": shift.commands,
                    "observations": [obs_hash(t) for t in shift.observations],
                    "outcome": score_shift(shift),
                }))  # fmt: skip
            programs[f"{wname}/{name}"] = _sha(per_incident)
    return {
        "gen_version": rules.gen_version(shipped_world()),
        "rules_hash": rules_hash(2),
        "worlds": worlds,
        "programs": programs,
        "fingerprint": _sha(programs),
    }
