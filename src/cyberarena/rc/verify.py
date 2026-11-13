"""Re-derive every number in a Responder Check report from its transcripts.

``verify(doc)`` rebuilds each incident from (family, seed, difficulty), replays the stored commands
through a fresh interpreter, recomputes every observation hash and the per-incident outcome, then
recomputes the aggregate metrics, the worst-incident traces, the summary of agent problems and the
report hash, and compares all of it to what the report claims. It returns a list of problems, each
saying where the report and the replay first disagree; an empty list means the report checks out.
There is no model and no judge anywhere: a report cannot pass unless its own commands reproduce its
own numbers.

Mismatches caught: an edited metric, a changed command, a swapped seed, a tampered observation
hash, an edited trace or Defender profile number, a different rules hash or world version, a
different company file (its digest), an edited fidelity disclosure, and a changed report hash.

A report made by an earlier version of the tool verifies when its rules hash is one this build
implements and every number re-derives; :func:`made_by` says which version made it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cyberarena import __version__
from cyberarena.rc import rules
from cyberarena.rc.engine import MAX_COMMANDS, Shift
from cyberarena.rc.metrics import aggregate
from cyberarena.rc.protocol import RUN_KEY
from cyberarena.rc.report import (
    SCHEMA,
    harness_summary,
    integration_block,
    report_hash,
    report_hash_before_rc3,
    rules_hash,
    worst_traces,
)
from cyberarena.rc.runner import obs_hash
from cyberarena.rc.scoring import score_shift
from cyberarena.rc.world import World


def made_by(doc: dict[str, Any]) -> str | None:
    """A note when the report was made by another version of the tool (None for this one)."""
    v = doc.get("tool_version") if isinstance(doc, dict) else None
    if v and v != __version__:
        return f"made by flagwake {v} (this is {__version__})"
    return None


def _replay(incident_doc: dict[str, Any], world: World, key: str = "") -> tuple[Shift, list[str]]:
    spec = incident_doc
    inc = rules.generate(world, spec["family"], spec["seed"], spec["difficulty"])
    shift = Shift(inc, world)
    if "calls" in spec:  # served as tools: re-run the calls through the same mapping
        from cyberarena.rc.protocol import incident_label
        from cyberarena.rc.toolsapi import replay_calls

        label = incident_label(spec["family"], spec["seed"], spec["difficulty"], key=key)
        if "repeat" in spec:
            label += f"-r{spec['repeat']}"
        calls = spec["calls"] if isinstance(spec["calls"], list) else []
        ti = replay_calls(shift, label, calls)
        if ti.commands != spec.get("commands"):
            raise ValueError("the recorded commands do not follow from the recorded tool calls")
        if ti.sent_hashes != spec.get("sent_hashes"):
            raise ValueError("the hashes of what was sent do not match a replay of the calls")
        return ti.shift, ti.obs_hashes
    commands = spec["commands"]
    if not isinstance(commands, list) or not all(isinstance(c, str) for c in commands):
        raise ValueError("the commands are not a list of text lines")
    first = shift.reset()
    hashes = [obs_hash(first["text"])]
    for n, cmd in enumerate(commands):
        if shift.done or n >= MAX_COMMANDS:  # nothing after the end was ever sent to the world
            raise ValueError(f"{len(commands) - n} command(s) are stored after the incident ended")
        obs, _ = shift.step(cmd)
        hashes.append(obs_hash(obs["text"]))
    shift.finish()
    return shift, hashes


def verify(doc: Any, world_file: str | Path | None = None) -> list[str]:
    """Return a list of problems; empty means the report verifies.

    A report made on a custom company needs the same company file (``world_file``); a shipped
    company is found by name. Either way the file's digest must match the report's.
    """
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        return [f"not a {SCHEMA} report"]
    if doc.get("rules", 1) not in (1, 2):
        return [f"unknown rules {str(doc.get('rules'))[:20]} (this build implements 1 and 2)"]
    try:
        world = rules.world_of_report(doc, world_file)
    except (rules.WorldMismatch, ValueError) as exc:
        return [str(exc)]
    problems = _header_problems(doc, world)
    incidents = doc.get("incidents")
    if not isinstance(incidents, list) or not incidents:
        problems.append("no incidents in the report")
        return problems

    key = doc.get("run_key", "")
    if not isinstance(key, str) or (key and not RUN_KEY.match(key)):
        problems.append("the run key is not 32 hex characters")
        key = ""
    outcomes, replayed = _replay_all(incidents, world, key, problems)
    if problems and len(outcomes) < len(incidents):
        return problems
    problems.extend(_derived_problems(doc, world, key, incidents, outcomes, replayed))
    return problems


def _header_problems(doc: dict[str, Any], world: World) -> list[str]:
    """The versions, the rules hash and the company record of a report against this build."""
    problems: list[str] = []
    rh = rules_hash(world.rules)
    if doc.get("world_version") != world.version:
        problems.append(f"world version mismatch: report {doc.get('world_version')}")
    if doc.get("gen_version") != rules.gen_version(world):
        problems.append(f"generator version mismatch: report {doc.get('gen_version')}")
    if doc.get("pack_version", rules.pack_version(world)) != rules.pack_version(world):
        problems.append(f"pack version mismatch: report {doc.get('pack_version')}")
    if doc.get("rules_hash") != rh:
        problems.append(
            f"rules hash mismatch: the report says {str(doc.get('rules_hash'))[:12]}, this build "
            f"is {rh[:12]} (the scoring rules differ)"
        )
    if world.rules >= 2:
        want = rules.header(world)
        for key in ("world", "families_skipped"):
            if doc.get(key) != want[key]:
                problems.append(f"the report's {key} record does not match the company file")
    return problems


def _replay_all(
    incidents: list[Any], world: World, key: str, problems: list[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Replay every incident from its stored commands; (outcomes, incidents as replayed).
    What does not match the record is added to ``problems``."""
    outcomes: list[dict[str, Any]] = []
    replayed: list[dict[str, Any]] = []
    for inc in incidents:
        label = f"{inc.get('family')}:{inc.get('seed')}" if isinstance(inc, dict) else "?"
        seed = inc.get("seed") if isinstance(inc, dict) else None
        if not isinstance(seed, int) or isinstance(seed, bool):  # 120000.0 is another incident
            problems.append(f"incident {label}: the seed is not a whole number")
            continue
        try:
            shift, hashes = _replay(inc, world, key)
        except Exception as exc:  # a bad family/seed/command in the record
            problems.append(f"incident {label}: cannot replay ({type(exc).__name__}: {exc})")
            continue
        claimed = inc.get("obs_hashes")
        if hashes != claimed:
            problems.append(f"incident {label}: {_first_hash_gap(hashes, claimed, inc)}")
        outcome = score_shift(shift)
        if "repeat" in inc:
            outcome = {**outcome, "repeat": inc["repeat"]}
        outcomes.append(outcome)
        replayed.append({**inc, "end_reason": shift.end_reason})
        where = _first_diff(outcome, inc.get("outcome"))
        if where:
            problems.append(f"incident {label}: outcome {where}")
    return outcomes, replayed


def _derived_problems(
    doc: dict[str, Any],
    world: World,
    key: str,
    incidents: list[dict[str, Any]],
    outcomes: list[dict[str, Any]],
    replayed: list[dict[str, Any]],
) -> list[str]:
    """Everything a report derives from its incidents, recomputed: the seed list, the pack, the
    metrics, the fidelity disclosure, the traces, the profile, the harness summary, the hash."""
    problems: list[str] = []
    seeds = sorted({inc["seed"] for inc in incidents})
    if doc.get("seeds") != seeds:
        problems.append("the seed list does not match the incidents in the report")
    problems.extend(pack_problems(doc.get("pack"), incidents, key, rules.families(world)))
    available = len(rules.families(world))
    if "families_available" in doc:
        if doc["families_available"] != available:
            problems.append("the number of families this company can host does not match")
    elif doc.get("pack") not in UNCHECKED_PACKS and len({i["family"] for i in incidents}) < (
        available
    ):
        # A report from before 0.5.0rc3 has no count; it verifies only if it left none out.
        problems.append("the report leaves out families this company can host and does not say so")
    if "provenance" in doc:  # a claim until verify --provenance checks its signature
        from cyberarena.rc.provenance import record_problems

        problems.extend(record_problems(doc["provenance"]))
    for block in ("integration", "traces", "profile", "harness"):
        if block not in doc:  # every report this tool writes has them; a missing one hides findings
            problems.append(f"the report has no {block} block")
    rh = rules_hash(world.rules)
    where = _first_diff(aggregate(outcomes, seed="rc-" + rh[:8]), doc.get("metrics"))
    if where:
        problems.append(f"metric {where}")
    if "integration" in doc:
        integ = doc["integration"] if isinstance(doc["integration"], dict) else {}
        try:
            fresh = integration_block(
                incidents,
                str(integ.get("mode")),
                str(integ.get("adapter", "")),
                str(integ.get("instruction_text", "")),
            )
        except (KeyError, TypeError):
            fresh = {}
        if fresh != integ:
            problems.append("the fidelity disclosure does not match what the transcripts sent")
    if "traces" in doc and doc["traces"] != worst_traces(replayed, outcomes):
        problems.append("the worst-incident traces do not match the transcripts")
    if "profile" in doc:
        from cyberarena.rc.profile import build_profile

        where = _first_diff(build_profile(incidents, outcomes, world), doc["profile"])
        if where:
            problems.append(f"profile {where}")
    if "harness" in doc and doc["harness"] != harness_summary(incidents):
        problems.append("the summary of agent problems does not match the incidents")
    if doc.get("report_hash") != report_hash(doc):
        if doc.get("report_hash") == report_hash_before_rc3(doc):
            problems.append("report hash made by 0.5.0rc2 or earlier, which did not cover the "
                            "tool's own checks (conformance, warnings): run it again")  # fmt: skip
        else:
            problems.append("report hash does not match the report's own contents")
    return problems


UNCHECKED_PACKS = ("custom", "mcp")  # incidents chosen by hand, or an MCP client's log


def pack_problems(
    pack: Any, incidents: list[dict[str, Any]], key: str, order: tuple[str, ...] = ()
) -> list[str]:
    """Whether the incidents are exactly what the named pack gives.

    For each family the seeds must be the start of the pack's sequence (a fixed pack's first
    seeds, or the draw a fresh pack's run key makes), each with the difficulty the pack gives that
    seed, repeats numbered from 0 with no duplicates, every family with the same number of seeds
    and in the pack's family order (only the last family of a run stopped early may end short).
    A family left out entirely is allowed and shown in the report's header. "custom" and "mcp"
    claim no pack; any other name is refused.
    """
    from cyberarena.rc import packs

    if pack in UNCHECKED_PACKS:
        return []
    if pack not in packs.PACKS:
        known = ", ".join((*packs.PACKS, *UNCHECKED_PACKS))
        return [f"unknown pack {str(pack)[:40]!r} (known: {known})"]
    if pack == "fresh" and not key:
        return ["a fresh pack needs the run key it was drawn from; the report has none"]
    by_family: dict[str, list[int]] = {}
    runs: dict[tuple[str, int], list[Any]] = {}
    for inc in incidents:
        family, seed = inc["family"], inc["seed"]
        if inc.get("difficulty") != packs.difficulty_for(family, seed):
            return [f"incident {family}:{seed}: not the difficulty the {pack} pack gives this seed"]
        seen = by_family.setdefault(family, [])
        if seed not in seen:
            seen.append(seed)
        runs.setdefault((family, seed), []).append(inc.get("repeat"))
    problem = _repeat_problem(runs) or _order_problem(list(by_family), order)
    if problem:
        return [problem]
    sizes = [len(seeds) for seeds in by_family.values()]
    if len(set(sizes[:-1])) > 1 or (len(sizes) > 1 and sizes[-1] > sizes[0]):
        return ["the families have different numbers of incidents (only the last family of a run "
                "stopped early may end short)"]  # fmt: skip
    for family, got in by_family.items():
        if got != _pack_seeds(pack, family, got, key):
            if pack == "fresh":
                return [f"the {family} seeds are not the fresh pack's draw from the run key"]
            return [f"the {family} seeds are not the start of the {pack} pack's seeds"]
    return []


def _pack_seeds(pack: str, family: str, got: list[int], key: str) -> list[int]:
    """The seeds the pack gives ``family``, as many as ``got`` holds."""
    from cyberarena.rc import packs

    n = len(got)
    if pack == "fresh":
        return packs.draw(key, family, n)
    if pack == "full":  # the practice seeds, then the held-out ones
        p = sum(1 for s in got if s in packs.PRACTICE)
        return [packs.PRACTICE.start + i for i in range(p)] + [
            packs.HELDOUT.start + i for i in range(n - p)
        ]
    space = packs.PRACTICE if pack == "practice" else packs.HELDOUT
    return [space.start + i for i in range(n)]


def _repeat_problem(runs: dict[tuple[str, int], list[Any]]) -> str | None:
    """Each incident once, or its repeats numbered 0, 1, 2 ... (a run stopped early may end one
    incident's repeats short, but every earlier incident has the full number)."""
    counts = []
    for (family, seed), reps in runs.items():
        if reps == [None]:
            counts.append(1)
            continue
        if None in reps or sorted(reps) != list(range(len(reps))):
            return f"incident {family}:{seed} appears more than once without distinct repeats"
        counts.append(len(reps))
    if len(set(counts[:-1])) > 1 or (len(counts) > 1 and counts[-1] > counts[0]):
        return "the incidents were not all repeated the same number of times"
    return None


def _order_problem(families: list[str], order: tuple[str, ...]) -> str | None:
    """The families appear in the pack's order (so the one that may end short is the last)."""
    if not order:
        return None
    unknown = [f for f in families if f not in order]
    if unknown:
        return f"family {unknown[0]!r} is not part of this company's families"
    idx = [order.index(f) for f in families]
    return None if idx == sorted(idx) else "the families are not in the pack's order"


def _first_hash_gap(replay: list[str], claimed: Any, inc: dict[str, Any]) -> str:
    if not isinstance(claimed, list):
        return "observation hashes are missing"
    for i, (a, b) in enumerate(zip(replay, claimed, strict=False)):
        if a != b:
            if i == 0:
                return (
                    "the opening observation does not match the replay (the family, seed or "
                    "difficulty was changed)"
                )
            cmd = str(inc.get("commands", [""] * i)[i - 1])[:60]
            return (
                f"observation {i} does not match the replay (command {i} {cmd!r} or its "
                "hash was changed)"
            )
    return f"{len(claimed)} observation hashes recorded, the replay gives {len(replay)}"


def _first_diff(fresh: Any, claimed: Any, path: str = "") -> str | None:
    """The first key path where ``claimed`` differs from ``fresh``, with both values."""
    if isinstance(fresh, dict) and isinstance(claimed, dict):
        for k in sorted(set(fresh) | set(claimed)):
            sub = f"{path}.{k}" if path else str(k)
            if k not in claimed:
                return f"{sub}: missing from the report"
            if k not in fresh:
                return f"{sub}: in the report but not produced by the transcripts"
            d = _first_diff(fresh[k], claimed[k], sub)
            if d:
                return d
        return None
    if isinstance(fresh, list) and isinstance(claimed, list) and len(fresh) == len(claimed):
        for i, (a, b) in enumerate(zip(fresh, claimed, strict=False)):
            d = _first_diff(a, b, f"{path}[{i}]")
            if d:
                return d
        return None
    if json.dumps(fresh, sort_keys=True) != json.dumps(claimed, sort_keys=True):
        return (
            f"{path or 'value'}: the report says {_short(claimed)}, the transcripts give "
            f"{_short(fresh)}"
        )
    return None


def _short(x: Any) -> str:
    s = json.dumps(x, sort_keys=True)
    return s if len(s) <= 60 else s[:57] + "..."
