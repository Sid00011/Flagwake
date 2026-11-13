"""Run an agent over a pack and build the verifiable transcript and report structure.

An agent is a *driver*: a callable that, given the running :class:`Shift`, returns the next command
string or ``None`` to stop. Shipped baselines are drivers (they read the shift). External agents
speak text only: :func:`text_driver` wraps a ``callable(obs_dict) -> str | None`` so it sees just
the observation, the clock and its own command history, exactly what the JSON-lines protocol sends.

A transcript stores the commands and a SHA-256 of every observation (not the observation text), so
``verify`` can replay the commands through a fresh shift, recompute the hashes and the score, and
confirm nothing was edited. Timestamps are never part of a hash.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any

from cyberarena.rc import rules
from cyberarena.rc.baselines import ALL_AGENTS
from cyberarena.rc.engine import MAX_COMMANDS, Shift
from cyberarena.rc.packs import build_pack, difficulty_for
from cyberarena.rc.scoring import score_shift
from cyberarena.rc.world import World

FAILED_IN_A_ROW = 3  # incidents in a row that end in an agent error with no command run

Driver = Callable[[Shift], "str | None"]


def obs_hash(text: str) -> str:
    """The stable hash of one observation (the text only)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Env:
    """A thin wrapper around one incident for the Python API: reset/step, pure in the commands."""

    def __init__(
        self, family: str, seed: int, difficulty: str = "standard", world: World | None = None
    ) -> None:
        w = world or rules.default_world()
        self.incident = rules.generate(w, family, seed, difficulty)
        self.shift = Shift(self.incident, w)

    def reset(self) -> dict[str, Any]:
        return self.shift.reset()

    def step(self, command: str) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.shift.step(command)

    @property
    def done(self) -> bool:
        return self.shift.done


def make(family: str, seed: int, difficulty: str = "standard", world: World | None = None) -> Env:
    """Build one incident environment: ``obs = env.reset(); obs, info = env.step(cmd)``."""
    return Env(family, seed, difficulty, world)


def text_driver(agent: Callable[[dict[str, Any]], str | None]) -> Driver:
    """Wrap a text agent (sees only the observation) as a shift driver."""

    def driver(shift: Shift) -> str | None:
        obs = {
            "text": shift.observations[-1] if shift.observations else "",
            "t": shift.now,
            "done": shift.done,
            "commands": list(shift.commands),
        }
        return agent(obs)

    return driver


def start_shift(spec: dict[str, Any], world: World | None = None) -> Shift:
    """A fresh shift for one incident spec in ``world`` (the default world when None)."""
    w = world or rules.default_world()
    return Shift(rules.generate(w, spec["family"], spec["seed"], spec["difficulty"]), w)


def baseline_driver(name: str) -> Driver:
    """A shipped scripted agent as a driver."""
    agent = ALL_AGENTS[name]()
    return agent.next_command


def run_incident(
    spec: dict[str, Any],
    driver: Driver,
    max_commands: int = MAX_COMMANDS,
    world: World | None = None,
    key: str | None = None,
) -> tuple[Shift, dict[str, Any], dict[str, Any]]:
    """Run one incident; return (shift, transcript, outcome).

    ``key`` is the run's secret key, which names the incident in what the program is sent; a
    throwaway key is made when there is none.
    """
    from cyberarena.rc import protocol

    shift = start_shift(spec, world)
    shift.label = protocol.incident_label(
        spec["family"], spec["seed"], spec["difficulty"], key=key or protocol.new_run_key()
    )
    shift.command_cap = max_commands  # the start message states the cap actually enforced
    first = shift.reset()
    hashes = [obs_hash(first["text"])]
    commands: list[str] = []
    for _ in range(max_commands):
        if shift.done:
            break
        cmd = driver(shift)
        if cmd is None:
            break
        obs, _info = shift.step(cmd)
        commands.append(cmd)
        hashes.append(obs_hash(obs["text"]))
    shift.finish()
    end = getattr(driver, "end", None)
    if callable(end):  # an external agent: tell it the incident is over, then reap it
        end(
            {
                "incident": shift.label,
                "end_reason": shift.end_reason,
                "commands": len(commands),
                "t": shift.now,
            }
        )
    transcript = {
        "family": spec["family"],
        "seed": spec["seed"],
        "difficulty": spec["difficulty"],
        "commands": commands,
        "obs_hashes": hashes,
        "end_reason": shift.end_reason,
    }
    notes = getattr(driver, "notes", None)
    if notes is not None:
        harness = notes.as_dict()
        if harness:
            transcript["harness"] = harness  # what went wrong with the responder (not re-derivable)
        if notes.usage:
            transcript["usage"] = notes.usage  # self-reported by the responder
    return shift, transcript, score_shift(shift)


def run_pack(
    driver_factory: Callable[[], Driver],
    specs: list[dict[str, Any]],
    repeat: int = 1,
    max_commands: int = MAX_COMMANDS,
    progress: Callable[[int, int], None] | None = None,
    stop: Callable[[], bool] | None = None,
    world: World | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    """Run a fresh driver over every incident spec (``repeat`` times each).

    ``key`` is the run's secret key (a new one when None): it names every incident in what the
    program is sent, and the result carries it as ``run_key`` for the report.

    ``progress(done, total)`` is called after each incident and ``stop()`` before each; when it
    returns true the run ends early and the result holds the incidents finished so far.

    ``driver_factory`` returns a new driver per incident so a stateful agent starts clean. An
    agent that fails in :data:`FAILED_IN_A_ROW` incidents in a row without running a single
    command stops the run with a :class:`ProtocolError` (it is clearly not working), instead of
    timing out on every remaining incident.
    """
    from cyberarena.rc.protocol import INVALID_REPLY, ProtocolError, new_run_key

    key = key or new_run_key()
    transcripts: list[dict[str, Any]] = []
    outcomes: list[dict[str, Any]] = []
    failed = 0
    total = len(specs) * repeat
    world = world or rules.default_world()
    for spec in specs:
        for r in range(repeat):
            if stop is not None and stop():
                return {"transcripts": transcripts, "outcomes": outcomes, "stopped": True,
                        "world": rules.world_ref(world), "run_key": key}  # fmt: skip
            driver = driver_factory()
            _shift, tr, outcome = run_incident(spec, driver, max_commands, world, key)
            dead = tr.get("harness", {}).get("error") and all(
                c == INVALID_REPLY for c in tr["commands"]
            )
            failed = failed + 1 if dead else 0
            if failed >= FAILED_IN_A_ROW:
                raise ProtocolError(
                    f"the responder failed in {FAILED_IN_A_ROW} incidents in a row without "
                    f"running a command (last: {tr['harness']['error']}); stopping the run"
                )
            if repeat > 1:
                tr = {**tr, "repeat": r}
                outcome = {**outcome, "repeat": r}
            transcripts.append(tr)
            outcomes.append(outcome)
            if progress is not None:
                progress(len(outcomes), total)
    return {"transcripts": transcripts, "outcomes": outcomes, "world": rules.world_ref(world),
            "run_key": key}  # fmt: skip


def run_baseline_pack(
    name: str, specs: list[dict[str, Any]], world: World | None = None, key: str | None = None
) -> dict[str, Any]:
    """Convenience: run a shipped baseline over a pack."""
    return run_pack(lambda: baseline_driver(name), specs, world=world, key=key)


def pack_specs(
    which: str,
    per_family: int,
    seeds: list[int] | None = None,
    world: World | None = None,
    key: str | None = None,
) -> list[dict[str, Any]]:
    w = world or rules.default_world()
    return build_pack(which, per_family=per_family, seeds=seeds, families=rules.families(w),
                      key=key)  # fmt: skip


def spec_from_seeds(family: str, seeds: list[int]) -> list[dict[str, Any]]:
    return [{"family": family, "seed": s, "difficulty": difficulty_for(family, s)} for s in seeds]


def dumps(obj: Any) -> str:
    """Canonical JSON (sorted keys, compact floats) with a trailing newline."""
    return json.dumps(obj, sort_keys=True, indent=1, ensure_ascii=True) + "\n"
