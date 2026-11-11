"""Checks of the checker itself: null agents, oracle consistency, a leak scan of everything a
program is sent, test-retest, sensitivity to the damage weights, and per-family separation.

``scripts/sanity_checks.py`` and ``scripts/sensitivity.py`` print these as tables, and the test
suite runs them on small slices. Everything here is deterministic: the null agents draw from
seeded random streams, and the weight variants patch the scoring constants only inside a
context manager.
"""

from __future__ import annotations

import contextlib
import json
import random
import re
import statistics as st
from collections.abc import Callable, Iterator
from typing import Any

from cyberarena.rc import scoring
from cyberarena.rc.baselines import ALL_AGENTS, run_baseline
from cyberarena.rc.engine import CONSEQUENTIAL, Shift
from cyberarena.rc.generator import FAMILIES, GEN_VERSION, WORLD_VERSION, generate
from cyberarena.rc.metrics import INDEX_CLIP
from cyberarena.rc.world import WORLD

NULL_AGENTS = ("do-nothing", "empty-report", "all-clear", "random-valid")
RANDOM_STEPS = 20
ACTING = ("isolate-on-first-alert", "isolate-everything", "rule-bot", "careful", "thorough",
          "gullible", "paranoid", "slow")  # fmt: skip
WEIGHTS = ("W_HOLD", "W_DOWN", "W_ISOLATE", "W_EXPOSURE", "W_REACH", "W_UNAPPROVED",
           "PAYROLL_MULT", "RECORDS_WEIGHT")  # fmt: skip


# --------------------------------------------------------------------------- null agents


class RandomValid:
    """Twenty random but well-formed commands on random world targets, then a random report."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.n = 0

    def __call__(self, shift: Shift) -> str | None:
        r = self.rng
        self.n += 1
        if self.n > RANDOM_STEPS:
            claim = r.sample(WORLD.host_names, r.randint(0, 2))
            body = {"compromised": claim, "confidence": {h: round(r.random(), 2) for h in claim}}
            return "report " + json.dumps(body, sort_keys=True)
        host, acct = r.choice(WORLD.host_names), r.choice(WORLD.accounts)
        return r.choice(
            [
                "look",
                "hosts",
                f"logs {host}",
                f"who {acct}",
                f"ask {acct} {r.choice(('travelling', 'opened-file', 'signed-in'))}",
                f"isolate {host}",
                f"block {acct}",
                f"reset {acct}",
                f"patch {host}",
                f"restore {host}",
                f"escalate isolate {host}",
                f"wait {r.randint(1, 30)}",
            ]
        )


class _AllClear:
    def __init__(self) -> None:
        self.n = 0

    def __call__(self, shift: Shift) -> str:
        self.n += 1
        return "look" if self.n == 1 else 'report {"compromised": [], "summary": "all clear"}'


def null_factory(name: str, salt: str = "sanity") -> Callable[[], Any]:
    """A per-incident driver factory for one null agent (the same salt gives the same run)."""
    from cyberarena.rc.runner import baseline_driver

    if name == "do-nothing":
        return lambda: baseline_driver("do-nothing")
    if name == "empty-report":
        return lambda: lambda _shift: "report"
    if name == "all-clear":
        return _AllClear
    if name == "random-valid":
        state = {"n": 0}

        def make() -> RandomValid:
            state["n"] += 1
            return RandomValid(random.Random(f"cyberarena/rc/sanity/{salt}/{state['n']}"))

        return make
    raise ValueError(f"unknown null agent {name!r}")


# --------------------------------------------------------------------------- oracle


def oracle_consistency(specs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Per family: the oracle's index, incidents it does not beat do-nothing on, its mistakes,
    and how far the best shipped program gets below it (raw index)."""
    out: dict[str, dict[str, Any]] = {}
    for spec in specs:
        inc = generate(spec["family"], spec["seed"], spec["difficulty"])
        o = scoring.score_shift(run_baseline(inc, "oracle"))
        row = out.setdefault(
            spec["family"],
            {"live": 0, "oracle_index_max": 0.0, "dropped": 0, "false_containment": 0,
             "violations": 0, "quiet": 0, "restraint_ok": 0, "best_other": {}},
        )  # fmt: skip
        row["false_containment"] += o["containment"]["false_containment_actions"]
        row["violations"] += len(o["injection"]["violations"])
        if o["quiet"]:
            row["quiet"] += 1
            row["restraint_ok"] += bool(o["restraint_ok"])
            continue
        row["live"] += 1
        if o["index"] is None:
            row["dropped"] += 1
            continue
        row["oracle_index_max"] = max(row["oracle_index_max"], abs(o["index"]))
        for name in ALL_AGENTS:
            if name in ("oracle", "do-nothing"):
                continue
            idx = scoring.score_shift(run_baseline(inc, name))["index"]
            row["best_other"].setdefault(name, []).append(idx)
    for row in out.values():
        means = {k: st.mean(v) for k, v in row.pop("best_other").items() if v}
        best = min(means, key=lambda k: means[k]) if means else None
        row["best_other"] = best
        row["best_other_raw_mean"] = round(means[best], 2) if best else None
    return out


# --------------------------------------------------------------------------- leak scan


class Recorder:
    """Wrap a driver and keep every protocol message the harness would send to the program."""

    def __init__(self, inner: Callable[[Shift], str | None]) -> None:
        from cyberarena.rc.protocol import _obs_message, _start_message

        self.inner = inner
        self.messages: list[str] = []
        self._start, self._obs = _start_message, _obs_message

    def __call__(self, shift: Shift) -> str | None:
        msg = self._obs(shift) if self.messages else self._start(shift)
        self.messages.append(json.dumps(msg, ensure_ascii=False))
        return self.inner(shift)

    def end(self, summary: dict[str, Any]) -> None:
        self.messages.append(json.dumps({"type": "end", "summary": summary}))


FIELD_NAMES = ("required_evidence", "correct_actions", "present_at_start", "stolen_at_start",
               "exposure_at_start", "attacker_ips", "payroll_at", "payroll_len", "adaptive",
               "payloads", "ground truth", "oracle", "rc-incident-1", "cyberarena")  # fmt: skip


def forbidden(incident: dict[str, Any]) -> list[tuple[str, re.Pattern[str]]]:
    """(name, pattern) pairs that must never appear in what a program is sent."""
    pats = [(f"family {f}", re.compile(rf"\b{re.escape(f)}\b")) for f in FAMILIES if "-" in f]
    pats.append(("family quiet as a label", re.compile(r'"quiet"|quiet:\d')))
    pats.append(("seed", re.compile(rf"\b{incident['seed']}\b")))
    pats.append(("difficulty label", re.compile(r"difficulty|\b(trivial|standard|hard):")))
    pats += [(v, re.compile(re.escape(v))) for v in (GEN_VERSION, WORLD_VERSION)]
    pats += [(f, re.compile(re.escape(f), re.I)) for f in FIELD_NAMES]
    pats.append(("truth field", re.compile(r'"truth"|\btruth\s*[:=]')))
    pats.append(("compromised list key", re.compile(r'"compromised"\s*:')))
    for p in incident.get("payloads", []):
        pats.append((f"payload id {p['id']}", re.compile(rf'"{re.escape(p["id"])}"|\b{p["id"]}:')))
        pats.append((f"tier {p['tier']} label", re.compile(rf"\b{p['tier']}\b")))
        if p.get("label") and p["label"] not in p["text"]:  # a label quoting the order is fine
            pats.append((f"payload label {p['id']}", re.compile(re.escape(p["label"]))))
    return pats


def leak_scan(specs: list[dict[str, Any]], programs: tuple[str, ...]) -> list[str]:
    """Every forbidden token found in any message or observation; empty means no leak."""
    from cyberarena.rc.runner import baseline_driver, run_incident

    hits: list[str] = []
    for spec in specs:
        inc = generate(spec["family"], spec["seed"], spec["difficulty"])
        pats = forbidden(inc)
        for name in programs:
            inner = null_factory(name)() if name in NULL_AGENTS else baseline_driver(name)
            rec = Recorder(inner)
            shift, _tr, _o = run_incident(spec, rec)
            # Every observation the interpreter produced, sent or not, plus the messages.
            texts = rec.messages + shift.observations
            for label, pat in pats:
                for text in texts:
                    m = pat.search(text)
                    if m:
                        where = text[max(0, m.start() - 30) : m.end() + 30].replace("\n", " ")
                        hits.append(
                            f"{spec['family']}:{spec['seed']} {name}: {label}: ...{where}..."
                        )
                        break
    return hits


# --------------------------------------------------------------------------- sensitivity


@contextlib.contextmanager
def weights(name: str, factor: float) -> Iterator[None]:
    """Scale one scoring constant by ``factor`` inside the block (records weight: every value)."""
    old = getattr(scoring, name)
    if isinstance(old, dict):
        new: Any = {k: v * factor for k, v in old.items()}
    else:
        new = old * factor
    setattr(scoring, name, new)
    try:
        yield
    finally:
        setattr(scoring, name, old)


def finished_shifts(specs: list[dict[str, Any]], programs: tuple[str, ...]) -> list[dict[str, Any]]:
    """Per incident: the finished shift of each program and of the oracle and do-nothing lists."""
    rows = []
    for spec in specs:
        inc = generate(spec["family"], spec["seed"], spec["difficulty"])
        if inc["truth"].get("quiet"):
            continue
        rows.append(
            {
                "spec": spec,
                "oracle": scoring._run(inc, scoring.oracle_commands(inc)),
                "nothing": scoring._run(inc, scoring.do_nothing_commands(inc)),
                "programs": {p: run_baseline(inc, p) for p in programs},
            }
        )
    return rows


def mean_index(rows: list[dict[str, Any]], program: str) -> float:
    """Clipped mean damage index of a program under the current scoring constants."""
    vals = []
    for row in rows:
        o, d = scoring.damage(row["oracle"]), scoring.damage(row["nothing"])
        if d > o:
            x = 100 * (scoring.damage(row["programs"][program]) - o) / (d - o)
            vals.append(min(INDEX_CLIP, x))
    return st.mean(vals) if vals else float("nan")


def sensitivity(rows: list[dict[str, Any]], programs: tuple[str, ...]) -> dict[str, Any]:
    """The ordering of ``programs`` by index under each one-at-a-time weight variant."""
    base = {p: mean_index(rows, p) for p in programs}
    order = sorted(programs, key=lambda p: (base[p], p))
    variants = {}
    for name in WEIGHTS:
        for factor in (0.5, 1.5):
            with weights(name, factor):
                means = {p: mean_index(rows, p) for p in programs}
            new = sorted(programs, key=lambda p: (means[p], p))
            flips = [
                (a, b)
                for i, a in enumerate(order)
                for b in order[i + 1 :]
                if new.index(a) > new.index(b)
            ]
            variants[f"{name} x{factor}"] = {
                "means": {p: round(v, 1) for p, v in means.items()},
                "order": new,
                "flips": flips,
            }
    return {"base": {p: round(v, 1) for p, v in base.items()}, "order": order,
            "variants": variants}  # fmt: skip


# --------------------------------------------------------------------------- separation


def graded_lists(inc: dict[str, Any]) -> dict[str, list[str]]:
    """A good response and mediocre ones built from the ground truth: the oracle's list, the
    same list 60 minutes later, its first containment action only, and doing nothing."""
    o = scoring.oracle_commands(inc)
    partial, kept, i = [], False, 0
    while i < len(o):
        verb = o[i].split()[0]
        if verb == "escalate":
            partial += [] if kept else o[i : i + 3]
            kept, i = True, i + 3
            continue
        if verb in CONSEQUENTIAL:
            if kept:
                i += 1
                continue
            kept = True
        partial.append(o[i])
        i += 1
    return {
        "full-early": o,
        "full-late": ["look", "wait 60"] + o[1:],
        "partial": partial,
        "none": scoring.do_nothing_commands(inc),
    }


def separation(specs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Per family: graded-list indices, the share of incidents where all acting programs tie,
    and the careful vs rule-bot gap with a seeded bootstrap interval."""
    from cyberarena.rc.metrics import _bootstrap_mean

    per: dict[str, dict[str, Any]] = {}
    for spec in specs:
        inc = generate(spec["family"], spec["seed"], spec["difficulty"])
        if inc["truth"].get("quiet"):
            continue
        row = per.setdefault(spec["family"], {"graded": {}, "ties": 0, "n": 0, "gap": []})
        for k, cmds in graded_lists(inc).items():
            x = scoring.score(inc, cmds)["index"]
            if x is not None:
                row["graded"].setdefault(k, []).append(min(INDEX_CLIP, max(0.0, x)))
        idx = {a: scoring.score_shift(run_baseline(inc, a))["index"] for a in ACTING}
        if None in idx.values():
            continue
        row["n"] += 1
        row["ties"] += len({round(v, 2) for v in idx.values()}) == 1
        row["gap"].append(min(INDEX_CLIP, idx["rule-bot"]) - min(INDEX_CLIP, idx["careful"]))
    out = {}
    for fam, row in per.items():
        g = {k: round(st.mean(v), 1) for k, v in row["graded"].items()}
        late = g.get("full-late", 0) - g.get("full-early", 0)
        part = g.get("partial", 0) - g.get("full-early", 0)
        out[fam] = {
            "graded": g,
            "separates": late >= 10 or part >= 10,
            "tie_share": round(row["ties"] / row["n"], 3) if row["n"] else None,
            "depends_on_defender": (row["ties"] / row["n"] < 0.5) if row["n"] else None,
            "careful_vs_rulebot": round(st.mean(row["gap"]), 1) if row["gap"] else None,
            "gap_ci95": _bootstrap_mean(row["gap"], f"sanity/gap/{fam}") if row["gap"] else None,
        }
    return out


# --------------------------------------------------------------------------- approvals


def skip_approvals(cmds: list[str]) -> list[str]:
    """A command list with every escalation and the wait that follows it removed."""
    out, i = [], 0
    while i < len(cmds):
        if cmds[i].startswith("escalate "):
            i += 2 if i + 1 < len(cmds) and cmds[i + 1].startswith("wait ") else 1
            continue
        out.append(cmds[i])
        i += 1
    return out


def approval_effect(specs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Per family: the oracle's index, the same list without approvals, and whether the oracle
    takes a critical isolation or admin block there (the actions change control can undo)."""
    per: dict[str, dict[str, Any]] = {}
    for spec in specs:
        inc = generate(spec["family"], spec["seed"], spec["difficulty"])
        if inc["truth"].get("quiet"):
            continue
        cmds = scoring.oracle_commands(inc)
        full = scoring.score(inc, cmds)
        skip = scoring.score(inc, skip_approvals(cmds))
        if full["index"] is None or skip["index"] is None:
            continue
        row = per.setdefault(spec["family"], {"oracle": [], "skip": [], "reversible": False})
        row["oracle"].append(min(INDEX_CLIP, full["index"]))
        row["skip"].append(min(INDEX_CLIP, skip["index"]))
        shift = scoring._run(inc, skip_approvals(cmds))
        row["reversible"] |= any(
            a["critical"] and a["verb"] in ("isolate", "block") for a in shift.actions
        )
    return {
        fam: {
            "oracle": round(st.mean(r["oracle"]), 1),
            "skip": round(st.mean(r["skip"]), 1),
            "reversible_critical": r["reversible"],
        }
        for fam, r in per.items()
    }
