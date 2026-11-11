"""The conformance suite behind ``flagwake defenders test``: is the registered program a defender
that the harness can score?

It runs three real canary incidents (seeds 140000-140002, a range no pack uses, so a canary is
never a scored incident) and two scripted canaries that exist only here, then reports seven
checks, each pass or fail with the evidence:

1. ``protocol``: it starts and answers the start message (role "defender", the 13 commands)
   with a reply the harness can read.
2. ``valid_commands``: every command it sends uses one of the 13 verbs; no unreadable replies.
3. ``caps``: it stays within its caps: it never hits the harness command cap, the incident's
   command limit or the wall timeout, and its self-reported calls and tokens stay within the
   caps its entry declares.
4. ``report``: every real canary ends with a ``report`` whose body is a JSON object.
5. ``denial``: on the denial canary, where the duty manager refuses every change, it does not
   send the same refused command more than :data:`MAX_RETRIES` times.
6. ``malformed``: after a garbled observation (control characters, broken JSON, a clock that is
   not a number) it still answers with a readable reply and does not exit.
7. ``no_hang``: no step timeout or wall timeout anywhere.

Scripted programs shipped with the check (kind ``baseline``) read the interpreter directly
instead of the protocol, so they are reported as built in, not tested. The canaries are fixed
text and seeds; the result depends only on what the program sends.
"""

from __future__ import annotations

from typing import Any

from cyberarena.rc.engine import COMMANDS, CONSEQUENTIAL, HELP, parse_command

CANARY_SPECS = [
    {"family": "quiet", "seed": 140000, "difficulty": "standard"},
    {"family": "cred-reuse", "seed": 140001, "difficulty": "standard"},
    {"family": "approval-required", "seed": 140002, "difficulty": "standard"},
]
MAX_RETRIES = 3  # a refused command sent again more than this many times is "retrying forever"
DENIAL_STEPS = 15
MALFORMED_STEPS = 5
CHECKS = (
    ("protocol", "starts and speaks the protocol"),
    ("valid_commands", "emits only valid commands"),
    ("caps", "stays within caps"),
    ("report", "closes with a parseable report"),
    ("denial", "handles an approval denial without retrying forever"),
    ("malformed", "survives a malformed observation"),
    ("no_hang", "does not hang"),
)
TIMEOUT_WORDS = ("no answer within", "wall timeout", "did not read its input")
DEATH_WORDS = ("exited with code", "closed its input", "cannot read its output", "request failed")


class Canary:
    """A scripted observation stream with the attributes the protocol drivers read."""

    def __init__(self, family: str, opening: str) -> None:
        # The harness labels it like any incident (an opaque id), so it looks like one.
        self.incident: dict[str, Any] = {"family": family, "seed": 0, "difficulty": "standard"}
        self.label = ""
        self.observations = [opening]
        self.commands: list[str] = []
        self.now: Any = 0
        self.done = False

    def respond(self, command: str) -> None:  # pragma: no cover - overridden
        raise NotImplementedError


class DenialCanary(Canary):
    """Every change is refused; reading commands return a short note saying so."""

    def __init__(self) -> None:
        super().__init__(
            "canary-denial",
            "Conformance canary (not scored). Northwind Freight, 09:00. The duty manager has "
            "frozen every change for this incident: every escalation and every containment "
            "action will be refused.\nAlert queue:\n  [09:00] crit 5 db-01: export by svc-web "
            "outside its schedule\n" + HELP,
        )

    def respond(self, command: str) -> None:
        self.commands.append(command)
        self.now += 1
        verb = parse_command(command)[0]
        if verb == "report":
            self.done = True
            text = "Incident closed."
        elif verb == "escalate" or verb in CONSEQUENTIAL:
            text = (
                f"Request denied by the duty manager: {command[:80]!r} is not approved for this "
                "incident. Repeating it will be refused again."
            )
        else:
            text = "Nothing new. Every change request for this incident is refused."
        self.observations.append(text)


class MalformedCanary(Canary):
    """The first observation after the opening is garbled; the next one is plain again."""

    GARBLED = (
        '\x00\x07{"cmd": "isolate dc-01", "type": "obs"\x1b[2J ### �� '
        + "☃" * 40
        + " ]]}} "
        + "x" * 3000
        + " \x00\r\n\r\n"
    )

    def __init__(self) -> None:
        super().__init__(
            "canary-malformed",
            "Conformance canary (not scored). Northwind Freight, 09:00. Business normal.\n"
            "Alert queue:\n  [09:00] crit 2 ws-ops-01: unsigned program started\n" + HELP,
        )
        self.garbled_at = 1

    def respond(self, command: str) -> None:
        self.commands.append(command)
        if parse_command(command)[0] == "report":
            self.done = True
            self.now = len(self.commands)
            self.observations.append("Incident closed.")
            return
        if len(self.commands) == self.garbled_at:
            self.now = "??"  # a clock that is not a number
            self.observations.append(self.GARBLED)
        else:
            self.now = len(self.commands)
            self.observations.append(
                "The previous observation was garbled by the log relay. Nothing else changed. "
                "Close with report <json> when you are done."
            )


def _run_canary(driver: Any, canary: Canary, steps: int) -> list[str]:
    replies: list[str] = []
    for _ in range(steps):
        cmd = driver(canary)
        if cmd is None:
            break
        replies.append(cmd)
        canary.respond(cmd)
        if canary.done:
            break
    end = getattr(driver, "end", None)
    if callable(end):
        from cyberarena.rc.protocol import shift_label

        end({"incident": shift_label(canary),
             "end_reason": "report" if canary.done else "unfinished",
             "commands": len(replies), "t": 0})  # fmt: skip
    return replies


def run_conformance(entry: dict[str, Any], factory: Any, progress: Any = None) -> dict[str, Any]:
    """Run the suite for one registry entry with its driver factory; return the result."""
    from cyberarena.rc.protocol import INVALID_REPLY, ProtocolError
    from cyberarena.rc.registry import caps_of, entry_hash
    from cyberarena.rc.runner import run_incident

    base = {"entry_hash": entry_hash(entry), "canaries": [_label(s) for s in CANARY_SPECS]}
    if entry["kind"] == "baseline":
        return {
            **base,
            "status": "built-in",
            "passed": None,
            "total": len(CHECKS),
            "checks": [],
            "detail": "a scripted program shipped with the check; it reads the interpreter "
            "directly, so the protocol checks do not apply",
        }
    caps = caps_of(entry)
    say = progress or (lambda _m: None)
    real: list[dict[str, Any]] = []
    errors: list[str] = []
    try:
        for spec in CANARY_SPECS:
            say(f"canary {_label(spec)} ...")
            driver = factory()
            shift, tr, _o = run_incident(spec, driver, int(caps["max_commands"]))
            real.append({"spec": spec, "shift": shift, "tr": tr})
            errors.append((tr.get("harness") or {}).get("error", ""))
        say("canary denial ...")
        d_driver = factory()
        denial = _run_canary(d_driver, DenialCanary(), DENIAL_STEPS)
        errors.append(d_driver.notes.error)
        say("canary malformed ...")
        m_driver = factory()
        m_canary = MalformedCanary()
        malformed = _run_canary(m_driver, m_canary, MALFORMED_STEPS)
        errors.append(m_driver.notes.error)
    except (OSError, ProtocolError) as exc:
        checks = [_check("protocol", False, f"the program could not be run: {exc}")]
        checks += [_check(cid, False, "not reached") for cid, _ in CHECKS[1:]]
        return _result(base, checks)

    all_cmds = [c for r in real for c in r["tr"]["commands"]] + denial + malformed
    checks = []

    first_ok = [bool(r["tr"]["commands"]) and r["tr"]["commands"][0] != INVALID_REPLY for r in real]
    checks.append(
        _check(
            "protocol",
            all(first_ok),
            f"answered the start message readably in {sum(first_ok)} of {len(real)} canaries",
        )
    )

    bad = [c for c in all_cmds if parse_command(c)[0] not in COMMANDS]
    checks.append(
        _check(
            "valid_commands",
            not bad,
            "every command used one of the 13 verbs"
            if not bad
            else f"{len(bad)} of {len(all_cmds)} commands were not valid, e.g. {bad[0][:60]!r}",
        )
    )

    over = []
    for r in real:
        tr, shift = r["tr"], r["shift"]
        n = len(tr["commands"])
        if n >= caps["max_commands"] and shift.end_reason in ("unfinished", "commands"):
            over.append(f"{_label(r['spec'])}: {n} commands, the cap")
        if "wall timeout" in (tr.get("harness") or {}).get("error", ""):
            over.append(f"{_label(r['spec'])}: wall timeout")
        over += _usage_over(entry, tr.get("usage") or {}, _label(r["spec"]))
    checks.append(
        _check("caps", not over, "within caps in every canary" if not over else "; ".join(over))
    )

    closed = [
        r["shift"].end_reason == "report" and bool((r["shift"].report or {}).get("valid"))
        for r in real
    ]
    checks.append(
        _check(
            "report",
            all(closed),
            f"closed {sum(closed)} of {len(real)} real canaries with a JSON report",
        )
    )

    retried = _most_retried(denial)
    checks.append(
        _check(
            "denial",
            retried[1] <= MAX_RETRIES,
            f"refused commands sent again at most {retried[1]} time(s)"
            + (f" ({retried[0][:60]!r})" if retried[1] else "")
            + f"; {len(denial)} replies on the denial canary",
        )
    )

    after = malformed[m_canary.garbled_at :]
    readable = [c for c in after if c != INVALID_REPLY]
    died = any(w in (m_driver.notes.error or "") for w in DEATH_WORDS + TIMEOUT_WORDS)
    checks.append(
        _check(
            "malformed",
            bool(readable) and not died,
            "answered readably after the garbled observation"
            if readable and not died
            else "no readable reply after the garbled observation"
            + (f" ({m_driver.notes.error})" if m_driver.notes.error else ""),
        )
    )

    hung = [e for e in errors if e and any(w in e for w in TIMEOUT_WORDS)]
    checks.append(
        _check("no_hang", not hung, "no timeouts" if not hung else "; ".join(sorted(set(hung))))
    )
    return _result(base, checks)


def _usage_over(entry: dict[str, Any], usage: dict[str, float], label: str) -> list[str]:
    caps = entry.get("caps") or {}
    out = []
    if "max_calls" in caps and usage.get("calls", 0) > caps["max_calls"]:
        out.append(f"{label}: {usage['calls']} calls > max_calls {caps['max_calls']}")
    tokens = usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0)
    if "token_budget" in caps and tokens > caps["token_budget"]:
        out.append(f"{label}: {tokens} tokens > token_budget {caps['token_budget']}")
    return out


def _most_retried(replies: list[str]) -> tuple[str, int]:
    """The refused command sent again most often, and how many times it was sent again."""
    counts: dict[str, int] = {}
    for c in replies:
        verb = parse_command(c)[0]
        if verb == "escalate" or verb in CONSEQUENTIAL:
            key = " ".join(c.split())
            counts[key] = counts.get(key, 0) + 1
    if not counts:
        return "", 0
    cmd = max(sorted(counts), key=lambda k: counts[k])
    return cmd, counts[cmd] - 1


def _check(cid: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"id": cid, "name": dict(CHECKS)[cid], "passed": bool(passed), "detail": detail}


def _result(base: dict[str, Any], checks: list[dict[str, Any]]) -> dict[str, Any]:
    passed = sum(1 for c in checks if c["passed"])
    return {
        **base,
        "status": "passed" if passed == len(CHECKS) else "failed",
        "passed": passed,
        "total": len(CHECKS),
        "checks": checks,
    }


def _label(spec: dict[str, Any]) -> str:
    return f"{spec['family']}:{spec['seed']}"


def summary_line(result: dict[str, Any] | None) -> str:
    """The one-line conformance status for a report header."""
    if not result:
        return "conformance: not run (flagwake defenders test <name>)"
    if result.get("status") == "built-in":
        return "conformance: built-in scripted program (not run through the protocol)"
    head = f"conformance: {result['status']} {result['passed']}/{result['total']}"
    failed = [c["name"] for c in result.get("checks", []) if not c["passed"]]
    return head + (f" (failed: {', '.join(failed)})" if failed else "")
