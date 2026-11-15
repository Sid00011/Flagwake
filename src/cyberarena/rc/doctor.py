"""``flagwake doctor``: a quick check that an agent or a model endpoint is ready for a real run.

With no option it checks the model endpoint named by FLAGWAKE_LLM_BASE_URL / FLAGWAKE_LLM_MODEL
(and FLAGWAKE_LLM_KEY when set): one tiny probe call, then three practice incidents run by the
reference model agent. With ``--agent "<command>"`` or ``--http <url>`` it runs the same three
incidents with that agent. Every finding is printed as PASS / WARN / FAIL with the likely fix. Each
test incident gets the same time whatever the model or the computer, with a line after each, and
a slow model gets a warning with an estimate of how long a run takes, not a failure. Nothing is
written except a temporary folder that is removed at the end; the key is only ever sent in the
request header to the endpoint you set.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cyberarena import USER_AGENT
from cyberarena.rc.connection import CAUSES, classify, diagnose_incidents
from cyberarena.rc.model_agent import key_transport_problem, open_keyed, provider_message
from cyberarena.rc.protocol import NET_ERRORS

SPECS = [
    {"family": "quiet", "seed": 120000, "difficulty": "standard"},
    {"family": "cred-reuse", "seed": 120001, "difficulty": "standard"},
    {"family": "forged-emergency", "seed": 120002, "difficulty": "standard"},
]
PROBE = [
    {"role": "system", "content": "You are testing a connection. Reply with the single word: look"},
    {"role": "user", "content": "Reply with: look"},
]
SLOW_CALL = 10.0  # seconds per model call above which a full run gets long
# Each test incident may take this long, whatever the model or the computer: a slow local
# model or a provider that makes calls wait still gets a fair chance (a real run allows 15
# minutes per incident). Progress is printed after each incident.
INCIDENT_SECONDS = 180.0
SMOKE_CALLS = 6  # model calls per test incident at most
# Calls a default run (200 incidents) makes, at about 19 per incident: the mean of the shipped
# model agent on reference runs. Used only to estimate how long a run takes.
DEFAULT_RUN_CALLS = 3800


class Findings:
    def __init__(self, out: Any) -> None:
        self.out = out
        self.failed = False

    def say(self, level: str, what: str, fix: str = "") -> None:
        self.failed = self.failed or level == "FAIL"
        self.out.write(f"{level:4}  {what}\n")
        if fix:
            self.out.write(f"      fix: {fix}\n")
        self.out.flush()


def probe_endpoint(
    base: str, model: str, key: str | None, timeout: float
) -> tuple[str, str, str, float]:
    """One tiny chat-completions call: (level, finding, likely fix, seconds)."""
    url = base.rstrip("/")
    url = url if url.endswith("/chat/completions") else url + "/chat/completions"
    body = json.dumps({"model": model, "messages": PROBE, "temperature": 0, "max_tokens": 16})
    req = urllib.request.Request(
        url,
        data=body.encode(),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    if key:
        req.add_header("Authorization", "Bearer " + key)
    t0 = time.monotonic()
    level, what, fix = _probe(req, timeout)
    return level, what, fix, time.monotonic() - t0


def _probe(req: urllib.request.Request, timeout: float) -> tuple[str, str, str]:
    t0 = time.monotonic()
    key = req.get_header("Authorization")
    try:
        with open_keyed(req, timeout) as resp:  # the user's endpoint; no redirects
            raw = resp.read(1_000_000)
    except urllib.error.HTTPError as exc:
        said = provider_message(exc)  # the provider's own words, key-like text masked
        if exc.code == 429:  # a rate limit or a quota that ran out
            return (
                "FAIL",
                f"the provider refuses requests for now (HTTP 429{': ' + said if said else ''})",
                (
                    "a rate limit or a quota that ran out: wait and try again, or use a plan "
                    "with a larger allowance"
                ),
            )
        if exc.code == 403:  # the key, a model the key cannot use, or a firewall
            return (
                "FAIL",
                f"the endpoint refused the request (HTTP 403{': ' + said if said else ''})",
                (
                    "a missing, wrong or restricted key, a model this key cannot use, or the "
                    "provider's firewall; check the key and the model id in the provider's "
                    "console"
                ),
            )
        cause = classify(exc.code, said)
        if exc.code in (401, 403) or cause == "key":
            if key:
                return (
                    "FAIL",
                    f"the endpoint refused the key (HTTP {exc.code}{': ' + said if said else ''})",
                    ("check FLAGWAKE_LLM_KEY: wrong, expired, or without access to this model"),
                )
            return (
                "FAIL",
                f"the endpoint wants a key (HTTP {exc.code})",
                ("set FLAGWAKE_LLM_KEY to your key (it is read from the environment only)"),
            )
        if 300 <= exc.code < 400:
            return (
                "FAIL",
                f"the endpoint redirected the request (HTTP {exc.code})",
                (
                    "use the final address as FLAGWAKE_LLM_BASE_URL: Flagwake does not follow "
                    "redirects, so the key never goes to an address you did not choose"
                ),
            )
        if exc.code == 404 or cause == "missing":
            return (
                "FAIL",
                f"no such model or API at this address (HTTP 404{': ' + said if said else ''})",
                (
                    "FLAGWAKE_LLM_BASE_URL should be the API base, usually ending in /v1, and "
                    "FLAGWAKE_LLM_MODEL a model the server actually serves"
                ),
            )
        return (
            "FAIL",
            f"the endpoint answered HTTP {exc.code}{': ' + said if said else ''}",
            ("check the model id, the key and any extra request fields"),
        )
    except NET_ERRORS as exc:  # unreachable, refused, timed out, bad TLS
        if "timed out" in str(exc) or isinstance(exc, TimeoutError):
            return (
                "FAIL",
                f"too slow: no answer within {timeout:.0f} s",
                (
                    "use a smaller or faster model, or raise --timeout here and --step-timeout in "
                    "flagwake check"
                ),
            )
        return (
            "FAIL",
            f"endpoint unreachable ({type(getattr(exc, 'reason', exc)).__name__})",
            ("is the server running? Check FLAGWAKE_LLM_BASE_URL (scheme, host, port, /v1)"),
        )
    seconds = time.monotonic() - t0
    try:
        data = json.loads(raw)
        text = data["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError):
        return (
            "FAIL",
            "the reply is not chat-completions JSON",
            ("point FLAGWAKE_LLM_BASE_URL at a chat-completions API (the /v1 base of the server)"),
        )
    if seconds > SLOW_CALL:
        return (
            "WARN",
            f"endpoint reachable but slow ({seconds:.1f} s for a tiny call)",
            ("a full run makes hundreds of calls; consider a faster model"),
        )
    answer = (
        repr(str(text)[:30]) if text else "an empty reply, normal for a model that reasons first"
    )
    return "PASS", f"endpoint reachable, model answered in {seconds:.1f} s ({answer})", ""


def _progress(f: Findings, done: int, total: int, t0: float) -> None:
    """One line per finished incident, so a slow or rate-limited provider never looks frozen."""
    f.out.write(f"      incident {done} of {total} done ({time.monotonic() - t0:.0f} s so far)\n")
    f.out.flush()


def _speed(f: Findings, per_call: float) -> None:
    """How long a default run would take at the speed the test calls had, waits included."""
    hours = per_call * DEFAULT_RUN_CALLS / 3600
    took = f"about {per_call:.1f} s per model call, waits included"
    if per_call > SLOW_CALL:
        f.say("WARN", f"slow: {took}; the default run of 200 incidents takes about "
              f"{hours:.0f} h at this speed", (
                  "try it first on 20 incidents (--pack practice --seeds 1); a faster model or "
                  "plan shortens it, and the scores do not depend on speed"
              ))  # fmt: skip
    else:
        f.say("INFO", f"{took}; the default run of 200 incidents takes about {hours:.1f} h")


def run_smoke(factory: Any, f: Findings, label: str) -> dict[str, Any] | None:
    """Run the three incidents; report what went wrong in plain words."""
    from cyberarena.rc.protocol import ProtocolError
    from cyberarena.rc.report import build_report
    from cyberarena.rc.runner import run_pack
    from cyberarena.rc.verify import verify

    t0 = time.monotonic()
    try:
        result = run_pack(
            factory, SPECS, progress=lambda done, total: _progress(f, done, total, t0)
        )
    except (OSError, ProtocolError) as exc:
        why = str(exc)
        if "invalid replies" in why:
            f.say("FAIL", f"replies unparseable: {label} sent no line the harness could read", (
                'answer each message with one JSON line such as {"cmd": "logs web-01"} '
                "(docs/PROTOCOL.md)"
            ))  # fmt: skip
        elif "no answer" in why or "wall timeout" in why:
            f.say("FAIL", f"too slow: {label} did not answer in time ({why})", (
                "answer each message within the step timeout (--step-timeout in flagwake check)"
            ))  # fmt: skip
        else:
            f.say("FAIL", f"{label} could not be run: {why}", (
                "run the --agent command by hand once; it must read JSON lines on stdin "
                "(docs/PROTOCOL.md)"
            ))  # fmt: skip
        return None
    seconds = time.monotonic() - t0
    doc = build_report(result, {"id": label}, pack_name="custom")  # three chosen incidents
    cmds = doc["metrics"]["cost"]["commands"]
    unrec = doc["metrics"]["cost"]["unrecognised_commands"]
    h = doc["harness"]
    f.say("PASS", f"ran {len(SPECS)} incidents in {seconds:.1f} s ({cmds} commands)")
    if h["incidents_with_errors"]:
        errs = "; ".join(f"{k} ({v})" for k, v in h["errors"].items())
        boxed = all("wall timeout" in k for k in h["errors"])
        late = any("no answer" in k for k in h["errors"])
        if boxed:
            f.say("WARN", f"{h['incidents_with_errors']} test incident(s) used all the "
                  f"{INCIDENT_SECONDS:.0f} s doctor allows for one: the model is slow", (
                      "a real run allows 15 minutes per incident; the speed line below says how "
                      "long a run would take"
                  ))  # fmt: skip
        else:
            f.say("FAIL", f"{h['incidents_with_errors']} incident(s) ended early: {errs}", (
                "an answer came later than the step timeout: raise --step-timeout in flagwake "
                "check (and --timeout here), or use a faster model"
                if late else "see agent-stderr.log in the output folder of a flagwake check run"
            ))  # fmt: skip
    diag = diagnose_incidents(doc["incidents"])
    if diag and diag["main"] != "unreadable":  # the cause has a name: say it, with the fix
        what, fix = CAUSES[diag["main"]]
        said = f" ({diag['example']})" if diag["example"] else ""
        level = "FAIL" if diag["empty"] * 2 >= max(1, cmds) else "WARN"
        f.say(level, f"{what}: {diag['empty']} of {cmds} replies carried no command{said}", fix)
    elif unrec and unrec * 2 >= max(1, cmds):
        f.say("FAIL", f"replies unparseable: {unrec} of {cmds} commands were not commands", (
            "an agent must answer one command per line, e.g. {\"cmd\": \"logs web-01\"}; a model "
            "must reply with only the command (docs/TRY_YOUR_AGENT.md)"
        ))  # fmt: skip
    elif unrec:
        f.say("WARN", f"{unrec} of {cmds} commands were not recognised (counted in the report)")
    else:
        f.say("PASS", "every command was understood")
    if not any(inc["commands"] and inc["commands"][-1].startswith("report")
               for inc in doc["incidents"]):  # fmt: skip
        f.say("WARN", "no incident was closed with a report", (
            "close with report {\"compromised\": [...], ...} so restraint and calibration count"
        ))  # fmt: skip
    problems = verify(doc)
    if problems:
        f.say("FAIL", "the report did not verify: " + problems[0])
    else:
        f.say("PASS", "the report verifies")
    return doc


def doctor(args: Any, out: Any = None) -> int:
    """The command. Returns 0 when nothing failed."""
    out = out or sys.stdout
    f = Findings(out)
    from cyberarena.rc.protocol import http_driver_factory, subprocess_driver_factory

    tmp = Path(tempfile.mkdtemp(prefix="flagwake-doctor-"))
    factory: Callable[[], Any]
    try:
        if args.http:
            out.write(f"Checking the HTTP agent at {args.http}\n")
            try:
                factory = http_driver_factory(args.http, args.timeout, INCIDENT_SECONDS)
            except ValueError as exc:
                f.say("FAIL", str(exc), "use http://127.0.0.1:<port>/<path>")
                return 1
            run_smoke(factory, f, f"http:{args.http}")
        elif args.agent:
            from cyberarena.rc.cli import split_command

            out.write(f"Checking this agent command: {args.agent}\n")
            factory = subprocess_driver_factory(
                split_command(args.agent), args.timeout, str(tmp / "stderr.log"), INCIDENT_SECONDS
            )
            out.write("Running 3 short incidents with your program ...\n")
            out.flush()
            run_smoke(factory, f, "agent")
            _stderr_tail(tmp / "stderr.log", out)
        else:
            base = os.environ.get("FLAGWAKE_LLM_BASE_URL", "")
            model = os.environ.get("FLAGWAKE_LLM_MODEL", "")
            key = os.environ.get("FLAGWAKE_LLM_KEY") or None
            out.write("Checking the model endpoint in FLAGWAKE_LLM_BASE_URL\n")
            if not base or not model:
                f.say("FAIL", "FLAGWAKE_LLM_BASE_URL or FLAGWAKE_LLM_MODEL is not set", (
                    "set both (docs/TRY_YOUR_AGENT.md), or check your own agent with "
                    "flagwake doctor --agent \"python my_agent.py\""
                ))  # fmt: skip
                return 1
            f.say(
                "PASS" if key else "INFO",
                "a key is set" if key else "no key set (fine for a local server)",
            )
            refused = key_transport_problem(base, key)
            if refused:
                f.say("FAIL", refused, "use an https:// address (no key is needed locally)")
                return 1
            level, what, fix, _latency = probe_endpoint(base, model, key, args.timeout)
            f.say(level, what, fix)
            if level == "FAIL":
                return 1
            # The same small test for every model: the tiny probe says nothing about how long a
            # real reply takes (a model that reasons first is slower), so it does not size it.
            argv = [sys.executable, "-m", "cyberarena.rc.model_agent", "--max-calls",
                    str(SMOKE_CALLS), "--timeout", str(args.timeout)]  # fmt: skip
            factory = subprocess_driver_factory(
                argv, args.timeout + 5, str(tmp / "stderr.log"), INCIDENT_SECONDS
            )
            out.write("Running 3 short incidents with the model; a few minutes if the provider "
                      "limits its rate ...\n")  # fmt: skip
            out.flush()
            doc = run_smoke(factory, f, "reference model agent")
            if doc is not None:
                u = doc["agent"].get("usage") or {}
                if u.get("rate_limited"):
                    f.say("WARN", f"the provider limited the rate: {u['rate_limited']} answers "
                          f"asked to wait ({u.get('waited_seconds', 0):.0f} s in all)", (
                              "a full run will be slow; set a pace below the provider's limit "
                              "(requests_per_minute in flagwake.yaml, FLAGWAKE_LLM_RPM)"
                          ))  # fmt: skip
                calls = int(u.get("calls", 0))
                failed = int(u.get("failed_calls", 0))
                if calls and failed * 2 >= calls:
                    f.say("FAIL", f"{failed} of {calls} model calls failed", (
                        "the endpoint fails under load or the model id is wrong; check its log"
                    ))  # fmt: skip
                if calls:
                    _speed(f, (u.get("seconds", 0) + u.get("waited_seconds", 0)) / calls)
        out.write(
            "\nAll checks passed.\n" if not f.failed else "\nSome checks failed (see fix:).\n"
        )
        return 1 if f.failed else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _stderr_tail(path: Path, out: Any) -> None:
    if path.is_file() and path.stat().st_size:
        tail = path.read_text(encoding="utf-8", errors="replace").splitlines()[-3:]
        out.write("      last lines of its stderr:\n" + "".join(f"        {t}\n" for t in tail))
