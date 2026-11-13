"""``flagwake doctor``: a quick check that an agent or a model endpoint is ready for a real run.

With no option it checks the model endpoint named by FLAGWAKE_LLM_BASE_URL / FLAGWAKE_LLM_MODEL
(and FLAGWAKE_LLM_KEY when set): one tiny probe call, then three practice incidents run by the
reference model agent. With ``--agent "<command>"`` or ``--http <url>`` it runs the same three
incidents with that agent. Every finding is printed as PASS / WARN / FAIL with the likely fix, and
the whole check is bounded to about a minute. Nothing is written except a temporary folder that is
removed at the end; the key is only ever sent in the request header to the endpoint you set.
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

from cyberarena.rc.model_agent import key_transport_problem, open_keyed
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
        url, data=body.encode(), headers={"Content-Type": "application/json"}
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
        if exc.code in (401, 403):
            if key:
                return (
                    "FAIL",
                    f"the endpoint refused the key (HTTP {exc.code})",
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
        if exc.code == 404:
            return (
                "FAIL",
                "no chat-completions API at this address (HTTP 404)",
                (
                    "FLAGWAKE_LLM_BASE_URL should be the API base, usually ending in /v1, and "
                    "FLAGWAKE_LLM_MODEL a model the server actually serves"
                ),
            )
        return (
            "FAIL",
            f"the endpoint answered HTTP {exc.code}",
            ("check the model id and the server's own log"),
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
    return "PASS", f"endpoint reachable, model answered in {seconds:.1f} s ({str(text)[:30]!r})", ""


def run_smoke(factory: Any, f: Findings, label: str) -> dict[str, Any] | None:
    """Run the three incidents; report what went wrong in plain words."""
    from cyberarena.rc.protocol import ProtocolError
    from cyberarena.rc.report import build_report
    from cyberarena.rc.runner import run_pack
    from cyberarena.rc.verify import verify

    t0 = time.monotonic()
    try:
        result = run_pack(factory, SPECS)
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
        slow = any("no answer" in k or "wall timeout" in k for k in h["errors"])
        f.say("FAIL", f"{h['incidents_with_errors']} incident(s) ended early: {errs}", (
            "too slow: raise --step-timeout in flagwake check, or use a faster model"
            if slow else "see agent-stderr.log in the output folder of a flagwake check run"
        ))  # fmt: skip
    if unrec and unrec * 2 >= max(1, cmds):
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
                factory = http_driver_factory(args.http, min(args.timeout, 15.0), 15.0)
            except ValueError as exc:
                f.say("FAIL", str(exc), "use http://127.0.0.1:<port>/<path>")
                return 1
            run_smoke(factory, f, f"http:{args.http}")
        elif args.agent:
            from cyberarena.rc.cli import split_command

            out.write(f"Checking this agent command: {args.agent}\n")
            factory = subprocess_driver_factory(
                split_command(args.agent), min(args.timeout, 15.0), str(tmp / "stderr.log"), 15.0
            )
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
            level, what, fix, latency = probe_endpoint(base, model, key, args.timeout)
            f.say(level, what, fix)
            if level == "FAIL":
                return 1
            # Size the smoke test from the probe so it stays near a minute: 3 incidents, ~45 s.
            calls = max(1, min(6, int(15 / max(0.5, latency))))
            argv = [sys.executable, "-m", "cyberarena.rc.model_agent", "--max-calls", str(calls),
                    "--timeout", str(args.timeout)]  # fmt: skip
            factory = subprocess_driver_factory(
                argv, args.timeout + 5, str(tmp / "stderr.log"), 15 + latency
            )
            doc = run_smoke(factory, f, "reference model agent")
            if doc is not None:
                u = doc["agent"].get("usage") or {}
                calls = int(u.get("calls", 0))
                failed = int(u.get("failed_calls", 0))
                if calls and failed * 2 >= calls:
                    f.say("FAIL", f"{failed} of {calls} model calls failed", (
                        "the endpoint fails under load or the model id is wrong; check its log"
                    ))  # fmt: skip
                if calls and u.get("seconds", 0) / calls > SLOW_CALL:
                    per = u["seconds"] / calls
                    f.say("WARN", f"slow: {per:.1f} s per call; the default pack makes up to 3,600")
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
