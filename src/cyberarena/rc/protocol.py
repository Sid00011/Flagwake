"""The JSON-lines harness side: run an external agent as a subprocess, or over localhost HTTP.

Subprocess protocol (one JSON object per line, newline-delimited):

  harness -> agent   {"type": "start", "role": "defender", "incident": "i-<12 hex>",
                      "text": "...", "commands": [...], "limits": {...}}
  harness -> agent   {"type": "obs", "text": "...", "t": <minute>, "done": false}
  agent   -> harness {"cmd": "logs web-01"}        (optionally with "usage": {...})
  agent   -> harness {"stop": true}                (optional: end the incident unfinished)
  harness -> agent   {"type": "end", "summary": {...}}

The harness never trusts the child and never lets one misbehaving incident stop a run. Every line
is length-capped; a line that is not one JSON object with a short string ``cmd`` is run as a
command the interpreter does not know (:data:`INVALID_REPLY`), so the child sees the help text
and the report counts it. Too many such lines, no answer within the step timeout, an incident that
runs past the wall timeout, or a child that stops reading its input ends that incident (the child is
killed) and is recorded in the transcript's ``harness`` notes; the run goes on. The run stops only
when the responder cannot be started at all, or when several incidents in a row fail with no command
run (see ``runner.run_pack``). The child's stderr is captured to a log file. User code runs
in the user's own process and is not sandboxed (docs/PROTOCOL.md and docs/SECURITY.md say so
plainly). The HTTP adapter speaks the same observation JSON to a localhost endpoint.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any, Protocol

from cyberarena.rc.engine import MAX_COMMANDS, RULES1_COMMANDS, Shift
from cyberarena.rc.provenance import child_env

MAX_LINE = 16384
NL = chr(10)  # the end of a reply line
MAX_BAD_LINES = 20
DEFAULT_STEP_TIMEOUT = 60.0
DEFAULT_WALL_TIMEOUT = 900.0
INVALID_REPLY = "(invalid reply)"  # run in place of a line the harness could not read
USAGE_KEYS = 12  # at most this many fields of a self-reported usage object
IDENTITY_KEYS = ("model", "endpoint")  # the text fields: what answered, and where
# The handshake: every start message tells the program it is the defender and lists the only
# commands it has. Anything else it sends is run as a command the interpreter does not know.
ROLE = "defender"
# What a call to an address the user chose can fail with: no route or refused or timed out
# (OSError), a broken HTTP exchange, or an answer that is not what was asked for (ValueError).
NET_ERRORS = (OSError, http.client.HTTPException, ValueError)


class ProtocolError(RuntimeError):
    """The responder cannot be run at all (it would not start, or failed at once every time)."""


RUN_KEY = re.compile(r"^[0-9a-f]{32}$")


def new_run_key() -> str:
    """A fresh secret for one run: 32 hex characters, never sent to the program under test."""
    return secrets.token_hex(16)


def incident_label(family: str, seed: int, difficulty: str, key: str) -> str:
    """An opaque name for one incident in the messages a program receives.

    The family name would tell the program what kind of incident it is ("quiet",
    "noisy-false-positive"), and family plus seed is enough to regenerate the ground truth with
    this package, so neither is ever sent. An unkeyed hash of them would not hide them either:
    the packs are small enough to hash every incident in a fraction of a second. So the name is
    keyed with the run's secret key (:func:`new_run_key`), which the report records only once the
    run is over; with the key, verify can rebuild every name.
    """
    # The prefix uses the frozen package name, so a change of product name never changes labels.
    blob = f"cyberarena/rc/label/{family}/{seed}/{difficulty}".encode()
    return "i-" + hmac.new(key.encode("ascii"), blob, hashlib.sha256).hexdigest()[:12]


class Named(Protocol):
    """What the harness names in its messages: a running incident or a connection-check canary."""

    incident: dict[str, Any]
    label: str


def shift_label(shift: Named) -> str:
    """The name a running incident was given (``runner.run_incident`` sets it); an incident
    started some other way gets a name under a throwaway key, never an unkeyed one."""
    if shift.label:
        return shift.label
    inc = shift.incident
    shift.label = incident_label(inc["family"], inc["seed"], inc["difficulty"], new_run_key())
    return shift.label


def _limits(
    step_timeout: float = DEFAULT_STEP_TIMEOUT, commands: int = MAX_COMMANDS
) -> dict[str, Any]:
    return {
        "commands": commands,
        "shift_minutes": 480,
        "obs_bytes": 8192,
        "step_seconds": step_timeout,
    }


def _start_message(shift: Shift, step_timeout: float = DEFAULT_STEP_TIMEOUT) -> dict[str, Any]:
    return {
        "type": "start",
        "role": ROLE,
        "incident": shift_label(shift),
        "text": shift.observations[0] if shift.observations else "",
        "commands": list(getattr(shift, "commands_known", RULES1_COMMANDS)),
        "limits": _limits(step_timeout, getattr(shift, "command_cap", MAX_COMMANDS)),
    }


def _obs_message(shift: Shift) -> dict[str, Any]:
    return {"type": "obs", "text": shift.observations[-1], "t": shift.now, "done": shift.done}


def clean_usage(obj: Any) -> dict[str, Any] | None:
    """A self-reported usage object reduced to a few non-negative numbers, plus the model and
    endpoint as short plain text (never trusted: a signed report says which program reported
    them)."""
    if not isinstance(obj, dict):
        return None
    out: dict[str, Any] = {}
    for k, v in list(obj.items())[:USAGE_KEYS]:
        if k in IDENTITY_KEYS and isinstance(v, str):
            text = "".join(ch for ch in v if ch.isascii() and ch.isprintable())[:100]
            if text:
                out[k] = text
        elif isinstance(k, str) and isinstance(v, int | float) and not isinstance(v, bool):
            if v == v and 0 <= v < 1e12:
                out[k[:40]] = round(float(v), 3) if isinstance(v, float) else v
    return out or None


def parse_reply(line: str) -> tuple[str, str | None, dict[str, Any] | None]:
    """Classify one reply: ("cmd", command, usage), ("stop", None, usage) or ("bad", None, None)."""
    try:
        obj = json.loads(line)
    except (ValueError, RecursionError):
        return "bad", None, None
    if not isinstance(obj, dict):
        return "bad", None, None
    usage = clean_usage(obj.get("usage"))
    if obj.get("stop") is True or ("cmd" in obj and obj["cmd"] is None):
        return "stop", None, usage
    if not isinstance(obj.get("cmd"), str):
        return "bad", None, None
    return "cmd", obj["cmd"][:4000], usage


class _Notes:
    """What went wrong with the responder during one incident (kept in the transcript)."""

    def __init__(self) -> None:
        self.invalid = 0
        self.error = ""
        self.usage: dict[str, Any] | None = None
        self.answered = 0

    def as_dict(self) -> dict[str, Any] | None:
        out: dict[str, Any] = {}
        if self.invalid:
            out["invalid_replies"] = self.invalid
        if self.error:
            out["error"] = self.error
        return out or None


class SubprocessAgent:
    """Launch ``argv`` and talk the JSON-lines protocol to it. One instance per incident.

    The instance is the driver: the runner calls it with the shift for each command, then calls
    :meth:`end` once the incident is over.
    """

    def __init__(
        self,
        argv: list[str],
        step_timeout: float = DEFAULT_STEP_TIMEOUT,
        stderr_path: str | None = None,
        wall_timeout: float = DEFAULT_WALL_TIMEOUT,
        first: bool = False,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self.argv = argv
        self.step_timeout = step_timeout
        self.wall_timeout = wall_timeout
        self.first = first  # the first incident of a run: a child that cannot start stops the run
        self.notes = _Notes()
        self._stderr = open(stderr_path, "ab") if stderr_path else subprocess.DEVNULL
        try:
            self.proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self._stderr,
                bufsize=1,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=cwd,
                env=child_env(env),  # never the job's signing tokens
            )
        except (FileNotFoundError, PermissionError) as exc:
            if not isinstance(self._stderr, int):
                self._stderr.close()
            why = "was not found" if isinstance(exc, FileNotFoundError) else "cannot be started"
            raise ProtocolError(
                f"the program {str(argv[0])[:120]!r} {why}; check the command and its path"
            ) from exc
        self._started = False
        self._t0 = time.monotonic()
        self._closed = False

    # ------------------------------------------------------------------ io with time limits
    def _timed(self, fn: Callable[[], Any]) -> tuple[bool, Any]:
        """Run ``fn`` in a thread; (finished, result). An exception counts as a result."""
        box: dict[str, Any] = {}

        def run() -> None:
            try:
                box["v"] = fn()
            except Exception as exc:  # a broken pipe or a closed stream
                box["e"] = exc

        th = threading.Thread(target=run, daemon=True)
        th.start()
        th.join(self.step_timeout)
        if th.is_alive():
            return False, None
        return True, box.get("e", box.get("v"))

    def _send(self, obj: dict[str, Any]) -> bool:
        stdin = self.proc.stdin
        assert stdin is not None
        data = json.dumps(obj, ensure_ascii=True) + "\n"

        def write() -> None:
            stdin.write(data)
            stdin.flush()

        done, err = self._timed(write)
        if not done:
            self._stop(f"did not read its input within {self.step_timeout:.0f}s", kill=True)
            return False
        if isinstance(err, Exception):
            self._stop("closed its input early")
            return False
        return True

    def _readline(self) -> str | None:
        stdout = self.proc.stdout
        assert stdout is not None

        def read() -> str:
            line = stdout.readline(MAX_LINE + 1)
            if len(line) > MAX_LINE and not line.endswith(NL):
                # Drop the rest of the overlong line, or it would be read as the next reply and
                # every later command would answer the observation before it.
                while True:
                    more = stdout.readline(MAX_LINE + 1)
                    if more == "" or more.endswith(NL):
                        break
            return line

        done, line = self._timed(read)
        if not done:
            self._stop(f"no answer within {self.step_timeout:.0f}s", kill=True)
            return None
        if isinstance(line, Exception):
            self._stop(f"cannot read its output ({type(line).__name__})")
            return None
        return line

    # ------------------------------------------------------------------ the driver
    def __call__(self, shift: Shift) -> str | None:
        if self._closed:
            return None
        if time.monotonic() - self._t0 > self.wall_timeout:
            self._stop(f"incident ran past the wall timeout of {self.wall_timeout:.0f}s", kill=True)
            return None
        msg = _start_message(shift, self.step_timeout) if not self._started else _obs_message(shift)
        self._started = True
        if not self._send(msg):
            return None
        line = self._readline()
        if line is None:
            return None
        if line == "":  # EOF: the responder exited
            self._exited()
            return None
        kind, cmd, usage = ("bad", None, None) if len(line) > MAX_LINE else parse_reply(line)
        if usage is not None:
            self.notes.usage = usage
        if kind == "stop":
            self._stop("")
            return None
        if kind == "bad":
            self.notes.invalid += 1
            if self.notes.invalid > MAX_BAD_LINES:
                self._stop(f"more than {MAX_BAD_LINES} invalid replies")
                return None
            return INVALID_REPLY
        self.notes.answered += 1
        return cmd

    def _exited(self) -> None:
        try:
            code = self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            code = None
        if self.first and self.notes.answered == 0 and code not in (0, None):
            self._stop("")
            raise ProtocolError(
                f"the responder exited with code {code} before sending a command "
                "(its stderr is in agent-stderr.log in the output folder)"
            )
        self._stop("" if code == 0 else f"exited with code {code}")

    def end(self, summary: dict[str, Any]) -> None:
        """Tell the responder the incident is over, then make sure the child is gone."""
        if not self._closed and self.proc.poll() is None:
            self._send({"type": "end", "summary": summary})
        self._stop("")

    def _stop(self, error: str, kill: bool = False) -> None:
        if error and not self.notes.error:
            self.notes.error = error
        if self._closed:
            return
        self._closed = True
        if kill and self.proc.poll() is None:  # unblocks a reader or writer thread first
            self.proc.kill()
        if self.proc.poll() is None:
            try:
                self.proc.stdin.close()  # type: ignore[union-attr]
            except (OSError, ValueError):  # the pipe is already broken or closed
                pass
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:  # pragma: no cover - a stuck kill
                    pass
        if not isinstance(self._stderr, int):
            self._stderr.close()


def subprocess_driver_factory(
    argv: list[str],
    step_timeout: float = DEFAULT_STEP_TIMEOUT,
    stderr_path: str | None = None,
    wall_timeout: float = DEFAULT_WALL_TIMEOUT,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> Callable[[], SubprocessAgent]:
    """A factory the runner calls per incident; each incident gets a fresh child process."""
    state = {"first": True}

    def make() -> SubprocessAgent:
        first, state["first"] = state["first"], False
        return SubprocessAgent(argv, step_timeout, stderr_path, wall_timeout, first, cwd, env)

    return make


class HttpAgent:
    """POST the observation JSON to a localhost endpoint; expect ``{"cmd": "..."}`` back."""

    def __init__(
        self,
        url: str,
        step_timeout: float = DEFAULT_STEP_TIMEOUT,
        first: bool = False,
        wall_timeout: float = DEFAULT_WALL_TIMEOUT,
    ) -> None:
        if not (url.startswith("http://127.0.0.1") or url.startswith("http://localhost")):
            raise ValueError("the HTTP adapter only talks to http://127.0.0.1 or http://localhost")
        self.url = url
        self.step_timeout = step_timeout
        self.wall_timeout = wall_timeout
        self.first = first
        self.notes = _Notes()
        self._started = False
        self._closed = False
        self._t0 = time.monotonic()

    def _post(self, payload: dict[str, Any], timeout: float) -> bytes:
        data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=data, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (localhost)
            return resp.read(MAX_LINE + 1)

    def __call__(self, shift: Shift) -> str | None:
        if self._closed:
            return None
        if time.monotonic() - self._t0 > self.wall_timeout:
            self._stop(f"incident ran past the wall timeout of {self.wall_timeout:.0f}s")
            return None
        payload = (
            _start_message(shift, self.step_timeout) if not self._started else (_obs_message(shift))
        )
        self._started = True
        try:
            body = self._post(payload, self.step_timeout)
        except urllib.error.HTTPError as exc:
            return self._bad(f"HTTP {exc.code}")
        except NET_ERRORS as exc:
            # urllib wraps connection failures (refused, or no answer to the connect) in URLError
            if self.first and self.notes.answered == 0 and isinstance(exc, urllib.error.URLError):
                reason = type(exc.reason).__name__
                raise ProtocolError(f"nothing answered at {self.url} ({reason})") from exc
            if "timed out" in str(exc) or isinstance(exc, TimeoutError):
                self._stop(f"no answer within {self.step_timeout:.0f}s")
                return None
            self._stop(f"request failed ({type(exc).__name__})")
            return None
        kind, cmd, usage = (
            ("bad", None, None)
            if len(body) > MAX_LINE
            else parse_reply(body.decode("utf-8", "replace"))
        )
        if usage is not None:
            self.notes.usage = usage
        if kind == "stop":
            self._stop("")
            return None
        if kind == "bad":
            return self._bad("")
        self.notes.answered += 1
        return cmd

    def _bad(self, _why: str) -> str | None:
        self.notes.invalid += 1
        if self.notes.invalid > MAX_BAD_LINES:
            self._stop(f"more than {MAX_BAD_LINES} invalid replies")
            return None
        return INVALID_REPLY

    def _stop(self, error: str) -> None:
        if error and not self.notes.error:
            self.notes.error = error
        self._closed = True

    def end(self, summary: dict[str, Any]) -> None:
        """Tell a stateful endpoint the incident is over (best effort, short timeout)."""
        try:
            self._post({"type": "end", "summary": summary}, min(5.0, self.step_timeout))
        except NET_ERRORS:  # best effort: the incident is over either way
            pass
        self._closed = True


def http_driver_factory(
    url: str, step_timeout: float = DEFAULT_STEP_TIMEOUT, wall_timeout: float = DEFAULT_WALL_TIMEOUT
) -> Callable[[], HttpAgent]:
    if not (url.startswith("http://127.0.0.1") or url.startswith("http://localhost")):
        raise ValueError("the HTTP adapter only talks to http://127.0.0.1 or http://localhost")
    state = {"first": True}

    def make() -> HttpAgent:
        first, state["first"] = state["first"], False
        return HttpAgent(url, step_timeout, first, wall_timeout)

    return make


def selfcheck() -> int:  # pragma: no cover - a tiny manual aid
    """Round-trip a trivial echo agent to confirm the protocol wiring (manual use)."""
    code = (
        "import sys,json\n"
        "for line in sys.stdin:\n"
        "    m=json.loads(line)\n"
        "    if m.get('type')=='end': break\n"
        "    print(json.dumps({'cmd':'look'}));sys.stdout.flush()\n"
    )
    from cyberarena.rc.runner import run_incident

    factory = subprocess_driver_factory([sys.executable, "-c", code])
    spec = {"family": "quiet", "seed": 130000, "difficulty": "standard"}
    shift, _tr, _o = run_incident(spec, factory())
    return 0 if shift.done else 1
