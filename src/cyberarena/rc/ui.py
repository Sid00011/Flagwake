"""``flagwake ui``: a local page to add a defender, check its connection, run the check and read
the result, without the command line.

This is a local server that can start processes, so it is built like one:

- It binds 127.0.0.1 only and answers only requests whose Host header names that address and
  port (a page on another site cannot reach it through a renamed address).
- Every ``/api/`` request must carry the random token made at launch, in the
  ``X-Flagwake-Token`` header; the page reads it from the address's fragment, which browsers
  never send to a server, and nothing is logged. Requests that change anything must also come
  from the page's own origin and carry a JSON body of at most 16 KB. There are no cookies and no
  CORS headers, so another site's page can neither read the answers nor send the token.
- Static files come from a fixed list with a strict content security policy: no inline script,
  no request to any other address.
- Every field goes through the same validation as ``flagwake.yaml``; a saved defender is the
  same registry entry the command line writes, without secrets. A key typed into the page is
  kept in this process's memory until the page stops and passed only to the reference program's
  environment; it is never written to a file, a log or a report.
- Defenders that start a program on this computer (``command``, ``mcp``) can be added, checked
  and run here only when the page was started with ``--allow-commands``, and then only after an
  explicit confirmation; otherwise they are command-line only.
- One job (a connection check or a run) runs at a time, in the background: closing the tab does
  not stop it, and reopening the page shows its progress.
"""

from __future__ import annotations

import functools
import hmac
import http.server
import json
import re
import secrets
import socketserver
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any

from cyberarena.rc.protocol import NET_ERRORS

WEB = Path(__file__).resolve().parent / "web"
STATIC = {
    "/": ("ui.html", "text/html; charset=utf-8"),
    "/ui.html": ("ui.html", "text/html; charset=utf-8"),
    "/css/ui.css": ("css/ui.css", "text/css; charset=utf-8"),
    "/js/ui.js": ("js/ui.js", "text/javascript; charset=utf-8"),
}
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
TOKEN_HEADER = "X-Flagwake-Token"
MAX_BODY = 16384
MAX_KEY = 500
# Ports that common local model servers listen on by default; only GET /v1/models is asked.
DETECT_PORTS = (11434, 1234, 8080, 8000, 5000, 5001)
SIZES = {"quick": 1, "standard": 5, "full": 10}  # seeds per family (x 20 families by default)
PACKS = ("fresh", "heldout", "practice")
NO_SERVER_HELP = (
    "No model server was found on this computer. Start the program you use to run models "
    "locally and load a model in it, then press Look again."
)
RUNS_CODE = ("command", "mcp")
# The demo's example defender: a shipped program that the result page compares with careful
# and rule-bot, so it is neither of those.
DEMO = "gullible"  # the example the demo opens first: its failures show what the check catches


def _demo_id(name: str) -> str:
    """The result id (folder under the runs folder) of one example defender's demo run."""
    return f"example-{name}/runs/demo-practice"


class UiError(Exception):
    """A request the page made that cannot be done; the message is shown as plain text."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


# --------------------------------------------------------------------------- local model servers


def detect(ports: tuple[int, ...] = DETECT_PORTS, timeout: float = 0.4) -> list[dict[str, Any]]:
    """Local chat-completions servers that answer GET /v1/models, with their model names."""
    found = []
    for port in ports:
        base = f"http://127.0.0.1:{port}/v1"
        try:
            with urllib.request.urlopen(base + "/models", timeout=timeout) as r:  # noqa: S310
                data = json.loads(r.read(1_000_000))
        except NET_ERRORS:  # nothing there, or not a model server
            continue
        names = []
        rows = data.get("data") if isinstance(data, dict) else None
        if not isinstance(rows, list) and isinstance(data, dict):
            rows = data.get("models")
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            name = row.get("id") or row.get("name") or row.get("model")
            if isinstance(name, str) and 0 < len(name) <= 200 and name.isprintable():
                names.append(name)
        found.append({"base_url": base, "models": sorted(set(names))[:100]})
    return found


# --------------------------------------------------------------------------- the live view

FEED = 8  # commands kept in the live feed
LINE = 140  # characters of an observation's first line


def snapshot(shift: Any, number: int, total: int) -> dict[str, Any]:
    """What the person watching sees of the incident in progress: the company's hosts with the
    intruder, isolations and outages, and the defender's last commands with the first line of
    what each returned. It is built from the interpreter for the page only; the defender itself
    never receives it."""
    inc = getattr(shift, "incident", {}) or {}
    out: dict[str, Any] = {
        "number": number,
        "total": total,
        "family": str(inc.get("family", "")),
        "seed": inc.get("seed"),
        "minute": shift.now if isinstance(shift.now, int) else 0,
        "commands": len(shift.commands),
        "feed": [],
        "hosts": {},
    }
    cmds, obs = shift.commands, shift.observations
    for i in range(max(0, len(cmds) - FEED), len(cmds)):
        first = (
            obs[i + 1].strip().splitlines()[0] if i + 1 < len(obs) and obs[i + 1].strip() else ""
        )
        out["feed"].append({"cmd": cmds[i][:200], "obs": first[:LINE]})
    hosts = getattr(shift, "hosts", None)
    if not hosts:
        return out
    held = 0
    for name, h in hosts.items():
        state = "clean"
        if h.present:
            state, held = "held", held + 1
        if shift.now < h.down_until:
            state = "down"
        elif shift.now < h.isolated_until:
            state = "held-cut" if h.present else "cut"
        out["hosts"][name] = state
    out["held"] = held
    out["contained"] = sum(1 for a in shift.actions if a["true"] and a["verb"] != "patch")
    out["wrong"] = sum(1 for a in shift.actions if not a["true"] and a["verb"] != "patch")
    return out


class Spy:
    """Wraps a driver and keeps a snapshot of the incident on the job after every command; the
    driver (and so the defender) is untouched."""

    def __init__(self, inner: Any, job: Job, number: int, total: int) -> None:
        self.inner, self.job, self.number, self.total = inner, job, number, total
        self.shift: Any = None

    def __call__(self, shift: Any) -> str | None:
        self.shift = shift
        self.job.live = snapshot(shift, self.number, self.total)
        return self.inner(shift)

    def end(self, summary: dict[str, Any]) -> None:
        if self.shift is not None:
            self.job.live = snapshot(self.shift, self.number, self.total)
        end = getattr(self.inner, "end", None)
        if callable(end):
            end(summary)

    def __getattr__(self, name: str) -> Any:  # notes, and anything else the runner reads
        return getattr(self.inner, name)


def watched(factory: Any, job: Job, total: int) -> Any:
    """A driver factory whose drivers report to the job's live view."""
    count = {"n": 0}

    def make() -> Spy:
        count["n"] += 1
        return Spy(factory(), job, count["n"], total)

    return make


def world_layout(world: Any = None) -> dict[str, Any]:
    """The company's hosts for the live map: name, zone and criticality (no incident data)."""
    from cyberarena.rc.world import resolve_world

    w = world or resolve_world(None)
    return {"zones": [z["id"] for z in w.zones],
            "hosts": [{"name": h["name"], "zone": h["zone"], "crit": w.crit(h["name"])}
                      for h in w.hosts]}  # fmt: skip


# --------------------------------------------------------------------------- jobs


class Job:
    """One background job: a connection check or a run."""

    def __init__(self, kind: str, name: str, total: int, estimate: float | None) -> None:
        self.kind, self.name, self.total = kind, name, total
        self.done = 0
        self.status = "running"
        self.message = ""
        self.error = ""
        self.result_id = ""
        self.started = time.monotonic()
        self.finished: float | None = None
        self.estimate = estimate  # seconds per step, from the timing probe
        self.live: dict[str, Any] | None = None

    def view(self) -> dict[str, Any]:
        end = self.finished if self.finished is not None else time.monotonic()
        elapsed = end - self.started
        return {
            "kind": self.kind,
            "name": self.name,
            "status": self.status,
            "done": self.done,
            "total": self.total,
            "elapsed": round(elapsed, 1),
            "remaining": remaining(elapsed, self.done, self.total, self.estimate)
            if self.status == "running"
            else 0,
            "message": self.message,
            "error": self.error,
            "result_id": self.result_id,
            "live": self.live,
        }


def remaining(elapsed: float, done: int, total: int, per_step: float | None) -> float | None:
    """Seconds left: from the pace so far once a step is done, else from the timing probe."""
    left = max(0, total - done)
    if done > 0:
        return round(elapsed / done * left, 1)
    if per_step is not None:
        return round(max(0.0, per_step * total - elapsed), 1)
    return None


def estimate_seconds(per_incident: float | None, incidents: int) -> float | None:
    """A rough time for a run of ``incidents`` from the seconds one incident took in the probe."""
    if per_incident is None:
        return None
    return round(per_incident * incidents * 1.15 + 2, 1)  # a margin: canaries are short


# --------------------------------------------------------------------------- the app


class App:
    """The state behind the page: the registry, keys held in memory, and the one job."""

    def __init__(self, registry_path: Path, allow_commands: bool = False,
                 detect_ports: tuple[int, ...] = DETECT_PORTS) -> None:  # fmt: skip
        self.path = registry_path
        self.folder = registry_path.resolve().parent
        self.allow_commands = allow_commands
        self.detect_ports = detect_ports
        self.token = secrets.token_urlsafe(32)
        self.keys: dict[str, str] = {}  # memory only, until the page stops
        self.lock = threading.Lock()
        self.job: Job | None = None
        self.stop = threading.Event()

    # ------------------------------------------------------------------ registry
    def registry(self) -> dict[str, Any]:
        from cyberarena.rc import registry as reg

        if not self.path.exists():
            return {"version": reg.REGISTRY_VERSION, "defenders": []}
        return reg.load(self.path)

    def runs_dir(self) -> Path:
        from cyberarena.rc.registry import runs_dir

        return runs_dir(self.path)

    def timing(self, name: str) -> float | None:
        try:
            data = json.loads((self.runs_dir() / name / "timing.json").read_text("utf-8"))
            return float(data["seconds_per_incident"])
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def state(self) -> dict[str, Any]:
        from cyberarena import __version__
        from cyberarena.rc.conformance import summary_line
        from cyberarena.rc.registry_cli import stored_conformance

        defenders = []
        for e in self.registry()["defenders"]:
            conf = stored_conformance(self.path, e)
            per = self.timing(e["name"])
            defenders.append({
                "entry": e,
                "label": describe(e),
                "has_key": e["name"] in self.keys,
                "runs_code": e["kind"] in RUNS_CODE,
                "conformance": summary_line(conf) if conf else "",
                "checked": bool(conf),
                "passed": (conf or {}).get("status") in ("passed", "built-in"),
                "estimates": {s: estimate_seconds(per, self.family_count(e) * n)
                              for s, n in SIZES.items()},  # fmt: skip
                "incidents": {s: self.family_count(e) * n for s, n in SIZES.items()},
            })  # fmt: skip
        with self.lock:
            job = self.job.view() if self.job else None
        return {
            "version": __version__,
            "registry": str(self.path),
            "allow_commands": self.allow_commands,
            "defenders": defenders,
            "job": job,
        }

    def save(self, body: dict[str, Any]) -> dict[str, Any]:
        from cyberarena.rc import registry as reg

        kind = body.get("kind")
        if kind not in ("model-endpoint", "http", "command"):
            raise UiError("Choose what you want to test first.")
        if kind == "command":
            self._may_run_code(body)
        entry: dict[str, Any] = {"name": _text(body.get("name"), "name", 40), "kind": kind,
                                 "role": "defender"}  # fmt: skip
        key = None
        if kind == "model-endpoint":
            entry["base_url"] = _text(body.get("base_url"), "address", 200)
            entry["model"] = _text(body.get("model"), "model name", 200)
            local = urllib.parse.urlsplit(entry["base_url"]).hostname in ("127.0.0.1", "localhost")
            entry["caps"] = (
                {"step_timeout": 120, "incident_timeout": 1800} if local else {"step_timeout": 60}
            )
            entry["meta"] = {"model_label": entry["model"]}
            if body.get("key_env"):
                entry["key_env"] = _text(body.get("key_env"), "variable name", 64)
            elif body.get("key"):
                key = _text(body.get("key"), "key", MAX_KEY)
                if any(c.isspace() for c in key):
                    raise UiError("The key cannot contain spaces.")
            if key or entry.get("key_env"):
                from cyberarena.rc.model_agent import key_transport_problem

                if key_transport_problem(entry["base_url"], "set"):
                    raise UiError("A key is only sent over https, or to a server on this computer.")
        elif kind == "http":
            entry["url"] = _text(body.get("url"), "address", 200)
        else:
            entry["command"] = _text(body.get("command"), "command", 1000)
            if body.get("mode") == "tools":
                entry["mode"] = "tools"
        world = body.get("world")
        if world not in (None, "", "harlow-pine"):
            entry["world"] = _text(world, "company", 300)
            self._check_world(entry)
        try:
            entry = reg.validate_entry(entry)
        except reg.RegistryError as exc:
            raise UiError(_plain_registry_error(str(exc))) from exc
        with self.lock:
            doc = self.registry()
            if any(e["name"] == entry["name"] for e in doc["defenders"]):
                raise UiError(f"A defender named {entry['name']} already exists; choose another "
                              "name.")  # fmt: skip
            doc["defenders"].append(entry)
            reg.save(self.path, doc)
            if key:
                self.keys[entry["name"]] = key
        return {"saved": entry["name"]}

    def remove(self, body: dict[str, Any]) -> dict[str, Any]:
        from cyberarena.rc import registry as reg

        name = _text(body.get("name"), "name", 40)
        with self.lock:
            if self.job and self.job.status == "running" and self.job.name == name:
                raise UiError("That defender is being checked or run right now.", 409)
            doc = self.registry()
            reg.get(doc, name)
            doc["defenders"] = [e for e in doc["defenders"] if e["name"] != name]
            reg.save(self.path, doc)
            self.keys.pop(name, None)
        return {"removed": name}

    def set_key(self, body: dict[str, Any]) -> dict[str, Any]:
        name = _text(body.get("name"), "name", 40)
        self._entry(name)
        key = _text(body.get("key"), "key", MAX_KEY)
        if any(c.isspace() for c in key):
            raise UiError("The key cannot contain spaces.")
        self.keys[name] = key
        return {"ok": True}

    def _entry(self, name: str) -> dict[str, Any]:
        from cyberarena.rc import registry as reg

        try:
            return reg.get(self.registry(), name)
        except reg.RegistryError as exc:
            raise UiError(str(exc), 404) from exc

    def _may_run_code(self, body: dict[str, Any]) -> None:
        if not self.allow_commands:
            raise UiError(
                "A program that runs on this computer can only be added from the command line, "
                "or after starting the page with: flagwake ui --allow-commands",
                403,
            )
        if body.get("confirm_runs_code") is not True:
            raise UiError("Confirm that you trust this program to run on this computer.", 403)

    # ------------------------------------------------------------------ jobs
    def _start(self, job: Job, work: Any) -> dict[str, Any]:
        with self.lock:
            if self.job and self.job.status == "running":
                raise UiError("Something is already running; wait for it or stop it first.", 409)
            self.job = job
            self.stop.clear()

        def run() -> None:
            try:
                work(job)
                if job.status == "running":
                    job.status = "stopped" if self.stop.is_set() else "done"
            except Exception as exc:  # shown to the user as plain text
                job.status = "failed"
                job.error = _plain_failure(exc)
            finally:
                job.finished = time.monotonic()

        threading.Thread(target=run, daemon=True).start()
        return {"started": job.kind}

    def check(self, body: dict[str, Any]) -> dict[str, Any]:
        from cyberarena.rc.registry import missing_program

        entry = self._entry(_text(body.get("name"), "name", 40))
        if entry["kind"] in RUNS_CODE:
            self._may_run_code(body)
        missing = missing_program(entry, self.folder)
        if missing:
            raise UiError(missing)
        job = Job("check", entry["name"], 5, self.timing(entry["name"]))
        return self._start(job, lambda j: self._check(j, entry))

    def _check_world(self, entry: dict[str, Any]) -> None:
        """A plain error when the entry's company cannot be loaded."""
        from cyberarena.rc.company import CompanyError

        try:
            self.world_of(entry)
        except CompanyError as exc:
            raise UiError("The company file is not valid: " + exc.problems[0]) from exc
        except ValueError as exc:
            raise UiError(str(exc)) from exc

    def _check(self, job: Job, entry: dict[str, Any]) -> None:
        from cyberarena.rc.conformance import run_conformance
        from cyberarena.rc.registry import driver_factory

        out = self.runs_dir() / entry["name"]
        if entry.get("mode") == "tools":
            self._check_tools(job, entry, out)
            return
        factory = watched(driver_factory(entry, self.folder, out / "conformance-log",
                                         key=self.keys.get(entry["name"])), job, 5)  # fmt: skip
        marks: list[float] = []

        def progress(_msg: str) -> None:
            marks.append(time.monotonic())
            job.done = len(marks) - 1
            job.message = f"Test incident {len(marks)} of 5"

        t0 = time.monotonic()
        result = run_conformance(entry, factory, progress=progress)
        out.mkdir(parents=True, exist_ok=True)
        (out / "conformance.json").write_text(
            json.dumps(result, sort_keys=True, indent=1) + "\n", encoding="utf-8", newline="\n"
        )
        if result.get("status") == "built-in":  # no protocol run: time one incident directly
            per = time_one(entry, self.folder, out)
        elif len(marks) >= 4:  # the three real test incidents
            per = (marks[3] - marks[0]) / 3
        else:  # the program failed early
            per = (time.monotonic() - t0) / max(1, len(marks))
        (out / "timing.json").write_text(
            json.dumps({"seconds_per_incident": round(per, 3)}) + "\n", encoding="utf-8",
            newline="\n",
        )  # fmt: skip
        job.done = 5
        job.message = "Connection check finished"

    def _check_tools(self, job: Job, entry: dict[str, Any], out: Path) -> None:
        """Connect-and-test in the tools mode: read an alert, call a read tool, close a ticket."""
        from cyberarena.rc.cli import split_command
        from cyberarena.rc.tools_cli import tools_conformance

        job.message = "Connecting through the tools"
        result = tools_conformance(split_command(entry["command"]), self.world_of(entry)[0],
                                   self.folder, out / "conformance-log")  # fmt: skip
        from cyberarena.rc.registry import entry_hash

        result["entry_hash"] = entry_hash(entry)
        out.mkdir(parents=True, exist_ok=True)
        (out / "conformance.json").write_text(
            json.dumps(result, sort_keys=True, indent=1) + "\n", encoding="utf-8", newline="\n"
        )
        per = float(result.get("seconds", 60.0)) / 2
        (out / "timing.json").write_text(json.dumps({"seconds_per_incident": round(per, 3)})
                                         + "\n", encoding="utf-8", newline="\n")  # fmt: skip
        job.done = 5
        job.message = "Connection check finished"

    def run(self, body: dict[str, Any]) -> dict[str, Any]:
        entry = self._entry(_text(body.get("name"), "name", 40))
        if entry["kind"] in RUNS_CODE:
            self._may_run_code(body)
        size, pack = body.get("size"), body.get("pack", "fresh")
        if size not in SIZES or pack not in PACKS:
            raise UiError("Choose how much to run.")
        from cyberarena.rc import rules

        fams = len(rules.families(self.world_of(entry)[0]))
        job = Job("run", entry["name"], fams * SIZES[size], self.timing(entry["name"]))
        return self._start(job, lambda j: self._run(j, entry, size, pack))

    def _run(self, job: Job, entry: dict[str, Any], size: str, pack: str) -> None:
        from cyberarena.rc import rules
        from cyberarena.rc.html import build_html
        from cyberarena.rc.protocol import new_run_key
        from cyberarena.rc.registry import caps_of, driver_factory, manifest
        from cyberarena.rc.registry_cli import contamination_warning, stored_conformance
        from cyberarena.rc.report import build_report, dumps, report_hash
        from cyberarena.rc.runner import build_pack, run_pack
        from cyberarena.rc.verify import verify

        name = entry["name"]
        stamp = time.strftime("%Y%m%d-%H%M%S")
        out = self.runs_dir() / name / "runs" / f"{stamp}-{size}-{pack}"
        world, world_file = self.world_of(entry)
        key = new_run_key()
        specs = build_pack(pack, per_family=SIZES[size], families=rules.families(world), key=key)
        factory = watched(driver_factory(entry, self.folder, out, key=self.keys.get(name)),
                          job, len(specs))  # fmt: skip
        job.message = "Running incidents"

        def progress(done: int, total: int) -> None:
            job.done, job.total = done, total

        from cyberarena.rc.registry_cli import native_integration

        if entry.get("mode") == "tools":  # the defender runs its own loop against the tools
            from cyberarena.rc.toolsrun import run_tools_entry

            result, integration = run_tools_entry(entry, self.folder, out, specs, 1, world, key)
        else:
            result = run_pack(factory, specs, max_commands=int(caps_of(entry)["max_commands"]),
                              progress=progress, stop=self.stop.is_set, world=world,
                              key=key)  # fmt: skip
            integration = native_integration(entry)
        if not result["outcomes"]:
            job.status = "stopped"
            job.message = "Stopped before the first incident finished; nothing was saved."
            return
        meta = {"id": f"registry:{name}", "note": "self-reported, not verified",
                "role": "defender", "manifest": manifest(entry),
                "conformance": stored_conformance(self.path, entry)}  # fmt: skip
        if result.get("stopped"):
            meta["stopped_early"] = f"stopped after {len(result['outcomes'])} of {job.total}"
        doc = build_report({"transcripts": result["transcripts"], "outcomes": result["outcomes"],
                            "run_key": key}, meta, pack_name=pack, world=world,
                           integration=integration)  # fmt: skip
        warning = contamination_warning(self.runs_dir() / name, pack, doc)
        if warning:
            doc["agent"]["contamination_warning"] = warning
            doc["report_hash"] = report_hash(doc)  # the warning is covered by the hash
        problems = verify(doc, world_file)
        for folder in (out, self.runs_dir() / name / pack):  # the page's history, the CLI's latest
            folder.mkdir(parents=True, exist_ok=True)
            (folder / "report.json").write_text(dumps(doc), encoding="utf-8", newline="\n")
            (folder / "report.html").write_text(build_html(doc, not problems), encoding="utf-8",
                                                newline="\n")  # fmt: skip
        job.result_id = out.relative_to(self.runs_dir()).as_posix()
        job.message = "Finished" if not result.get("stopped") else "Stopped early; partial result"
        if result.get("stopped"):
            job.status = "stopped"

    def family_count(self, entry: dict[str, Any]) -> int:
        """How many families a run of this entry covers (its world's; the default company's if
        its world cannot load)."""
        from cyberarena.rc import rules

        try:
            return len(rules.families(self.world_of(entry)[0]))
        except ValueError:
            return len(rules.families(rules.default_world()))

    def world_of(self, entry: dict[str, Any]) -> tuple[Any, str | None]:
        """The company an entry runs in (its world: field, else the default) and, for a company
        file, its path for verify. A file path is read relative to the registry folder."""
        from cyberarena.rc.cli import world_file_arg
        from cyberarena.rc.world import resolve_world

        value = entry.get("world")
        path = world_file_arg(value)
        if path and not Path(path).is_absolute():
            path = str(self.folder / path)
        return resolve_world(path or value), path

    def checks(self, name: Any) -> dict[str, Any]:
        from cyberarena.rc.registry_cli import stored_conformance
        from cyberarena.rc.ui_text import plain_checks

        entry = self._entry(_text(name, "name", 40))
        conf = stored_conformance(self.path, entry)
        return {
            "checks": plain_checks(conf),
            "passed": (conf or {}).get("status") in ("passed", "built-in"),
        }

    def stop_job(self) -> dict[str, Any]:
        with self.lock:
            if not self.job or self.job.status != "running":
                raise UiError("Nothing is running.", 409)
            if self.job.kind != "run":
                raise UiError("A connection check cannot be stopped; it ends within minutes.", 409)
            self.stop.set()
            self.job.message = "Stopping after the current incident"
        return {"stopping": True}

    # ------------------------------------------------------------------ results
    def runs(self) -> list[dict[str, Any]]:
        base = self.runs_dir()
        files = list(base.glob("*/runs/*/report.json")) + [
            p for p in base.glob("*/*/report.json") if p.parent.name in PACKS
        ]
        # The page saves each run twice (its own history and the command line's latest copy);
        # keep the history copy, then list newest first.
        files.sort(key=lambda p: ("runs" not in p.parts, -p.stat().st_mtime))
        seen, out = set(), []
        for f in files[:400]:
            try:
                doc = json.loads(f.read_text(encoding="utf-8"))
                m = doc["metrics"]
            except (OSError, ValueError, KeyError, TypeError):
                continue
            if doc.get("report_hash") in seen:
                continue
            seen.add(doc.get("report_hash"))
            out.append({
                "id": f.parent.relative_to(base).as_posix(),
                "name": f.relative_to(base).parts[0],
                "pack": doc.get("pack"),
                "incidents": m["incidents"],
                "damage": m["damage_index"]["mean_clipped"],
                "when": time.strftime("%Y-%m-%d %H:%M", time.localtime(f.stat().st_mtime)),
                "stopped": bool((doc.get("agent") or {}).get("stopped_early")),
                "mtime": f.stat().st_mtime,
            })  # fmt: skip
        out.sort(key=lambda r: -r.pop("mtime"))
        return out[:200]

    def _report(self, rid: Any) -> tuple[Path, dict[str, Any]]:
        if not isinstance(rid, str) or rid not in {r["id"] for r in self.runs()}:
            raise UiError("No such result.", 404)
        path = self.runs_dir() / rid / "report.json"
        return path, json.loads(path.read_text(encoding="utf-8"))

    def result(self, rid: Any) -> dict[str, Any]:
        from cyberarena.rc.demo import POINTS_NOTE, cost_items, cost_totals, kpi_items
        from cyberarena.rc.ui_text import plain_checks, plain_result

        path, doc = self._report(rid)
        return {
            "id": rid,
            "pair": self._pair() if str(rid).startswith("example-") else [],
            "costs": {"items": cost_items(doc), **cost_totals(doc), "note": POINTS_NOTE},
            "kpis": kpi_items(doc),
            "plain": plain_result(doc),
            "checks": plain_checks((doc.get("agent") or {}).get("conformance")),
            "verify": f'flagwake verify "{path}"',
            "stopped": (doc.get("agent") or {}).get("stopped_early"),
        }

    def download(self, rid: Any, name: Any) -> tuple[bytes, str]:
        path, _doc = self._report(rid)
        if name not in ("report.json", "report.html"):
            raise UiError("No such file.", 404)
        ctype = "application/json" if name.endswith(".json") else "text/html; charset=utf-8"
        return (path.parent / name).read_bytes(), ctype

    def compare(self, a: Any, b: Any) -> dict[str, Any]:
        _pa, da = self._report(a)
        _pb, db = self._report(b)
        return {
            "same_incidents": [(i["family"], i["seed"]) for i in da["incidents"]]
            == [(i["family"], i["seed"]) for i in db["incidents"]],
            "rows": compare_rows(da, db),
            "names": [a, b],
        }

    # ------------------------------------------------------------------ demo, verify, tamper
    def demo(self, _body: dict[str, Any]) -> dict[str, Any]:
        """Run the shipped example defenders on the same practice incidents and save each like a
        run; the page opens the gullible one and shows both side by side.

        Scripted, so it takes a second or two; it always writes the same folders, so repeating the
        demo does not pile up results.
        """
        from cyberarena.rc.demo import EXAMPLES
        from cyberarena.rc.html import build_html
        from cyberarena.rc.report import build_report, dumps
        from cyberarena.rc.runner import baseline_driver, pack_specs, run_pack
        from cyberarena.rc.verify import verify
        from cyberarena.rc.world import shipped_world

        with self.lock:
            if self.job and self.job.status == "running":
                raise UiError("Wait for the current run or check to finish.", 409)
        world = shipped_world()
        specs = pack_specs("practice", 1, world=world)
        for name in EXAMPLES:
            result = run_pack(functools.partial(baseline_driver, name), specs, world=world)
            doc = build_report(
                result,
                {"id": f"baseline:{name}"},
                pack_name="practice",
                world=world,
                integration={"adapter": "built-in program"},
            )
            out = self.runs_dir() / _demo_id(name)
            out.mkdir(parents=True, exist_ok=True)
            (out / "report.json").write_text(dumps(doc), encoding="utf-8", newline="\n")
            (out / "report.html").write_text(build_html(doc, not verify(doc)), encoding="utf-8",
                                             newline="\n")  # fmt: skip
        return {"id": _demo_id(DEMO), "pair": self._pair()}

    def _pair(self) -> list[dict[str, Any]]:
        """The demo's example results that exist, in order: id, name, score, verdict, tone."""
        from cyberarena.rc.demo import EXAMPLES
        from cyberarena.rc.ui_text import verdict

        out = []
        for name in EXAMPLES:
            path = self.runs_dir() / _demo_id(name) / "report.json"
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
                words, tone = verdict(doc)
                score = doc["metrics"]["damage_index"]["mean_clipped"]
            except (OSError, ValueError, KeyError, TypeError):
                continue
            out.append({"id": _demo_id(name), "name": f"example-{name}", "score": score,
                        "verdict": words, "tone": tone})  # fmt: skip
        return out

    def _world_file(self, rid: str) -> str | None:
        """The company file a result was made in, when its defender runs in one (for verify)."""
        name = rid.split("/")[0]
        for entry in self.registry()["defenders"]:
            if entry["name"] == name:
                try:
                    return self.world_of(entry)[1]
                except ValueError:
                    return None
        return None

    def verify_result(self, body: dict[str, Any]) -> dict[str, Any]:
        """Re-derive every number of a saved result, as ``flagwake verify`` does."""
        from cyberarena.rc.demo import commands
        from cyberarena.rc.verify import verify

        rid = body.get("id")
        _path, doc = self._report(rid)
        problems = verify(doc, self._world_file(str(rid)))
        return {
            "ok": not problems,
            "problems": [p[:300] for p in problems[:3]],
            "commands": commands(doc),
            "incidents": len(doc.get("incidents") or []),
        }

    def tamper(self, body: dict[str, Any]) -> dict[str, Any]:
        """Verify a copy of a result with its damage index lowered (in memory; the file stays)."""
        from cyberarena.rc.demo import tampered_copy
        from cyberarena.rc.verify import verify

        rid = body.get("id")
        _path, doc = self._report(rid)
        bad, before, after = tampered_copy(doc)
        found = verify(bad, self._world_file(str(rid)))
        return {"before": round(before, 1), "after": round(after, 1), "caught": bool(found),
                "message": found[0][:300] if found else ""}  # fmt: skip


def compare_rows(da: dict[str, Any], db: dict[str, Any]) -> list[list[str]]:
    """Plain rows comparing two reports (label, first, second)."""

    def idx(d: dict[str, Any]) -> str:
        di = d["metrics"]["damage_index"]
        if di["mean_clipped"] is None:
            return "n/a"
        return f"{di['mean_clipped']:.0f} ({di['ci95'][0]:.0f}-{di['ci95'][1]:.0f})"

    def pct(r: dict[str, Any]) -> str:
        return "n/a" if r["rate"] is None else f"{r['rate'] * 100:.0f}% of {r['den']}"

    rows = [["Damage score (lower is better)", idx(da), idx(db)]]
    for label, get in (
        ("Intruder-held computers cut off", lambda m: m["containment"]["true_containment"]),
        ("Actions on untouched computers", lambda m: m["containment"]["false_containment"]),
        ("Planted instructions followed", lambda m: m["injection"]["violation_rate"]),
        ("Big actions with approval", lambda m: m["approval"]["compliance"]),
        ("Quiet incidents closed cleanly", lambda m: m["restraint"]),
    ):
        rows.append([label, pct(get(da["metrics"])), pct(get(db["metrics"]))])
    rows.append(["Incidents", str(da["metrics"]["incidents"]), str(db["metrics"]["incidents"])])
    return rows


def time_one(entry: dict[str, Any], folder: Path, out: Path) -> float:
    """Seconds one practice incident takes for this defender (a built-in one needs no probe)."""
    from cyberarena.rc.registry import driver_factory
    from cyberarena.rc.runner import run_incident

    t0 = time.monotonic()
    run_incident({"family": "cred-reuse", "seed": 140001, "difficulty": "standard"},
                 driver_factory(entry, folder, out)())  # fmt: skip
    return max(0.01, time.monotonic() - t0)


def describe(entry: dict[str, Any]) -> str:
    """What the defender is, in plain words."""
    kind = entry["kind"]
    if kind == "model-endpoint":
        host = urllib.parse.urlsplit(entry["base_url"]).hostname
        where = "on this computer" if host in ("127.0.0.1", "localhost") else "online"
        return f"A model {where}: {entry['model']}"
    if kind == "http":
        return f"A service at {entry['url']}"
    if kind == "baseline":
        return f"An example program shipped with the check ({entry['baseline']})"
    return f"A program on this computer: {entry.get('command', '')}"


def _text(value: Any, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise UiError(f"Fill in the {field}.")
    value = value.strip()
    if len(value) > limit or not value.isprintable():
        raise UiError(f"The {field} is too long or has characters that are not allowed.")
    return value


def _plain_registry_error(msg: str) -> str:
    msg = re.sub(r"^defender (\d+|'[^']*'): ", "", msg)
    if "name must be" in msg:
        return ("The name can use small letters, digits, dots, dashes and underscores, up to 40 "
                "characters.")  # fmt: skip
    if "url must be http://127.0.0.1" in msg:
        return "The service address must start with http://127.0.0.1 or http://localhost."
    if "base_url must be" in msg:
        return "The address must start with http:// or https://."
    return msg[0].upper() + msg[1:] if msg else "That is not valid."


def _plain_failure(exc: Exception) -> str:
    text = str(exc)
    if "could not be run" in text or "exited with code" in text or "nothing answered" in text:
        return ("The defender could not be started or reached. Check that it is running and run "
                "the connection check again.")  # fmt: skip
    if "failed in 3 incidents in a row" in text:
        return ("The defender stopped answering in three incidents in a row, so the run was "
                "stopped. Run the connection check to see what is wrong.")  # fmt: skip
    return "Something went wrong: " + text[:300]


# --------------------------------------------------------------------------- HTTP


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "flagwake-ui"
    app: App
    port: int

    def log_message(self, *_args: object) -> None:  # nothing is logged, the token included
        pass

    # ------------------------------------------------------------------ guards
    def _hosts(self) -> tuple[set[str], set[str]]:
        hosts = {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}
        return hosts, {f"http://{h}" for h in hosts}

    def _guard(self, changing: bool) -> bool:
        hosts, origins = self._hosts()
        if self.headers.get("Host", "") not in hosts:
            return self._fail(421, "This page only answers on its own local address.")
        # Only a plain "/path" target: the routes look at the parsed path, so an absolute-form
        # target ("http://host/api/...") would otherwise reach them without the token check.
        if not self.path.startswith("/") or self.path.startswith("//"):
            return self._fail(400, "Bad request target.")
        if urllib.parse.urlsplit(self.path).path.startswith("/api/"):
            token = self.headers.get(TOKEN_HEADER, "")
            if not hmac.compare_digest(token.encode(), self.app.token.encode()):
                return self._fail(403, "Open the page with the address printed when it started.")
        if changing:
            if self.headers.get("Origin", "") not in origins:
                return self._fail(403, "Requests from other sites are refused.")
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                return self._fail(415, "Send JSON.")
        return True

    def _fail(self, status: int, message: str) -> bool:
        self._json(status, {"error": message})
        return False

    def _drain(self) -> None:
        """Read and drop a small unread request body, then close: on some systems closing a
        connection with unread bytes resets it before the client reads the answer."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if 0 < length <= 1_000_000:
            self.rfile.read(length)
        self.close_connection = True

    def _headers(self, status: int, ctype: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")

    def _json(self, status: int, obj: Any) -> None:
        body = json.dumps(obj, ensure_ascii=True).encode("ascii")
        self._headers(status, "application/json", len(body))
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------ routes
    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        if not self._guard(changing=False):
            return
        url = urllib.parse.urlsplit(self.path)
        if not url.path.startswith("/api/"):
            static = STATIC.get(url.path)
            if static is None:
                self._fail(404, "Not found.")
                return
            body = (WEB / static[0]).read_bytes()
            self._headers(200, static[1], len(body))
            self.end_headers()
            self.wfile.write(body)
            return
        q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        app = self.app
        try:
            if url.path == "/api/state":
                self._json(200, app.state())
            elif url.path == "/api/checks":
                self._json(200, app.checks(q.get("name")))
            elif url.path == "/api/world":
                name = urllib.parse.parse_qs(url.query).get("name", [""])[0][:40]
                entries = [e for e in self.app.registry()["defenders"] if e["name"] == name]
                world = self.app.world_of(entries[0])[0] if entries else None
                self._json(200, world_layout(world))
            elif url.path == "/api/runs":
                self._json(200, {"runs": app.runs()})
            elif url.path == "/api/detect":
                servers = detect(app.detect_ports)
                self._json(200, {"servers": servers, "help": "" if servers else NO_SERVER_HELP})
            elif url.path == "/api/result":
                self._json(200, app.result(q.get("id")))
            elif url.path == "/api/compare":
                self._json(200, app.compare(q.get("a"), q.get("b")))
            elif url.path == "/api/download":
                body, ctype = app.download(q.get("id"), q.get("file"))
                self._headers(200, ctype, len(body))
                self.send_header("Content-Disposition", f'attachment; filename="{q["file"]}"')
                self.end_headers()
                self.wfile.write(body)
            else:
                self._fail(404, "Not found.")
        except UiError as exc:
            self._fail(exc.status, str(exc))

    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        if not self._guard(changing=True):
            self._drain()  # a refused request's body is read, so the refusal reaches the sender
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_BODY:
            if 0 < length <= 1_000_000:  # read it first, so the refusal reaches the sender
                self.rfile.read(length)
            self.close_connection = True
            self._fail(413, "The request is too large.")
            return
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            body = None
        if not isinstance(body, dict):
            self._fail(400, "Send one JSON object.")
            return
        routes = {
            "/api/defenders": self.app.save,
            "/api/defenders/remove": self.app.remove,
            "/api/key": self.app.set_key,
            "/api/check": self.app.check,
            "/api/run": self.app.run,
            "/api/stop": lambda _b: self.app.stop_job(),
            "/api/demo": self.app.demo,
            "/api/verify": self.app.verify_result,
            "/api/tamper": self.app.tamper,
        }
        handler = routes.get(urllib.parse.urlsplit(self.path).path)
        if handler is None:
            self._fail(404, "Not found.")
            return
        try:
            self._json(200, handler(body))
        except UiError as exc:
            self._fail(exc.status, str(exc))


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = False


def make_server(app: App, port: int = 0) -> Server:
    """A server for ``app`` bound to 127.0.0.1 (port 0: a free port)."""
    server = Server(("127.0.0.1", port), Handler)
    bound = server.server_address[1]
    server.RequestHandlerClass = type("UiHandler", (Handler,), {"app": app, "port": bound})
    return server


def serve(registry_path: Path, port: int = 0, open_browser: bool = True,
          allow_commands: bool = False) -> int:  # fmt: skip
    app = App(registry_path, allow_commands)
    try:
        server = make_server(app, port)
    except OSError as exc:
        print(f"error: cannot listen on 127.0.0.1:{port} ({exc}); try another --port")
        return 2
    url = f"http://127.0.0.1:{server.server_address[1]}/#t={app.token}"
    print(
        "Flagwake is running on this computer only. Open this address in your browser:", flush=True
    )
    print(f"  {url}", flush=True)
    print("Keep this window open while you use it; press Ctrl+C here to stop.", flush=True)
    if open_browser:
        webbrowser.open(url)
    with server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
    return 0
