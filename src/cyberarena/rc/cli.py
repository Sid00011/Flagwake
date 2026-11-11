"""Command-line handlers for the Responder Check, wired into ``cyberarena.cli``.

Subcommands: ``check`` (run an agent or a baseline over a pack and write a report), ``replay``
(print one incident of a report or transcript as a plain transcript), ``baselines`` (run the
shipped agents and print a table), ``doctor``, ``mcp`` (the stdio server) and ``serve`` (the
report viewer on localhost). ``verify`` and ``report`` dispatch on the report schema.
"""

from __future__ import annotations

import argparse
import functools
import json
import sys
from pathlib import Path
from typing import Any

from cyberarena.rc.baselines import ALL_AGENTS, BASELINES, FIXTURES
from cyberarena.rc.gen2 import DIFFICULTIES
from cyberarena.rc.gen2 import FAMILIES as ALL_FAMILIES
from cyberarena.rc.packs import PACKS, run_key_arg

PACK_HELP = (
    "which incidents: fresh (default for check: seeds drawn for this run), heldout (fixed, never "
    "in docs), practice (public) or full"
)
RUN_KEY_HELP = (
    "repeat the incidents of an earlier run: give its report's run_key (a fresh key, the "
    "default, is what keeps the incidents unknown in advance)"
)
WORLD_HELP = (
    "the company: harlow-pine (default, 18 hosts), fenwick-brae (60 hosts), legacy (the "
    "original rules) or a company file you wrote (flagwake world init)"
)


def load_world_arg(value: str | None):
    """The world named by --world, or None after printing a plain error."""
    from cyberarena.rc.company import CompanyError
    from cyberarena.rc.world import resolve_world

    try:
        return resolve_world(value)
    except CompanyError as exc:
        print("error: the company file is not valid:\n  " + "\n  ".join(exc.problems),
              file=sys.stderr)  # fmt: skip
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
    return None


def world_lines(world) -> list[str]:
    """What a run says about its world: custom company, custom costs, skipped families."""
    from cyberarena.rc import rules

    out = []
    if world.rules >= 2 and world.custom:
        out.append(f"world: custom company file {world.name} ({world.version}, "
                   f"{len(world.hosts)} hosts; digest {world.digest[:12]})")  # fmt: skip
    if world.rules >= 2 and world.cost:
        out.append("custom costs, not comparable with the default pack")
    for fam, why in rules.skipped(world):
        out.append(f"skipped {fam}: {why}")
    return out


def world_file_arg(value: str | None) -> str | None:
    """--world as a file path for verify (None for a shipped company or no value)."""
    from cyberarena.rc.world import SHIPPED

    if not value or value in SHIPPED or value in ("legacy", "hp-2"):
        return None
    return value


def add_subparsers(sub: argparse._SubParsersAction) -> None:
    """Register the Responder Check subcommands on the top-level parser."""
    c = sub.add_parser("check", help="run a responder agent over the Responder Check and report")
    c.add_argument(
        "--agent",
        help='a subprocess agent, e.g. --agent "python my_agent.py", '
        "or baseline:<name> / fixture:<name>",
    )
    c.add_argument("--http", help="a localhost agent endpoint, e.g. http://127.0.0.1:8000/act")
    c.add_argument("--pack", choices=PACKS, default="fresh", help=PACK_HELP)
    c.add_argument("--run-key", type=run_key_arg, help=RUN_KEY_HELP)
    c.add_argument("--seeds", type=int, default=10, help="seeds per family (default 10)")
    c.add_argument(
        "--family",
        choices=sorted(ALL_FAMILIES),
        action="append",
        help="restrict to a family (repeatable)",
    )
    c.add_argument("--world", help=WORLD_HELP)
    c.add_argument("--repeat", type=int, default=1, help="runs per incident (stochastic agents)")
    c.add_argument("--difficulty", choices=DIFFICULTIES, help="force one difficulty")
    c.add_argument("--out", default="check-out", help="folder for report.json/.html")
    c.add_argument("--step-timeout", type=float, default=60.0, help="seconds per command")
    c.add_argument(
        "--incident-timeout", type=float, default=900.0, help="seconds per incident (wall clock)"
    )
    c.add_argument(
        "--fail-under", type=float, help="exit non-zero if the damage index exceeds this"
    )
    c.add_argument("--json", action="store_true", help="print the report JSON to stdout")

    r = sub.add_parser(
        "replay", help="print one incident of a report or transcript as a plain transcript"
    )
    r.add_argument("source", help="a report.json or a transcript file")
    r.add_argument("--incident", help="which one: family:seed (default: the first)")
    r.add_argument("--world", help="the company file a custom-world report was made from")

    b = sub.add_parser("baselines", help="run the shipped scripted agents and print a table")
    b.add_argument("--pack", choices=PACKS, default="practice", help=PACK_HELP)
    b.add_argument("--seeds", type=int, default=10)
    b.add_argument("--json", action="store_true")
    b.add_argument("--out", help="also write each baseline's report.json under this folder")
    b.add_argument("--world", help=WORLD_HELP)

    d = sub.add_parser(
        "doctor", help="check a model endpoint or an agent with a 3-incident smoke test (~1 min)"
    )
    d.add_argument("--agent", help='an agent command to check, e.g. --agent "python my_agent.py"')
    d.add_argument("--http", help="a localhost agent endpoint to check")
    d.add_argument("--timeout", type=float, default=40.0, help="seconds per model call or command")
    d.add_argument("--world", help=WORLD_HELP)

    m = sub.add_parser("mcp", help="run the Responder Check as a stdio MCP server")
    m.add_argument("--log-dir", default="rc-mcp-log", help="where finished transcripts are written")
    m.add_argument("--world", help=WORLD_HELP)

    s = sub.add_parser("serve", help="serve the report viewer on 127.0.0.1")
    s.add_argument("--port", type=int, default=8077)

    from cyberarena.rc.registry_cli import add_subparsers as _registry_add

    _registry_add(sub)


# --------------------------------------------------------------------------- check


def cmd_check(args: argparse.Namespace) -> int:
    from cyberarena.rc import rules
    from cyberarena.rc.protocol import ProtocolError, new_run_key
    from cyberarena.rc.report import build_report, dumps, terminal_summary
    from cyberarena.rc.runner import build_pack, run_pack
    from cyberarena.rc.verify import verify

    world = load_world_arg(getattr(args, "world", None))
    if world is None:
        return 2
    bound = rules.families(world)
    if args.family:
        missing = [f for f in args.family if f not in bound]
        if missing:
            why = dict(rules.skipped(world))
            for f in missing:
                print(f"error: {f} cannot run in this world: "
                      f"{why.get(f, 'not part of its rules')}", file=sys.stderr)  # fmt: skip
            return 2
    families = tuple(args.family) if args.family else bound
    key = args.run_key or new_run_key()
    specs = build_pack(args.pack, per_family=args.seeds, families=families, key=key)
    if args.difficulty:
        specs = [{**s, "difficulty": args.difficulty} for s in specs]

    factory, meta = _agent_factory(args)
    if factory is None:
        return 2
    for line in world_lines(world):
        print(line, file=sys.stderr)
    print(f"Running {len(specs)} incidents x {args.repeat} ...", file=sys.stderr)
    try:
        result = run_pack(factory, specs, repeat=args.repeat, world=world, key=key)
    except (OSError, ProtocolError) as exc:
        print(f"error: the responder could not be run: {exc}", file=sys.stderr)
        log = Path(args.out) / "agent-stderr.log"
        if log.is_file() and log.stat().st_size:
            tail = log.read_text(encoding="utf-8", errors="replace").splitlines()[-5:]
            print("last lines of its stderr:\n  " + "\n  ".join(tail), file=sys.stderr)
        print("Check the --agent command; see docs/PROTOCOL.md for the protocol.", file=sys.stderr)
        return 2
    doc = build_report(result, meta, pack_name=args.pack, world=world,
                       integration=_integration(args))  # fmt: skip
    problems = verify(doc, world_file_arg(getattr(args, "world", None)))
    verified = not problems
    for p in problems:
        print(f"  verify problem: {p}", file=sys.stderr)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(dumps(doc), encoding="utf-8", newline="\n")
    from cyberarena.rc.html import build_html

    (out / "report.html").write_text(build_html(doc, verified), encoding="utf-8", newline="\n")
    print(terminal_summary(doc, verified))
    print(
        f"\nreport.json and report.html written to {out}/ (local files; nothing sent anywhere).",
        file=sys.stderr,
    )
    if args.json:
        print(dumps(doc))
    if args.fail_under is not None:
        idx = doc["metrics"]["damage_index"]["mean_clipped"]
        if idx is not None and idx > args.fail_under:
            print(f"damage index {idx} exceeds --fail-under {args.fail_under}", file=sys.stderr)
            return 1
    return 0 if verified else 1


def _integration(args: argparse.Namespace) -> dict[str, str]:
    """The fidelity disclosure of a check run: native protocol, and which adapter."""
    if args.http:
        return {"adapter": "HTTP endpoint (native protocol)"}
    if (args.agent or "").startswith(("baseline:", "fixture:")):
        return {"adapter": "built-in program"}
    return {"adapter": "subprocess (native protocol)"}


def _agent_factory(args: argparse.Namespace):
    """Return (driver_factory, agent_meta) for --agent / --http, or (None, None) on error."""
    from cyberarena.rc.protocol import http_driver_factory, subprocess_driver_factory

    if args.http:
        try:
            return http_driver_factory(args.http, args.step_timeout, args.incident_timeout), {
                "id": f"http:{args.http}",
                "note": "self-reported, not verified",
            }
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return None, None
    agent = args.agent
    if not agent:
        print("error: give --agent or --http (try --agent baseline:careful)", file=sys.stderr)
        return None, None
    if agent.startswith(("baseline:", "fixture:")):
        name = agent.split(":", 1)[1]
        if name not in ALL_AGENTS:
            print(
                f"error: unknown agent {name!r}; choose from {', '.join(sorted(ALL_AGENTS))}",
                file=sys.stderr,
            )
            return None, None
        return (lambda n=name: baseline_driver_import(n)), {
            "id": f"baseline:{name}",
            "track": "reference",
        }
    stderr_log = str(Path(args.out) / "agent-stderr.log")
    Path(args.out).mkdir(parents=True, exist_ok=True)

    argv = split_command(agent)
    factory = subprocess_driver_factory(argv, args.step_timeout, stderr_log, args.incident_timeout)
    return factory, {
        "id": f"subprocess:{argv[0]}",
        "note": "self-reported, not verified",
    }


def split_command(command: str) -> list[str]:
    """Split an --agent command line into argv.

    On Windows the split keeps backslashes (paths) but also keeps the quotes around a quoted
    word, which would then reach the program name; they are removed here, so
    ``"C:\\Program Files\\Python\\python.exe" agent.py`` works.
    """
    import shlex

    if sys.platform != "win32":
        return shlex.split(command)
    words = shlex.split(command, posix=False)
    return [w[1:-1] if len(w) >= 2 and w[0] == w[-1] and w[0] in "\"'" else w for w in words]


def baseline_driver_import(name: str):
    from cyberarena.rc.runner import baseline_driver

    return baseline_driver(name)


# --------------------------------------------------------------------------- baselines


def cmd_baselines(args: argparse.Namespace) -> int:

    from cyberarena.rc.protocol import new_run_key
    from cyberarena.rc.report import build_report, dumps
    from cyberarena.rc.runner import baseline_driver, pack_specs, run_pack

    world = load_world_arg(getattr(args, "world", None))
    if world is None:
        return 2
    for line in world_lines(world):
        print(line, file=sys.stderr)
    key = new_run_key()  # one draw for every program, so the table compares the same incidents
    specs = pack_specs(args.pack, args.seeds, world=world, key=key)
    rows = {}
    reports = {}
    for name in ALL_AGENTS:
        result = run_pack(functools.partial(baseline_driver, name), specs, world=world, key=key)
        doc = build_report(result, {"id": f"baseline:{name}"}, pack_name=args.pack, world=world,
                           integration={"adapter": "built-in program"})  # fmt: skip
        reports[name] = doc
        m = doc["metrics"]
        rows[name] = {
            "index": m["damage_index"]["mean_clipped"],
            "worse": m["damage_index"]["worse_than_do_nothing"],
            "false_cont": m["containment"]["false_containment"]["num"],
            "collateral": m["collateral"]["benign_hosts_disrupted"],
            "contained": m["containment"]["true_containment"]["rate"],
            "inj": m["injection"]["violation_rate"]["rate"],
            "restraint": m["restraint"]["rate"],
            "check": m["cost"]["mean_investigation_minutes"],
            "first_act": m["cost"]["median_minutes_before_first_action"],
        }
    if args.out:
        base = Path(args.out)
        base.mkdir(parents=True, exist_ok=True)
        for name, doc in reports.items():
            (base / f"{name}.json").write_text(dumps(doc), encoding="utf-8", newline="\n")
    if args.json:
        print(json.dumps(rows, sort_keys=True, indent=1))
        return 0
    order = list(BASELINES) + list(FIXTURES)
    per = f"{args.seeds} seed{'s' if args.seeds != 1 else ''} per family"
    print(f"Reference programs on pack {args.pack} ({per}, {len(specs)} incidents):\n")
    print(
        f"{'agent':22} {'index':>6} {'worse':>5} {'falseC':>6} {'collat':>6} {'cont':>5} "
        f"{'inj':>5} {'restr':>5} {'check':>6} {'1st':>5}"
    )
    for name in order:
        r = rows[name]
        print(
            f"{name:22} {_f(r['index']):>6} {r['worse']:>5} {r['false_cont']:>6} "
            f"{r['collateral']:>6} {_f(r['contained']):>5} {_f(r['inj']):>5} "
            f"{_f(r['restraint']):>5} {_f(r['check']):>6} {_f(r['first_act']):>5}"
        )
    print(
        "\nindex: business damage, 0 = oracle, 100 = do-nothing (clipped mean); worse: incidents "
        "worse than doing nothing;\nfalseC: actions on benign targets; collat: benign hosts "
        "disrupted; cont/inj/restr: rates of containment,\nplanted orders obeyed and quiet "
        "incidents closed cleanly; check: mean minutes spent checking;\n1st: median minute of the "
        "first action (n/a = never acted)."
    )
    return 0


def _f(x: Any) -> str:
    return "n/a" if x is None else (f"{x:.2f}" if isinstance(x, float) else str(x))


# --------------------------------------------------------------------------- replay


def cmd_replay(args: argparse.Namespace) -> int:
    try:
        doc = json.loads(Path(args.source).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: cannot read {args.source}: {exc}", file=sys.stderr)
        return 2
    incident = _pick_incident(doc, args.incident)
    if incident is None:
        print("error: no such incident in the file (use family:seed)", file=sys.stderr)
        return 2
    from cyberarena.rc import rules

    try:
        world = rules.world_of_report(doc if isinstance(doc, dict) and "incidents" in doc
                                      else {}, getattr(args, "world", None))  # fmt: skip
    except (rules.WorldMismatch, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(transcript_text(incident, world))
    return 0


def transcript_text(incident: dict[str, Any], world: Any = None) -> str:
    """One incident re-run from its stored commands, as plain text.

    Each entry gives the simulated minute the command was issued, the command, the simulated
    minutes it took and the observation it returned; the end gives the business cost and the
    ground truth. The text comes from a fresh interpreter, never from the file, so it shows what
    the commands actually did.
    """
    from cyberarena.rc import rules
    from cyberarena.rc.engine import SHIFT_MINUTES, Shift
    from cyberarena.rc.scoring import score_shift

    w = world or rules.legacy_world()
    inc = rules.generate(w, incident["family"], incident["seed"], incident["difficulty"])
    shift = Shift(inc, w)
    first = shift.reset()
    out = [
        f"Incident {inc['family']}:{inc['seed']} ({inc['difficulty']}), "
        f"{len(incident['commands'])} commands stored",
        "",
        "[minute 0] start",
        _indent(first["text"]),
    ]
    for cmd in incident["commands"]:
        if shift.done:
            break
        minute = shift.now
        obs, info = shift.step(cmd)
        out += ["", f"[minute {minute}] > {cmd}  (took {info['cost']} min)", _indent(obs["text"])]
    shift.finish()
    sc = score_shift(shift)
    cont = sc["containment"]
    truth = inc["truth"]
    out += [
        "",
        f"End: {ENDINGS.get(shift.end_reason, shift.end_reason)}, after {len(shift.commands)} "
        f"commands; the incident window is {SHIFT_MINUTES} simulated minutes.",
        f"Business cost: damage {sc['damage']} (oracle {sc['oracle_damage']}, do-nothing "
        f"{sc['do_nothing_damage']}); damage index "
        + ("n/a (no intruder)" if sc["index"] is None else str(sc["index"]))
        + " (0 = oracle, 100 = do-nothing).",
        f"Containment: {cont['contained']}/{cont['true_compromised_hosts']} compromised hosts; "
        f"{cont['false_containment_actions']} action(s) on benign targets; planted orders "
        f"obeyed: {len(sc['injection']['violations'])}.",
        "Ground truth: "
        + (
            "no intruder."
            if truth.get("quiet")
            else "compromised " + (", ".join(truth.get("compromised", [])) or "nothing") + "."
        ),
    ]
    return "\n".join(out)


ENDINGS = {
    "report": "closed with a report",
    "time": "the incident window ran out",
    "commands": "the command limit was reached",
    "unfinished": "stopped without a report",
}


def _indent(text: str) -> str:
    return "\n".join("  " + line for line in text.splitlines())


def _pick_incident(doc: Any, which: str | None) -> dict[str, Any] | None:
    incidents = doc.get("incidents") if isinstance(doc, dict) else None
    if incidents is None and isinstance(doc, dict) and "commands" in doc:
        incidents = [doc]  # a bare transcript
    if not incidents:
        return None
    if which is None:
        return incidents[0]
    fam, _, seed = which.partition(":")
    for inc in incidents:
        if inc.get("family") == fam and str(inc.get("seed")) == seed:
            return inc
    return None


def cmd_doctor(args: argparse.Namespace) -> int:
    from cyberarena.rc.doctor import doctor

    return doctor(args)


# --------------------------------------------------------------------------- mcp / serve


def cmd_mcp(args: argparse.Namespace) -> int:
    from cyberarena.rc.mcp import serve

    world = load_world_arg(getattr(args, "world", None))
    if world is None:
        return 2
    return serve(log_dir=args.log_dir, world=world)


def cmd_serve(args: argparse.Namespace) -> int:
    from cyberarena.rc.serve import serve

    return serve(port=args.port)


# --------------------------------------------------------------------------- report --mcp-log


def _mcp_world(transcripts: list[dict[str, Any]], world_arg: str | None):
    """The company a folder of MCP transcripts ran in, or None after printing a plain error.

    A transcript records its rules and its company (name and digest). A shipped company is found
    by name; a company file must be given again with --world, as for verify.
    """
    from cyberarena.rc import rules
    from cyberarena.rc.world import SHIPPED, shipped_world

    seen = {(int(t.get("rules", 1)), str((t.get("world") or {}).get("digest", "")))
            for t in transcripts}  # fmt: skip
    if len(seen) != 1:
        print("error: the transcripts come from different companies; score each company's "
              "folder on its own", file=sys.stderr)  # fmt: skip
        return None
    (rules_n, digest), info = next(iter(seen)), transcripts[0].get("world") or {}
    if world_arg:
        world = load_world_arg(world_arg)
    elif rules_n == 1:
        world = rules.legacy_world()
    elif not info.get("custom") and info.get("name") in SHIPPED:
        world = shipped_world(info["name"])
    else:
        print(f"error: these transcripts ran in a custom company ({info.get('name', 'unnamed')}); "
              "give the same company file with --world <file>", file=sys.stderr)  # fmt: skip
        return None
    if world is not None and (world.rules != rules_n or (rules_n >= 2 and world.digest != digest)):
        print("error: the company given is not the one the transcripts ran in (its digest "
              "differs)", file=sys.stderr)  # fmt: skip
        return None
    return world


def cmd_report_mcp(args: argparse.Namespace) -> int:
    """``flagwake report --mcp-log <dir>``: score MCP transcripts into a report."""
    from cyberarena.rc import rules
    from cyberarena.rc.engine import Shift
    from cyberarena.rc.html import build_html
    from cyberarena.rc.report import build_report, dumps, terminal_summary
    from cyberarena.rc.runner import obs_hash
    from cyberarena.rc.scoring import score_shift
    from cyberarena.rc.verify import verify

    d = Path(args.mcp_log)
    files = sorted(d.glob("*.json"))
    if not files:
        print(f"error: no transcript files in {d}", file=sys.stderr)
        return 2
    raw = []
    for f in files:
        try:
            tr = json.loads(f.read_text(encoding="utf-8"))
            if tr.get("schema") != "flagwake-rc-transcript-1":
                raise ValueError("not a Responder Check transcript")
        except (OSError, ValueError, AttributeError) as exc:
            print(f"error: {f.name}: {exc}", file=sys.stderr)
            return 2
        raw.append(tr)
    world_arg = getattr(args, "world", None)
    world = _mcp_world(raw, world_arg)
    if world is None:
        return 2
    transcripts, outcomes = [], []
    for f, tr in zip(files, raw, strict=True):
        try:
            inc = rules.generate(world, tr["family"], tr["seed"], tr["difficulty"])
        except (KeyError, TypeError, ValueError) as exc:
            print(f"error: {f.name}: cannot rebuild its incident ({exc})", file=sys.stderr)
            return 2
        shift = Shift(inc, world)
        first = shift.reset()
        hashes = [obs_hash(first["text"])]
        for cmd in tr["commands"]:
            if shift.done:
                break
            obs, _ = shift.step(cmd)
            hashes.append(obs_hash(obs["text"]))
        shift.finish()
        kept = {k: v for k, v in tr.items() if k not in ("rules", "world")}
        transcripts.append({**kept, "obs_hashes": hashes})
        outcomes.append(score_shift(shift))
    doc = build_report(
        {"transcripts": transcripts, "outcomes": outcomes},
        {"id": "mcp-run", "note": "self-reported, not verified"},
        pack_name="mcp",
        world=world,
    )
    problems = verify(doc, world_file_arg(world_arg))
    out = Path(args.out) if args.out else Path("mcp-report")
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(dumps(doc), encoding="utf-8", newline="\n")
    (out / "report.html").write_text(build_html(doc, not problems), encoding="utf-8", newline="\n")
    print(terminal_summary(doc, not problems))
    return 0 if not problems else 1
