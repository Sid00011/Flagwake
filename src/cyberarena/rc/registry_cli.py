"""Command-line handlers for the defender registry: ``init``, ``defenders``, ``run`` and ``view``.

``flagwake init`` writes an empty ``flagwake.yaml``; ``flagwake defenders add|list|show|remove|
test`` edits and checks it; ``flagwake run`` runs registered defenders over a pack and writes one
report per defender and pack under ``flagwake-runs/``; ``flagwake view`` serves the report viewer
on 127.0.0.1 and opens it on the newest report. Everything stays on this machine.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cyberarena.rc.registry import CAPS, KINDS, META, RegistryError

CONTAMINATION_GAP = 15.0  # index points by which practice may beat held-out before a warning


def add_subparsers(sub: argparse._SubParsersAction) -> None:
    """Register init, defenders, run and view on the top-level parser."""
    i = sub.add_parser("init", help="create flagwake.yaml, the defender registry, in this folder")
    i.add_argument("--config", help="registry path (default ./flagwake.yaml)")
    i.add_argument("--force", action="store_true", help="overwrite an existing registry")

    d = sub.add_parser("defenders", help="add, list, show, remove or test registered defenders")
    dsub = d.add_subparsers(dest="defenders_command")
    a = dsub.add_parser("add", help="register a defender (interactive without --name)")
    a.add_argument("--name")
    a.add_argument("--kind", choices=KINDS)
    a.add_argument(
        "--command", dest="start_command", help="kind command or mcp: the command that starts it"
    )
    a.add_argument("--url", help="kind http: a localhost endpoint")
    a.add_argument("--base-url", help="kind model-endpoint: a chat-completions base URL")
    a.add_argument("--model", help="kind model-endpoint: the model id")
    a.add_argument("--key-env", help="kind model-endpoint: the NAME of the variable with a key")
    a.add_argument("--extra-body", help="kind model-endpoint: a JSON object added to requests")
    a.add_argument("--baseline", help="kind baseline: a shipped scripted program")
    a.add_argument("--tool", help="kind mcp: the tool that returns the next command (act)")
    for cap in CAPS:
        a.add_argument("--" + cap.replace("_", "-"), type=float, dest="cap_" + cap)
    a.add_argument("--model-label", help="self-reported: which model it runs")
    a.add_argument("--agent-version", help="self-reported: its version")
    a.add_argument("--description", help="self-reported: one line about it")
    a.add_argument("--config")
    for name, text in (("list", "list registered defenders"), ("show", "show one defender"),
                       ("remove", "remove one defender"),
                       ("test", "run the conformance suite on one defender")):  # fmt: skip
        p = dsub.add_parser(name, help=text)
        if name != "list":
            p.add_argument("name")
        p.add_argument("--config")

    r = sub.add_parser("run", help="run registered defenders over a pack and write reports")
    who = r.add_mutually_exclusive_group()
    who.add_argument("--defender", action="append", help="a registered name (repeatable)")
    who.add_argument("--all", action="store_true", help="every registered defender")
    from cyberarena.rc.cli import RUN_KEY_HELP
    from cyberarena.rc.packs import run_key_arg

    r.add_argument(
        "--pack",
        choices=("fresh", "heldout", "practice"),
        default="fresh",
        help="fresh (default: seeds drawn for this run), heldout or practice",
    )
    r.add_argument("--run-key", type=run_key_arg, help=RUN_KEY_HELP)
    r.add_argument("--seeds", type=int, default=10, help="seeds per family (default 10)")
    r.add_argument("--repeat", type=int, default=1, help="runs per incident (run-to-run spread)")
    r.add_argument("--no-conformance", action="store_true", help="skip the conformance suite")
    r.add_argument("--world", help="the company (overrides the entry's world:); default "
                   "harlow-pine")  # fmt: skip
    r.add_argument("--config")

    u = sub.add_parser("ui", help="open the local page: add a defender, check it, run, read")
    u.add_argument("--port", type=int, default=0, help="port on 127.0.0.1 (default: a free one)")
    u.add_argument("--no-open", action="store_true", help="do not open a browser")
    u.add_argument(
        "--allow-commands",
        action="store_true",
        help="let the page add and run programs on this computer (asks to confirm each time)",
    )
    u.add_argument("--config")

    v = sub.add_parser("view", help="serve the report viewer on 127.0.0.1 with the newest report")
    v.add_argument("--report", help="a report.json to show (default: the newest one)")
    v.add_argument("--port", type=int, default=8077)
    v.add_argument("--no-open", action="store_true", help="do not open a browser")
    v.add_argument("--config")


# --------------------------------------------------------------------------- helpers


def _path(args: argparse.Namespace) -> Path:
    from cyberarena.rc.registry import find_registry

    return find_registry(getattr(args, "config", None))


def _fail(msg: str) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return 2


# --------------------------------------------------------------------------- init


def cmd_init(args: argparse.Namespace) -> int:
    from cyberarena.rc.registry import REGISTRY_VERSION, save

    path = _path(args)
    if path.exists() and not args.force:
        return _fail(f"{path} exists; use --force to replace it")
    save(path, {"version": REGISTRY_VERSION, "defenders": []})
    print(f"wrote {path}")
    print("next: flagwake defenders add   (or: flagwake defenders add --name careful "
          "--kind baseline --baseline careful)")  # fmt: skip
    return 0


# --------------------------------------------------------------------------- defenders


def cmd_defenders(args: argparse.Namespace) -> int:
    handler = {
        "add": _add,
        "list": _list,
        "show": _show,
        "remove": _remove,
        "test": _test,
    }.get(args.defenders_command)
    if handler is None:
        print("usage: flagwake defenders {add,list,show,remove,test}", file=sys.stderr)
        return 2
    try:
        return handler(args)
    except RegistryError as exc:
        return _fail(str(exc))


def entry_from_args(args: argparse.Namespace) -> dict[str, Any]:
    """A raw entry from ``defenders add`` flags (validated by the caller)."""
    entry: dict[str, Any] = {"name": args.name, "kind": args.kind, "role": "defender"}
    if args.start_command is not None:
        entry["command"] = args.start_command
    for field in ("url", "base_url", "model", "key_env", "baseline", "tool"):
        value = getattr(args, field, None)
        if value is not None:
            entry[field] = value
    if args.extra_body is not None:
        try:
            entry["extra_body"] = json.loads(args.extra_body)
        except ValueError as exc:
            raise RegistryError("--extra-body must be a JSON object") from exc
    caps = {}
    for cap in CAPS:
        v = getattr(args, "cap_" + cap, None)
        if v is not None:
            caps[cap] = int(v) if float(v).is_integer() else v
    if caps:
        entry["caps"] = caps
    meta = {
        k: v
        for k, v in (
            ("model_label", args.model_label),
            ("version", args.agent_version),
            ("description", args.description),
        )  # fmt: skip
        if v is not None
    }
    if meta:
        entry["meta"] = meta
    return entry


def entry_interactive(ask: Callable[[str], str]) -> dict[str, Any]:
    """Build an entry by asking one question per field (blank keeps the default)."""
    from cyberarena.rc.registry import KIND_FIELDS

    entry: dict[str, Any] = {"name": ask("name (a-z, 0-9, . _ -): ").strip()}
    kind = ask(f"kind ({' | '.join(KINDS)}): ").strip()
    entry["kind"] = kind
    entry["role"] = "defender"
    questions = {
        "command": "command line that starts it (run without a shell, from this folder): ",
        "url": "localhost endpoint, e.g. http://127.0.0.1:8000/act: ",
        "base_url": "chat-completions base URL, e.g. http://localhost:8080/v1: ",
        "model": "model id: ",
        "key_env": "name of the environment variable holding a key (blank: none): ",
        "extra_body": "extra request body as a JSON object (blank: none): ",
        "baseline": "shipped program (careful, rule-bot, do-nothing, ...): ",
        "tool": "MCP tool that returns the next command (blank: act): ",
    }
    required, optional = KIND_FIELDS.get(kind, ((), ()))
    for field in required + optional:
        value = ask(questions[field]).strip()
        if not value:
            continue
        if field == "extra_body":
            try:
                entry[field] = json.loads(value)
            except ValueError as exc:
                raise RegistryError("extra body must be a JSON object") from exc
        else:
            entry[field] = value
    caps = {}
    for cap in CAPS:
        value = ask(f"cap {cap} (blank: default): ").strip()
        if value:
            try:
                num = float(value)
            except ValueError as exc:
                raise RegistryError(f"cap {cap} must be a number") from exc
            caps[cap] = int(num) if num.is_integer() else num
    if caps:
        entry["caps"] = caps
    meta = {}
    for key in META:
        value = ask(f"self-reported {key.replace('_', ' ')} (blank: none): ").strip()
        if value:
            meta[key] = value
    if meta:
        entry["meta"] = meta
    return entry


def _add(args: argparse.Namespace, ask: Callable[[str], str] | None = None) -> int:
    from cyberarena.rc.registry import load, save, validate_entry

    path = _path(args)
    doc = load(path)
    if args.name is None:
        if ask is None and not sys.stdin.isatty():
            return _fail("give --name and --kind (or run in a terminal to answer questions)")
        entry = entry_interactive(ask or input)
    else:
        if args.kind is None:
            return _fail("give --kind with --name")
        entry = entry_from_args(args)
    entry = validate_entry(entry)
    if any(e["name"] == entry["name"] for e in doc["defenders"]):
        return _fail(f"a defender named {entry['name']!r} exists; remove it first")
    doc["defenders"].append(entry)
    save(path, doc)
    print(f"added {entry['name']} ({entry['kind']}) to {path}")
    print(f"next: flagwake defenders test {entry['name']}")
    return 0


def _how(entry: dict[str, Any]) -> str:
    return {
        "command": lambda e: e["command"],
        "mcp": lambda e: f"{e['command']} (tool {e.get('tool', 'act')})",
        "http": lambda e: e["url"],
        "model-endpoint": lambda e: f"{e['model']} at {e['base_url']}",
        "baseline": lambda e: f"shipped program {e['baseline']}",
    }[entry["kind"]](entry)


def _list(args: argparse.Namespace) -> int:
    from cyberarena.rc.conformance import summary_line
    from cyberarena.rc.registry import load

    path = _path(args)
    doc = load(path)
    if not doc["defenders"]:
        print(f"no defenders in {path}; add one with: flagwake defenders add")
        return 0
    for e in doc["defenders"]:
        label = (e.get("meta") or {}).get("model_label", "")
        conf = summary_line(stored_conformance(path, e)).replace("conformance: ", "")
        print(f"{e['name']:20} {e['kind']:15} {_how(e)[:48]:48} {label[:20]:20} {conf}")
    return 0


def _show(args: argparse.Namespace) -> int:
    from cyberarena.rc.conformance import summary_line
    from cyberarena.rc.registry import dump_yaml, get, load, runs_dir

    path = _path(args)
    entry = get(load(path), args.name)
    lines = dump_yaml({"version": 1, "defenders": [entry]}).splitlines()
    print("\n".join(line[4:] for line in lines[lines.index("defenders:") + 1 :]))
    result = stored_conformance(path, entry)
    print(summary_line(result))
    for c in (result or {}).get("checks", []):
        print(f"  {'PASS' if c['passed'] else 'FAIL'}  {c['name']}: {c['detail']}")
    for report in sorted((runs_dir(path) / entry["name"]).glob("*/report.json")):
        print(f"report: {report}")
    return 0


def _remove(args: argparse.Namespace) -> int:
    from cyberarena.rc.registry import get, load, save

    path = _path(args)
    doc = load(path)
    get(doc, args.name)
    doc["defenders"] = [e for e in doc["defenders"] if e["name"] != args.name]
    save(path, doc)
    print(f"removed {args.name} from {path} (its reports under flagwake-runs/ are kept)")
    return 0


def stored_conformance(path: Path, entry: dict[str, Any]) -> dict[str, Any] | None:
    """The saved conformance result for this exact entry, or None (missing or entry changed)."""
    from cyberarena.rc.registry import entry_hash, runs_dir

    f = runs_dir(path) / entry["name"] / "conformance.json"
    try:
        result = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return result if result.get("entry_hash") == entry_hash(entry) else None


def check_entry(path: Path, entry: dict[str, Any]) -> dict[str, Any]:
    """Run the conformance suite for an entry and save the result next to its reports."""
    from cyberarena.rc.conformance import run_conformance
    from cyberarena.rc.registry import driver_factory, runs_dir

    out = runs_dir(path) / entry["name"]
    if entry.get("mode") == "tools":  # connect-and-test through the tools, not the text protocol
        if entry["kind"] == "baseline":
            result: dict[str, Any] = {"status": "built-in", "mode": "tools"}
        else:
            from cyberarena.rc.cli import split_command
            from cyberarena.rc.tools_cli import tools_conformance
            from cyberarena.rc.world import resolve_world

            result = tools_conformance(split_command(entry["command"]), resolve_world(None),
                                       path.resolve().parent, out / "conformance-log")  # fmt: skip
        from cyberarena.rc.registry import entry_hash

        result["entry_hash"] = entry_hash(entry)
    else:
        factory = driver_factory(entry, path.resolve().parent, out / "conformance-log")
        result = run_conformance(entry, factory,
                                 progress=lambda m: print("  " + m, file=sys.stderr))  # fmt: skip
    out.mkdir(parents=True, exist_ok=True)
    (out / "conformance.json").write_text(
        json.dumps(result, sort_keys=True, indent=1) + "\n", encoding="utf-8", newline="\n"
    )
    return result


def _test(args: argparse.Namespace) -> int:
    from cyberarena.rc.conformance import summary_line
    from cyberarena.rc.registry import get, load, missing_program

    path = _path(args)
    entry = get(load(path), args.name)
    missing = missing_program(entry, path.resolve().parent)
    if missing:
        return _fail(missing)
    print(f"conformance suite for {entry['name']} ({entry['kind']}):", file=sys.stderr)
    result = check_entry(path, entry)
    for c in result.get("checks", []):
        print(f"  {'PASS' if c['passed'] else 'FAIL'}  {c['name']}: {c['detail']}")
    if result.get("detail"):
        print("  " + result["detail"])
    print(summary_line(result))
    return 0 if result["status"] in ("passed", "built-in") else 1


# --------------------------------------------------------------------------- run


def cmd_run(args: argparse.Namespace) -> int:
    from cyberarena.rc.registry import get, load

    path = _path(args)
    try:
        doc = load(path)
        if args.all:
            entries = list(doc["defenders"])
        elif args.defender:
            entries = [get(doc, n) for n in args.defender]
        else:
            return _fail("give --defender NAME or --all")
    except RegistryError as exc:
        return _fail(str(exc))
    if not entries:
        return _fail(f"no defenders in {path}; add one with: flagwake defenders add")
    if args.pack == "practice":
        print("note: practice seeds are public; leave out --pack (fresh incidents) for claims.",
              file=sys.stderr)  # fmt: skip
    worst = 0
    for entry in entries:
        worst = max(worst, run_entry(path, entry, args))
    return worst


REFERENCE_SCAFFOLD = "the reference scaffold's instructions (cyberarena/rc/model_agent.py)"


def native_integration(entry: dict[str, Any]) -> dict[str, str]:
    """The fidelity disclosure of a native-protocol run of a registry entry."""
    kind = entry["kind"]
    if kind == "baseline":
        return {"adapter": "built-in program"}
    if kind == "model-endpoint":
        return {"adapter": "model + reference scaffold (native protocol)",
                "instruction_text": REFERENCE_SCAFFOLD}  # fmt: skip
    return {"adapter": f"{kind} (native protocol)"}


def run_entry(path: Path, entry: dict[str, Any], args: argparse.Namespace) -> int:
    """Run one registered defender over the pack; write its report; return an exit code."""
    from cyberarena.rc.conformance import summary_line
    from cyberarena.rc.html import build_html
    from cyberarena.rc.protocol import ProtocolError, new_run_key
    from cyberarena.rc.registry import caps_of, driver_factory, manifest, missing_program, runs_dir
    from cyberarena.rc.report import build_report, dumps, report_hash, terminal_summary
    from cyberarena.rc.runner import build_pack, run_pack
    from cyberarena.rc.verify import verify

    name = entry["name"]
    missing = missing_program(entry, path.resolve().parent)
    if missing:
        print(f"error: {missing}", file=sys.stderr)
        return 2
    out = runs_dir(path) / name / args.pack
    conformance = stored_conformance(path, entry)
    if conformance is None and not args.no_conformance:
        print(f"{name}: conformance suite first ...", file=sys.stderr)
        conformance = check_entry(path, entry)
    print(f"{name}: {summary_line(conformance)}", file=sys.stderr)
    from cyberarena.rc import rules
    from cyberarena.rc.cli import load_world_arg, world_file_arg, world_lines

    world_arg = getattr(args, "world", None) or entry.get("world")
    if world_arg and world_file_arg(world_arg) and not Path(world_arg).is_absolute():
        world_arg = str(path.resolve().parent / world_arg)  # relative to the registry
    world = load_world_arg(world_arg)
    if world is None:
        return 2
    for line in world_lines(world):
        print(f"{name}: {line}", file=sys.stderr)
    key = getattr(args, "run_key", None) or new_run_key()
    specs = build_pack(args.pack, per_family=args.seeds, families=rules.families(world), key=key)
    print(f"{name}: running {len(specs)} incidents x {args.repeat} ...", file=sys.stderr)
    try:
        if entry.get("mode") == "tools":
            from cyberarena.rc.toolsrun import run_tools_entry

            result, integration = run_tools_entry(entry, path.resolve().parent, out, specs,
                                                  args.repeat, world, key)  # fmt: skip
        else:
            factory = driver_factory(entry, path.resolve().parent, out)
            result = run_pack(factory, specs, repeat=args.repeat,
                              max_commands=int(caps_of(entry)["max_commands"]),
                              world=world, key=key)  # fmt: skip
            integration = native_integration(entry)
    except (OSError, ProtocolError) as exc:
        print(f"error: {name} could not be run: {exc}", file=sys.stderr)
        return 2
    meta = {
        "id": f"registry:{name}",
        "note": "self-reported, not verified",
        "role": "defender",
        "manifest": manifest(entry),
        "conformance": conformance,
    }
    doc = build_report(result, meta, pack_name=args.pack, world=world, integration=integration)
    warning = contamination_warning(runs_dir(path) / name, args.pack, doc)
    if warning:
        doc["agent"]["contamination_warning"] = warning
        doc["report_hash"] = report_hash(doc)  # the warning is covered by the hash
    problems = verify(doc, world_file_arg(world_arg))
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(dumps(doc), encoding="utf-8", newline="\n")
    (out / "report.html").write_text(build_html(doc, not problems), encoding="utf-8",
                                     newline="\n")  # fmt: skip
    print(terminal_summary(doc, not problems))
    if warning:
        print("WARNING: " + warning)
    print(f"\n{name}: report written to {out}/", file=sys.stderr)
    return 0 if not problems else 1


def contamination_warning(folder: Path, pack: str, doc: dict[str, Any]) -> str | None:
    """A warning when this defender's practice index is far better than on unseen incidents.

    Practice seeds are public, so a program tuned on them (or a model that saw them) can score
    better there than on fresh or held-out seeds. "Far" means more than
    :data:`CONTAMINATION_GAP` points apart with 95% intervals that do not overlap (lower index is
    better).
    """
    others = ("fresh", "heldout") if pack == "practice" else ("practice",)
    prev_di = None
    for other in others:
        try:
            prev = json.loads((folder / other / "report.json").read_text(encoding="utf-8"))
            prev_di = prev["metrics"]["damage_index"]
            break
        except (OSError, ValueError, KeyError, TypeError):
            continue
    if prev_di is None:
        return None
    di = doc["metrics"]["damage_index"]
    practice, heldout = (di, prev_di) if pack == "practice" else (prev_di, di)
    if practice["mean_clipped"] is None or heldout["mean_clipped"] is None:
        return None
    gap = heldout["mean_clipped"] - practice["mean_clipped"]
    if gap > CONTAMINATION_GAP and practice["ci95"][1] < heldout["ci95"][0]:
        return (
            f"practice index {practice['mean_clipped']:.1f} is {gap:.1f} points better than "
            f"unseen {heldout['mean_clipped']:.1f} with non-overlapping intervals: the public "
            "practice seeds may have been learned. Use fresh numbers for claims."
        )
    return None


# --------------------------------------------------------------------------- view


def latest_report(path: Path) -> Path | None:
    """The newest report.json under flagwake-runs/, else ./check-out/report.json."""
    from cyberarena.rc.registry import runs_dir

    found = sorted(
        runs_dir(path).glob("*/*/report.json"), key=lambda p: (p.stat().st_mtime, str(p))
    )
    if found:
        return found[-1]
    fallback = Path.cwd() / "check-out" / "report.json"
    return fallback if fallback.is_file() else None


def cmd_view(args: argparse.Namespace) -> int:
    from cyberarena.rc.serve import serve

    report = Path(args.report) if args.report else latest_report(_path(args))
    if report is None or not report.is_file():
        return _fail("no report found; run: flagwake run --defender <name>  (or pass --report)")
    return serve(port=args.port, report=report, open_browser=not args.no_open)


# --------------------------------------------------------------------------- ui


def cmd_ui(args: argparse.Namespace) -> int:
    from cyberarena.rc.ui import serve

    return serve(_path(args), port=args.port, open_browser=not args.no_open,
                 allow_commands=args.allow_commands)  # fmt: skip
