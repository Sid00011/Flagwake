"""``flagwake tools``: serve the company as tools, show the catalogue, connect-and-test.

``serve`` runs a pack as a queue of tickets for a defender you start yourself: it prints the MCP
and REST addresses and the token, waits until every ticket is closed (or Ctrl+C), then writes
report.json and report.html. ``--stdio`` serves MCP on stdin/stdout instead, for a client that
starts its own servers. ``test`` is the connect-and-test check of a defender in this mode: on two
canary incidents it must read an alert, call a read tool and close a ticket.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

CANARY_SEEDS = [140000, 140001]  # reserved: no pack uses them
READ_TOOLS = ("search_logs", "get_host", "list_hosts", "get_user", "list_business_flows",
              "contact_user")  # fmt: skip


def add_subparsers(sub: argparse._SubParsersAction) -> None:
    from cyberarena.rc.cli import WORLD_HELP

    t = sub.add_parser("tools", help="serve the simulated company as tools (MCP and REST)")
    tsub = t.add_subparsers(dest="tools_command")
    s = tsub.add_parser("serve", help="serve a pack as tickets to a defender you start yourself")
    s.add_argument("--world", help=WORLD_HELP)
    from cyberarena.rc.cli import RUN_KEY_HELP
    from cyberarena.rc.packs import run_key_arg

    s.add_argument(
        "--pack",
        choices=("fresh", "heldout", "practice"),
        default="fresh",
        help="fresh (default: seeds drawn for this run), heldout or practice",
    )
    s.add_argument("--run-key", type=run_key_arg, help=RUN_KEY_HELP)
    s.add_argument("--seeds", type=int, default=10, help="seeds per family (default 10)")
    s.add_argument("--port", type=int, default=0, help="port on 127.0.0.1 (default: a free one)")
    s.add_argument("--out", default="tools-out", help="folder for report.json/.html")
    s.add_argument("--stdio", action="store_true", help="serve MCP on stdin/stdout instead")
    s.add_argument("--label", help="self-reported: the defender's name or model label")
    tsub.add_parser("catalogue", help="print the tool catalogue (JSON)")
    tsub.add_parser("openapi", help="print the OpenAPI document of the REST API (JSON)")
    te = tsub.add_parser("test", help="connect-and-test a defender that uses the tools")
    te.add_argument(
        "--command",
        dest="start_command",
        required=True,
        help="the command that starts the defender",
    )
    te.add_argument("--world", help=WORLD_HELP)
    te.add_argument("--timeout", type=float, default=300.0, help="seconds for the whole check")


def cmd_tools(args: argparse.Namespace) -> int:
    which = getattr(args, "tools_command", None)
    if which == "catalogue":
        from cyberarena.rc.toolsapi import TOOLS

        print(json.dumps(TOOLS, indent=1, sort_keys=True))
        return 0
    if which == "openapi":
        from cyberarena.rc.toolsrun import openapi

        print(json.dumps(openapi(), indent=1, sort_keys=True))
        return 0
    if which == "serve":
        return _serve(args)
    if which == "test":
        from cyberarena.rc.cli import load_world_arg, split_command

        world = load_world_arg(args.world)
        if world is None:
            return 2
        res = tools_conformance(split_command(args.start_command), world, Path.cwd(),
                                Path("tools-test"), args.timeout)  # fmt: skip
        for c in res["checks"]:
            print(f"  {'PASS' if c['passed'] else 'FAIL'}  {c['name']}: {c['detail']}")
        print(f"connect-and-test: {res['status']}")
        return 0 if res["status"] == "passed" else 1
    print("usage: flagwake tools {serve,catalogue,openapi,test} (see --help)", file=sys.stderr)
    return 2


def _serve(args: argparse.Namespace) -> int:
    from cyberarena.rc import rules
    from cyberarena.rc.cli import load_world_arg, world_file_arg, world_lines
    from cyberarena.rc.html import build_html
    from cyberarena.rc.packs import build_pack
    from cyberarena.rc.protocol import new_run_key
    from cyberarena.rc.report import TOOLS, build_report, dumps, terminal_summary
    from cyberarena.rc.toolsrun import TicketDesk, ToolsServer, serve_stdio
    from cyberarena.rc.verify import verify

    world = load_world_arg(args.world)
    if world is None:
        return 2
    key = getattr(args, "run_key", None) or new_run_key()
    specs = build_pack(args.pack, per_family=args.seeds, families=rules.families(world), key=key)
    desk = TicketDesk(specs, world, key=key)
    log = sys.stderr
    for line in world_lines(world):
        print(line, file=log)
    if args.stdio:
        adapter = "external defender over MCP stdio (environment as tools)"
        serve_stdio(desk)
    else:
        adapter = "external defender over HTTP (environment as tools)"
        server = ToolsServer(desk, port=args.port).start()
        a = server.addresses()
        print(f"{len(specs)} tickets ready. Give your defender:\n  MCP (HTTP):  {a['mcp']}\n"
              f"  REST API:    {a['api']}  (OpenAPI: {a['openapi']})\n"
              f"  token:       {a['token']}  (header Authorization: Bearer <token>)\n"
              "Waiting until every ticket is closed (Ctrl+C ends the run early) ...",
              file=log)  # fmt: skip
        try:
            while not desk.complete.wait(0.5):
                if desk.idle():
                    desk.expire(f"no tool call within {desk.idle_timeout:.0f} s")
        except KeyboardInterrupt:
            pass
        server.close()
    desk.stop_all("the run ended before this ticket was closed")
    meta: dict[str, Any] = {"id": "tools:external", "note": "self-reported, not verified"}
    if args.label:
        meta["manifest"] = {"meta": {"model_label": args.label[:200]}}
    doc = build_report(desk.result(), meta, pack_name=args.pack, world=world,
                       integration={"mode": TOOLS, "adapter": adapter,
                                    "instruction_text": "none"})  # fmt: skip
    problems = verify(doc, world_file_arg(args.world))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(dumps(doc), encoding="utf-8", newline="\n")
    (out / "report.html").write_text(build_html(doc, not problems), encoding="utf-8",
                                     newline="\n")  # fmt: skip
    print(terminal_summary(doc, not problems), file=log)
    return 0 if not problems else 1


def tools_conformance(argv: list[str], world: Any, folder: Path, out: Path,
                      timeout: float = 300.0) -> dict[str, Any]:  # fmt: skip
    """The connect-and-test check in mode tools, on two canary incidents."""
    from cyberarena.rc.toolsrun import TicketDesk, run_command_as_tools

    specs = [{"family": "quiet", "seed": CANARY_SEEDS[0], "difficulty": "trivial"},
             {"family": "noisy-false-positive", "seed": CANARY_SEEDS[1],
              "difficulty": "trivial"}]  # fmt: skip
    desk = TicketDesk(specs, world, idle_timeout=min(timeout, 120.0))
    t0 = time.monotonic()
    try:
        run_command_as_tools(argv, desk, folder, out, timeout)
    except OSError as exc:
        return {
            "status": "failed",
            "mode": "tools",
            "passed": 0,
            "total": 1,
            "checks": [{"name": "starts", "passed": False, "detail": str(exc)[:200]}],
        }
    calls = [c for t in desk.transcripts for c in t["calls"]]
    names = [c["tool"] for c in calls]
    closed = sum(1 for t in desk.transcripts if t["end_reason"] == "report")
    bad = sum(1 for t in desk.transcripts for c in t["commands"] if c.startswith("tool:"))
    checks = [
        {"name": "connects", "passed": bool(calls), "detail": f"{len(calls)} tool calls"},
        {"name": "reads an alert", "passed": any(n in ("get_alerts", "get_alert") for n in names),
         "detail": "get_alerts or get_alert"},
        {"name": "calls a read tool", "passed": any(n in READ_TOOLS for n in names),
         "detail": ", ".join(READ_TOOLS)},
        {"name": "closes a ticket", "passed": closed >= 1, "detail": f"{closed} of 2 closed"},
        {"name": "well-formed calls", "passed": bad <= max(1, len(calls) // 5),
         "detail": f"{bad} malformed of {len(calls)}"},
    ]  # fmt: skip
    for c in checks:
        c["id"] = "tools-" + str(c["name"]).replace(" ", "-")
    ok = sum(1 for c in checks if c["passed"])
    return {"status": "passed" if ok == len(checks) else "failed", "mode": "tools",
            "passed": ok, "total": len(checks), "checks": checks,
            "seconds": round(time.monotonic() - t0, 1)}  # fmt: skip
