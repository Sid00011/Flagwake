"""Command-line entry point of ``flagwake``.

The Responder Check commands (``check``, ``baselines``, ``replay``, ``doctor``, ``mcp``,
``serve``) are registered from ``cyberarena.rc.cli``, the registry commands (``init``,
``defenders``, ``run``, ``view``) from ``cyberarena.rc.registry_cli``; ``verify`` and ``report``
are defined here.
"""

from __future__ import annotations

import argparse
import json
import textwrap
from collections.abc import Sequence

from cyberarena import __version__

DESCRIPTION = (
    "Flagwake Responder Check: a free, offline, re-checkable test of how an AI defender behaves "
    "during a security incident, scored with business cost."
)
# The commands as `flagwake --help` lists them: what a newcomer needs first, then the rest.
GROUPS: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
    ("Start here", (
        ("demo", "see it work in a few seconds: two example defenders, a report, verify"),
        ("ui", "the local page: add a defender, check it, run it, read the result"),
    )),
    ("Test a defender", (
        ("init", "create flagwake.yaml, the list of defenders, in this folder"),
        ("defenders", "add, list, show, remove or test a defender"),
        ("run", "run registered defenders on fresh incidents and write reports"),
        ("verify", "re-derive every number of a report.json from its stored commands"),
    )),
    ("Read results", (
        ("view", "open the newest report in the report viewer"),
        ("replay", "print one incident of a report as a plain transcript"),
        ("baselines", "run the shipped reference programs and print a table"),
    )),
    ("Your own company", (
        ("world", "write, check or show a company file"),
    )),
    ("Other ways in", (
        ("check", "a one-off run of a command or endpoint, with no registry"),
        ("doctor", "a one-minute smoke test of a model endpoint or a program"),
        ("tools", "serve the company as tools (MCP and REST) to a product with its own loop"),
        ("mcp", "the check as a stdio MCP server (score its logs with report)"),
        ("report", "score MCP transcripts into report.json and report.html"),
        ("serve", "serve the report viewer on 127.0.0.1"),
    )),
)  # fmt: skip


def overview() -> str:
    """What `flagwake --help` prints: the commands in the order a newcomer needs them."""
    lines = ["usage: flagwake <command> [options]", "", *textwrap.wrap(DESCRIPTION, 92), ""]
    for title, commands in GROUPS:
        lines.append(f"{title}:")
        lines += [f"  {name:<11}{text}" for name, text in commands]
        lines.append("")
    lines += [
        "flagwake <command> --help shows a command's options; flagwake --version the version.",
        "Docs: README.md, then docs/QUICKSTART.md.",
    ]
    return "\n".join(lines) + "\n"


class _TopParser(argparse.ArgumentParser):
    """The top-level parser: its help is the grouped overview, not one flat list."""

    def format_help(self) -> str:
        return overview()


REPORT_SCHEMA = "flagwake-rc-report-1"


def build_parser() -> argparse.ArgumentParser:
    """Return the top-level argument parser."""
    parser = _TopParser(prog="flagwake", description=DESCRIPTION)
    parser.add_argument("--version", action="version", version=f"flagwake {__version__}")
    sub = parser.add_subparsers(
        dest="command", metavar="<command>", parser_class=argparse.ArgumentParser
    )

    from cyberarena.rc.cli import add_subparsers as _rc_add

    _rc_add(sub)
    from cyberarena.rc.world_cli import add_subparsers as _world_add

    _world_add(sub)
    from cyberarena.rc.tools_cli import add_subparsers as _tools_add

    _tools_add(sub)

    v = sub.add_parser(
        "verify", help="re-derive every number of a report.json from its transcripts"
    )
    v.add_argument("files", nargs="+")
    v.add_argument("--world", help="the company file a custom-world report was made from")

    d = sub.add_parser(
        "demo",
        help="see it work in a few seconds: two example defenders, a report, verify, and an "
        "edited copy that verify catches",
    )
    d.add_argument("--out", default="flagwake-demo", help="folder to write (default flagwake-demo)")
    d.add_argument("--open", action="store_true", help="open the HTML report in your browser")

    rp = sub.add_parser("report", help="score MCP transcripts into report.json and report.html")
    rp.add_argument(
        "--mcp-log",
        required=True,
        help="the folder of transcripts written by flagwake mcp --log-dir",
    )
    rp.add_argument("--out", help="the folder to write (default mcp-report)")
    rp.add_argument("--world", help="the company file the transcripts ran in, when it was a file")
    return parser


def _verify_one(path: str, world: str | None = None) -> tuple[list[str], str | None]:
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return [f"cannot read: {exc}"], None
    from cyberarena.rc.verify import made_by, verify

    return verify(doc, world), made_by(doc)


def _cmd_verify(args: argparse.Namespace) -> int:
    failed = 0
    for path in args.files:
        errors, note = _verify_one(path, getattr(args, "world", None))
        if errors:
            failed += 1
            print(f"FAIL {path}: " + "; ".join(errors))
        else:
            print(f"OK   {path}" + (f" ({note})" if note else ""))
    return 1 if failed else 0


def _rc(handler_name: str):
    def run(args: argparse.Namespace) -> int:
        from cyberarena.rc import cli as rc_cli

        return getattr(rc_cli, handler_name)(args)

    return run


def _registry(handler_name: str):
    def run(args: argparse.Namespace) -> int:
        from cyberarena.rc import registry_cli

        return getattr(registry_cli, handler_name)(args)

    return run


def _cmd_demo(args: argparse.Namespace) -> int:
    from cyberarena.rc.demo import cmd_demo

    return cmd_demo(args)


def _cmd_tools(args: argparse.Namespace) -> int:
    from cyberarena.rc import tools_cli

    return tools_cli.cmd_tools(args)


def _cmd_world(args: argparse.Namespace) -> int:
    from cyberarena.rc import world_cli

    return world_cli.cmd_world(args)


COMMANDS = {
    "verify": _cmd_verify,
    "demo": _cmd_demo,
    "report": _rc("cmd_report_mcp"),
    "check": _rc("cmd_check"),
    "doctor": _rc("cmd_doctor"),
    "replay": _rc("cmd_replay"),
    "baselines": _rc("cmd_baselines"),
    "mcp": _rc("cmd_mcp"),
    "serve": _rc("cmd_serve"),
    "init": _registry("cmd_init"),
    "defenders": _registry("cmd_defenders"),
    "run": _registry("cmd_run"),
    "view": _registry("cmd_view"),
    "ui": _registry("cmd_ui"),
    "world": _cmd_world,
    "tools": _cmd_tools,
}


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in COMMANDS:
        return COMMANDS[args.command](args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
