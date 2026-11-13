"""``flagwake ci``: the steps of Flagwake's signing workflow that are not the check itself.

``flagwake ci prepare`` creates the defender's own unprivileged user and gives it a copy of the
defender's folder (then runs an optional setup command as that user); ``flagwake ci attempt``
finds the next attempt number of a repository in Sigstore's public log and writes the ticket the
workflow signs before the check. docs/SIGNED_RESULTS.md describes the whole workflow.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

DEFAULT_USER = "flagwake-defender"


def add_subparsers(sub: argparse._SubParsersAction) -> None:
    c = sub.add_parser("ci", help="steps of Flagwake's signing workflow (GitHub Actions)")
    steps = c.add_subparsers(dest="ci_step", required=True)
    p = steps.add_parser(
        "prepare", help="create the defender's user and give it a copy of a folder"
    )
    p.add_argument(
        "--user", default=DEFAULT_USER, help=f"the user to create (default {DEFAULT_USER})"
    )
    p.add_argument("--source", default=".", help="the defender's folder (default: this one)")
    p.add_argument("--dest", required=True, help="where the user's copy goes (in its home)")
    p.add_argument("--setup", default="", help="a shell command to run as that user in its copy")
    p.add_argument("--exclude", action="append", default=[], help="a folder name not to copy")
    a = steps.add_parser("attempt", help="number this run's attempt and write its ticket")
    a.add_argument("--repo", required=True, help="the repository, org/repo")
    a.add_argument("--write", required=True, help="the ticket file to write")


def cmd_ci(args: argparse.Namespace) -> int:
    if args.ci_step == "prepare":
        from cyberarena.rc.sandbox import SandboxError, prepare

        try:
            prepare(args.user, args.source, args.dest, args.setup, args.exclude)
        except (SandboxError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"{args.user} owns {args.dest}; it cannot use sudo")
        return 0
    from cyberarena.rc.attempt import AttemptError, Log, next_number, ticket_text

    try:
        n = next_number(Log(), args.repo)
        Path(args.write).write_bytes(ticket_text(args.repo, n))
    except (AttemptError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"attempt {n} of {args.repo}: ticket written to {args.write}")
    return 0
