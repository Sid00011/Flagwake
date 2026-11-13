"""Start ``flagwake check`` for Flagwake's signing workflow and GitHub Action.

The defender sees only what it is given: the secrets named in DEFENDER_ENV (taken from
SECRETS_JSON, the calling workflow's secrets, or else from the step's own variables), the
public NAME=value lines in DEFENDER_VARS, and the job's own token under the name in TOKEN_AS
(for a model the job reaches with it, such as GitHub Models). The defender runs as
DEFENDER_USER (see cyberarena.rc.sandbox) unless ISOLATE is "false", which only the self-test's
control run uses. Everything else comes from the step's environment: AGENT, PACK, SEEDS,
WORLD, OUT, TICKET, DEFENDER_SRC, DEFENDER_CWD, STEP_TIMEOUT.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
SHIPPED = {"harlow-pine", "fenwick-brae", "legacy", "hp-2"}


def defender_env(env: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """The environment for flagwake, and the names it may pass on to the defender."""
    out = {k: v for k, v in env.items() if k not in ("SECRETS_JSON", "JOB_TOKEN")}
    names: list[str] = []
    # The signing workflow gets the caller's secrets as JSON; the action, as variables of its step.
    secrets = json.loads(env.get("SECRETS_JSON") or "{}")
    for name in filter(None, (n.strip() for n in env.get("DEFENDER_ENV", "").split(","))):
        value = secrets.get(name, env.get(name))
        if value is None:
            raise SystemExit(f"error: {name} is not available (pass it as a secret or variable)")
        out[name], names = value, [*names, name]
    for line in env.get("DEFENDER_VARS", "").splitlines():
        if not line.strip():
            continue
        name, sep, value = line.partition("=")
        if not sep or not NAME.match(name.strip()):
            raise SystemExit(f"error: not a NAME=value line: {line!r}")
        out[name.strip()], names = value.strip(), [*names, name.strip()]
    if env.get("TOKEN_AS"):
        if not NAME.match(env["TOKEN_AS"]):
            raise SystemExit("error: github-token-as is not a variable name")
        out[env["TOKEN_AS"]], names = env.get("JOB_TOKEN", ""), [*names, env["TOKEN_AS"]]
    return out, names


def argv_for(env: dict[str, str], names: list[str]) -> list[str]:
    argv = ["flagwake", "check", "--agent", env["AGENT"], "--pack", env.get("PACK") or "fresh",
            "--seeds", env.get("SEEDS") or "3", "--out", env["OUT"], "--record-ci",
            "--step-timeout", env.get("STEP_TIMEOUT") or "60"]  # fmt: skip
    if env.get("TICKET"):
        argv += ["--attempt-ticket", env["TICKET"]]
    if env.get("ISOLATE", "true") != "false":
        argv += ["--defender-user", env["DEFENDER_USER"], "--defender-cwd", env["DEFENDER_CWD"]]
        if names:
            argv += ["--defender-env", ",".join(names)]
    world = env.get("WORLD", "")
    if world:
        in_repo = os.path.join(env.get("DEFENDER_SRC") or ".", world)
        argv += ["--world", world if world in SHIPPED else in_repo]
    return argv


def main() -> int:
    env, names = defender_env(dict(os.environ))
    return subprocess.call(argv_for(env, names), env=env)


if __name__ == "__main__":
    sys.exit(main())
