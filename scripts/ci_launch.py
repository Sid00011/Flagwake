"""Start ``flagwake check`` for Flagwake's signing workflow and GitHub Action.

The defender sees only what it is given: the secrets named in DEFENDER_ENV and the public
NAME=value lines in DEFENDER_VARS. A DEFENDER_ENV entry is a name, or NAME=SECRET to hand a
secret to the defender under another name (FLAGWAKE_LLM_KEY=MY_PROVIDER_KEY). Secrets come from
SECRETS_JSON (the calling workflow's secrets, in the signing workflow) or else from the step's
own variables (in the action). In the signing workflow, MODEL_KEY_SECRET holds the workflow's own
model-key secret, which DEFENDER_ENV names as model-key (FLAGWAKE_LLM_KEY=model-key): a caller in
another account or organisation can pass that one, where secrets inherit passes nothing.
The defender runs as DEFENDER_USER (see cyberarena.rc.sandbox) unless ISOLATE is "false".
Everything else comes from the step's environment: AGENT, PACK, SEEDS, WORLD, OUT, TICKET,
TICKET_BUNDLE, DEFENDER_SRC, DEFENDER_CWD, STEP_TIMEOUT, INCIDENT_TIMEOUT.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
SHIPPED = {"harlow-pine", "fenwick-brae", "legacy", "hp-2"}
# The signing workflow's declared secret (on.workflow_call.secrets). No repository secret can be
# called this (GitHub secret names have no hyphen), so it never stands for an inherited one.
MODEL_KEY = "model-key"
INHERIT_HINT = (
    "secrets: inherit passes secrets only within one organisation or enterprise; from another "
    "account, pass the key as the model-key secret and name it in defender-env as NAME=model-key "
    "(docs/SIGNED_RESULTS.md)"
)


def defender_env(env: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """The environment for flagwake, and the names it may pass on to the defender."""
    out = {k: v for k, v in env.items() if k not in ("SECRETS_JSON", "MODEL_KEY_SECRET")}
    names: list[str] = []
    # GitHub spells secret names in upper case whatever the workflow wrote; look up likewise.
    secrets = {k.upper(): v for k, v in json.loads(env.get("SECRETS_JSON") or "{}").items()}
    if env.get("MODEL_KEY_SECRET"):
        secrets[MODEL_KEY.upper()] = env["MODEL_KEY_SECRET"]
    for entry in filter(None, (n.strip() for n in env.get("DEFENDER_ENV", "").split(","))):
        name, _, source = entry.partition("=")
        name, source = name.strip(), (source.strip() or name.strip())
        if name.lower() == MODEL_KEY:
            raise SystemExit(f"error: give {MODEL_KEY} a name for the defender, as in "
                             f"FLAGWAKE_LLM_KEY={MODEL_KEY}")  # fmt: skip
        if not NAME.match(name) or not (NAME.match(source) or source.lower() == MODEL_KEY):
            raise SystemExit(f"error: not a NAME or NAME=SECRET entry: {entry!r}")
        # A secret always has a value, so an empty one is a secret that was not passed.
        value = secrets.get(source.upper(), env.get(source))
        if not value:
            hint = INHERIT_HINT if "SECRETS_JSON" in env else "set it in this step's env"
            raise SystemExit(f"error: {source} did not arrive or is empty. {hint}")
        out[name], names = value, [*names, name]
    for line in env.get("DEFENDER_VARS", "").splitlines():
        if not line.strip():
            continue
        name, sep, value = line.partition("=")
        if not sep or not NAME.match(name.strip()):
            raise SystemExit(f"error: not a NAME=value line: {line!r}")
        out[name.strip()], names = value.strip(), [*names, name.strip()]
    return out, names


def argv_for(env: dict[str, str], names: list[str]) -> list[str]:
    argv = ["flagwake", "check", "--agent", env["AGENT"], "--pack", env.get("PACK") or "fresh",
            "--seeds", env.get("SEEDS") or "3", "--out", env["OUT"], "--record-ci",
            "--step-timeout", env.get("STEP_TIMEOUT") or "60",
            "--incident-timeout", env.get("INCIDENT_TIMEOUT") or "900"]  # fmt: skip
    if env.get("TICKET"):
        argv += ["--attempt-ticket", env["TICKET"], "--attempt-bundle", env["TICKET_BUNDLE"]]
    if env.get("ISOLATE", "true") != "false":
        argv += ["--defender-user", env["DEFENDER_USER"], "--defender-cwd", env["DEFENDER_CWD"]]
        if names:
            argv += ["--defender-env", ",".join(names)]
    world = env.get("WORLD", "")
    if world:
        if world not in SHIPPED and (
            os.path.isabs(world) or ".." in world.replace("\\", "/").split("/")
        ):
            raise SystemExit("error: world is a shipped company or a file inside your repository")
        in_repo = os.path.join(env.get("DEFENDER_SRC") or ".", world)
        argv += ["--world", world if world in SHIPPED else in_repo]
    return argv


def main() -> int:
    env, names = defender_env(dict(os.environ))
    return subprocess.call(argv_for(env, names), env=env)


if __name__ == "__main__":
    sys.exit(main())
