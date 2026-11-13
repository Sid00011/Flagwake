"""The launcher of the signing workflow: what reaches the defender, and the check it starts."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("ci_launch", ROOT / "scripts" / "ci_launch.py")
assert spec and spec.loader
launch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launch)

BASE = {"AGENT": "python bot.py", "OUT": "out", "DEFENDER_USER": "flagwake-defender",
        "DEFENDER_CWD": "/srv/flagwake-defender", "DEFENDER_SRC": "defender"}  # fmt: skip


def test_only_named_secrets_public_values_and_the_token_reach_the_defender():
    env = {**BASE, "SECRETS_JSON": json.dumps({"MODEL_KEY": "k1", "OTHER": "k2"}),
           "DEFENDER_ENV": "MODEL_KEY", "DEFENDER_VARS": "FLAGWAKE_LLM_MODEL=m\n\nBASE=https://x/v1",
           "TOKEN_AS": "FLAGWAKE_LLM_KEY", "JOB_TOKEN": "t"}  # fmt: skip
    out, names = launch.defender_env(env)
    assert names == ["MODEL_KEY", "FLAGWAKE_LLM_MODEL", "BASE", "FLAGWAKE_LLM_KEY"]
    assert out["MODEL_KEY"] == "k1" and out["BASE"] == "https://x/v1"
    assert "SECRETS_JSON" not in out and "JOB_TOKEN" not in out and "OTHER" not in out
    step_var, step_names = launch.defender_env(
        {**BASE, "DEFENDER_ENV": "MODEL_KEY", "MODEL_KEY": "v"}
    )
    assert step_var["MODEL_KEY"] == "v" and step_names == ["MODEL_KEY"]  # the action's way
    for bad in ({"DEFENDER_ENV": "MISSING"}, {"DEFENDER_VARS": "no equals sign"},
                {"TOKEN_AS": "bad name"}):  # fmt: skip
        with pytest.raises(SystemExit):
            launch.defender_env({**BASE, **bad})


def test_the_check_is_isolated_ticketed_and_recorded():
    argv = launch.argv_for({**BASE, "TICKET": "out/attempt-ticket.txt", "WORLD": "co.yaml"}, ["K"])
    assert argv[:4] == ["flagwake", "check", "--agent", "python bot.py"] and "--record-ci" in argv
    assert argv[argv.index("--defender-user") + 1] == "flagwake-defender"
    assert argv[argv.index("--defender-env") + 1] == "K"
    assert argv[argv.index("--attempt-ticket") + 1] == "out/attempt-ticket.txt"
    assert argv[argv.index("--world") + 1].replace("\\", "/") == "defender/co.yaml"
    shipped = launch.argv_for({**BASE, "WORLD": "fenwick-brae"}, [])
    assert shipped[shipped.index("--world") + 1] == "fenwick-brae"
    open_run = launch.argv_for({**BASE, "ISOLATE": "false"}, ["K"])
    assert "--defender-user" not in open_run and "--defender-env" not in open_run
