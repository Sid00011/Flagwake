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

BASE = {
    "AGENT": "python bot.py",
    "OUT": "out",
    "DEFENDER_USER": "flagwake-defender",
    "DEFENDER_CWD": "/srv/flagwake-defender",
    "DEFENDER_SRC": "defender",
}


def test_only_named_secrets_and_public_values_reach_the_defender():
    env = {
        **BASE,
        "SECRETS_JSON": json.dumps({"MODEL_KEY": "k1", "OTHER": "k2", "github_token": "t"}),
        "DEFENDER_ENV": "MODEL_KEY, FLAGWAKE_LLM_KEY=model_key, TOKEN=GITHUB_TOKEN",
        "DEFENDER_VARS": "FLAGWAKE_LLM_MODEL=m\n\nBASE=https://x/v1",
    }
    out, names = launch.defender_env(env)
    assert names == ["MODEL_KEY", "FLAGWAKE_LLM_KEY", "TOKEN", "FLAGWAKE_LLM_MODEL", "BASE"]
    assert out["MODEL_KEY"] == out["FLAGWAKE_LLM_KEY"] == "k1"  # a secret under another name
    assert out["TOKEN"] == "t" and out["BASE"] == "https://x/v1"
    assert "SECRETS_JSON" not in out and "OTHER" not in out
    step_var, step_names = launch.defender_env(
        {**BASE, "DEFENDER_ENV": "MODEL_KEY", "MODEL_KEY": "v"}
    )
    assert step_var["MODEL_KEY"] == "v" and step_names == ["MODEL_KEY"]  # the action's way
    for bad in (
        {"DEFENDER_ENV": "MISSING"},
        {"DEFENDER_ENV": "A=B=C"},
        {"DEFENDER_ENV": "bad name=X"},
        {"DEFENDER_VARS": "no equals sign"},
    ):
        with pytest.raises(SystemExit):
            launch.defender_env({**BASE, **bad})


def test_a_caller_in_another_account_passes_its_key_as_the_model_key_secret():
    # Explicitly passed secrets: only the declared model-key (and GitHub's own token) arrive.
    env = {
        **BASE,
        "SECRETS_JSON": json.dumps({"github_token": "t"}),
        "MODEL_KEY_SECRET": "k1",
        "DEFENDER_ENV": "FLAGWAKE_LLM_KEY=model-key",
    }
    out, names = launch.defender_env(env)
    assert names == ["FLAGWAKE_LLM_KEY"] and out["FLAGWAKE_LLM_KEY"] == "k1"
    assert "MODEL_KEY_SECRET" not in out and "SECRETS_JSON" not in out
    # However GitHub spells the declared secret in the secrets context, it is the same one.
    spelled = launch.defender_env(
        {**BASE, "SECRETS_JSON": json.dumps({"model-key": "k1"}), "DEFENDER_ENV": "K=MODEL-KEY"}
    )[0]
    assert spelled["K"] == "k1"


def test_the_model_key_reaches_the_defender_only_when_named():
    env = {**BASE, "SECRETS_JSON": "{}", "MODEL_KEY_SECRET": "k1", "DEFENDER_ENV": ""}
    out, names = launch.defender_env(env)
    assert names == [] and "k1" not in out.values()
    with pytest.raises(SystemExit, match="a name for the defender"):
        launch.defender_env({**env, "DEFENDER_ENV": "model-key"})
    with pytest.raises(SystemExit, match="not a NAME"):
        launch.defender_env({**env, "DEFENDER_ENV": "K=other-key"})  # only the declared one


@pytest.mark.parametrize(
    "secrets",
    [
        {},  # secrets: inherit from another account passes nothing
        {"MY_KEY": ""},  # GitHub resolves a secret that was not passed to an empty string
    ],
)
def test_a_secret_that_did_not_arrive_stops_the_run_and_says_why(secrets):
    for entry, more in (("FLAGWAKE_LLM_KEY=MY_KEY", {}), ("K=model-key", {"MODEL_KEY_SECRET": ""})):
        env = {**BASE, "SECRETS_JSON": json.dumps(secrets), "DEFENDER_ENV": entry, **more}
        with pytest.raises(SystemExit, match="only within one organisation") as stop:
            launch.defender_env(env)
        assert "model-key secret" in str(stop.value)
    with pytest.raises(SystemExit, match="this step's env"):  # the action: the step's variables
        launch.defender_env({**BASE, "DEFENDER_ENV": "MY_KEY", "MY_KEY": ""})


def test_the_check_is_isolated_ticketed_and_recorded():
    env = {
        **BASE,
        "TICKET": "out/attempt-ticket.txt",
        "TICKET_BUNDLE": "b.json",
        "WORLD": "co.yaml",
    }
    argv = launch.argv_for(env, ["K"])
    assert argv[:4] == ["flagwake", "check", "--agent", "python bot.py"] and "--record-ci" in argv
    assert argv[argv.index("--defender-user") + 1] == "flagwake-defender"
    assert argv[argv.index("--defender-env") + 1] == "K"
    assert argv[argv.index("--attempt-ticket") + 1] == "out/attempt-ticket.txt"
    assert argv[argv.index("--attempt-bundle") + 1] == "b.json"
    assert argv[argv.index("--world") + 1].replace("\\", "/") == "defender/co.yaml"
    shipped = launch.argv_for({**BASE, "WORLD": "fenwick-brae"}, [])
    assert shipped[shipped.index("--world") + 1] == "fenwick-brae"
    open_run = launch.argv_for({**BASE, "ISOLATE": "false"}, ["K"])
    assert "--defender-user" not in open_run and "--defender-env" not in open_run


@pytest.mark.parametrize("world", ["/etc/hostname", "../flagwake-src/x.yaml", "a/../../b.yaml"])
def test_a_company_file_stays_inside_the_repository(world):
    with pytest.raises(SystemExit, match="inside your repository"):
        launch.argv_for({**BASE, "WORLD": world}, [])
