"""The defender sandbox: the command that starts it as another user, the checks that refuse a user
who could reach the harness, and the preparation of that user. sudo itself is exercised by the
signed self-test workflow on a GitHub-hosted runner (including a defender that attacks the
harness); here the calls to it are recorded instead."""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace

import pytest

from cyberarena.rc.sandbox import (
    SandboxError,
    check_user,
    env_names,
    isolated_factory,
    prepare,
    wrap,
)


class Calls:
    """Records each command; answers with the exit code the test sets for it."""

    def __init__(self, codes: dict[str, int] | None = None) -> None:
        self.seen: list[list[str]] = []
        self.codes = codes or {}

    def __call__(self, argv, **_kw):
        self.seen.append(list(argv))
        return SimpleNamespace(returncode=self.codes.get(" ".join(argv[:3]), 0))


def test_only_named_variables_reach_the_defender_and_never_the_signing_tokens():
    assert env_names("MODEL_KEY, FLAGWAKE_LLM_MODEL,") == ("MODEL_KEY", "FLAGWAKE_LLM_MODEL")
    for bad in ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_RUNTIME_TOKEN", "A-B", "1X"):
        with pytest.raises(SandboxError):
            env_names(bad)


def test_the_wrapped_command_runs_as_the_user_in_its_folder_with_no_secret_on_the_line():
    argv = wrap(["python", "agent.py"], "flagwake-defender", "/srv/d/work", ("MODEL_KEY",),
                "/opt/py/bin:/usr/bin", "/srv/home-d")  # fmt: skip
    assert argv[:5] == ["sudo", "-n", "-H", "-u", "flagwake-defender"]
    assert "--preserve-env=MODEL_KEY" in argv  # the value travels in the environment
    assert "PATH=/srv/home-d/.local/bin:/opt/py/bin:/usr/bin" in argv
    assert argv[-3:] == ["/srv/d/work", "python", "agent.py"]
    assert not any("=" in a and a.split("=")[0] == "MODEL_KEY" for a in argv)


def test_each_incident_starts_after_the_previous_defender_is_stopped():
    calls = Calls()
    made = []
    make = isolated_factory(lambda: made.append(1) or "driver", "flagwake-defender", calls)
    assert make() == "driver" and make() == "driver"
    assert calls.seen == [["sudo", "-n", "pkill", "-KILL", "-u", "flagwake-defender"]] * 2


@pytest.mark.skipif(sys.platform == "win32", reason="users and sudo are a Linux/macOS matter")
def test_a_user_that_could_reach_the_harness_is_refused(tmp_path):
    import getpass

    with pytest.raises(SandboxError, match="root or the harness's own user"):
        check_user(getpass.getuser(), str(tmp_path), Calls())
    with pytest.raises(SandboxError, match="no user named"):
        check_user("no-such-user-here", str(tmp_path), Calls())
    with pytest.raises(SandboxError, match="not a user name"):
        check_user("Bad Name", str(tmp_path), Calls())


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows message")
def test_on_windows_the_sandbox_says_where_it_works(tmp_path):
    with pytest.raises(SandboxError, match="Linux and macOS only"):
        check_user("flagwake-defender", str(tmp_path), Calls())


def test_prepare_copies_the_folder_without_excluded_parts_and_hands_it_over(tmp_path):
    src = tmp_path / "repo"
    (src / "agents").mkdir(parents=True)
    (src / "agents" / "bot.py").write_text("print('hi')\n", encoding="utf-8")
    (src / ".git").mkdir()
    (src / "flagwake-result").mkdir()
    calls = Calls(codes={"id -u flagwake-defender": 1})  # the user does not exist yet
    prepare("flagwake-defender", str(src), "/srv/flagwake-defender", "",
            ["flagwake-result"], calls)  # fmt: skip
    commands = [" ".join(c[:4]) for c in calls.seen]
    assert any(c.startswith("sudo -n useradd --create-home") for c in commands)
    staging = next(c[3] for c in calls.seen if c[:3] == ["sudo", "-n", "mv"])
    copied = {p.name for p in os.scandir(staging)}
    assert copied == {"agents"}  # neither .git nor the output folder
    assert ["sudo", "-n", "chmod", "700", "/home/flagwake-defender"] in calls.seen


def test_a_failed_setup_stops_the_preparation(tmp_path):
    (tmp_path / "repo").mkdir()
    calls = Calls(codes={"sudo -n -H": 3})
    with pytest.raises(SandboxError, match="setup command failed"):
        prepare("flagwake-defender", str(tmp_path / "repo"), "/srv/x", "false", (), calls)


def test_check_refuses_isolation_it_cannot_give(tmp_path):
    from cyberarena.cli import main

    base = ["check", "--pack", "practice", "--seeds", "1", "--out", str(tmp_path / "o")]
    assert main([*base, "--agent", "baseline:careful", "--defender-user", "d"]) == 2
    assert main([*base, "--agent", "python x.py", "--defender-env", "A"]) == 2
