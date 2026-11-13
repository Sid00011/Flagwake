"""Run each defender process as another, unprivileged user, so it cannot touch the harness.

A defender that runs as the harness's own user can read the harness's memory and environment (the
run key, a CI job's signing token), write the output folder, or leave a process behind that
rewrites report.json before it is signed. ``flagwake check --defender-user NAME`` starts every
defender process through ``sudo -n -u NAME`` in a folder that user owns, with only the variables
named by ``--defender-env``. It refuses a user that is root, is the harness's own user, can use
sudo or belongs to a group that amounts to root, and it stops every process of that user before
each incident and when the run ends. ``flagwake ci prepare`` creates such a user and gives it a
copy of the defender's folder. Linux and macOS only: it needs sudo, which a GitHub-hosted runner
grants the job's own user.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
# Groups whose members can act as root (docker, for one, starts privileged containers).
ROOT_GROUPS = frozenset({"root", "sudo", "wheel", "admin", "adm", "docker", "lxd", "libvirt"})
# The job's own signing and runtime identity: never handed to a defender, even when named.
NEVER = frozenset({"ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"})

Run = Callable[..., Any]


class SandboxError(ValueError):
    """The defender cannot be isolated as asked."""


def env_names(text: str) -> tuple[str, ...]:
    """The variable names in a comma-separated list, each checked."""
    names = tuple(n.strip() for n in text.split(",") if n.strip())
    for n in names:
        if not ENV_NAME.match(n):
            raise SandboxError(f"not a variable name: {n!r}")
        if n in NEVER or n.startswith("ACTIONS_"):
            raise SandboxError(f"{n} is never given to a defender")
    return names


def wrap(
    argv: Sequence[str], user: str, cwd: str, keep: Sequence[str], path: str, home: str
) -> list[str]:
    """The command line that starts ``argv`` as ``user`` in ``cwd``.

    sudo resets the environment; ``keep`` names the variables passed through, and PATH is set
    explicitly (sudo would otherwise replace it) with the user's own ~/.local/bin first. Values of
    passed variables travel in the environment, never on the command line, which any user can
    read.
    """
    head = ["sudo", "-n", "-H", "-u", user]
    if keep:
        head.append("--preserve-env=" + ",".join(keep))
    script = 'cd "$0" && exec "$@"'
    return [*head, "--", "/usr/bin/env", f"PATH={home}/.local/bin:{path}", "/bin/sh", "-c",
            script, cwd, *argv]  # fmt: skip


def check_user(user: str, cwd: str, run: Run = subprocess.run) -> str:
    """Refuse a user that could reach the harness; return its home folder."""
    if sys.platform == "win32":
        raise SandboxError("--defender-user works on Linux and macOS only")
    if not NAME.match(user):
        raise SandboxError(f"not a user name: {user!r}")
    import grp
    import pwd

    try:
        rec = pwd.getpwnam(user)
    except KeyError as exc:
        raise SandboxError(f"there is no user named {user}") from exc
    if rec.pw_uid == 0 or rec.pw_uid == os.getuid():
        raise SandboxError(f"{user} is root or the harness's own user")
    groups = {g.gr_name for g in grp.getgrall() if user in g.gr_mem or g.gr_gid == rec.pw_gid}
    if groups & ROOT_GROUPS:
        raise SandboxError(
            f"{user} is in a group that amounts to root: {sorted(groups & ROOT_GROUPS)}"
        )
    folder = Path(cwd)
    if not folder.is_dir() or folder.stat().st_uid != rec.pw_uid:
        raise SandboxError(f"the defender's folder {cwd} must exist and belong to {user}")
    if shutil.which("sudo") is None:
        raise SandboxError("--defender-user needs sudo")
    if run(["sudo", "-n", "-u", user, "--", "/bin/true"], capture_output=True).returncode != 0:
        raise SandboxError(f"cannot start processes as {user} (sudo -n -u {user} failed)")
    inner = ["sudo", "-n", "-u", user, "--", "sudo", "-n", "/bin/true"]
    if run(inner, capture_output=True).returncode == 0:
        raise SandboxError(f"{user} can use sudo, so it could reach the harness")
    return rec.pw_dir


def stop_all(user: str, run: Run = subprocess.run) -> None:
    """Kill every process of ``user`` (nothing to do is fine)."""
    run(["sudo", "-n", "pkill", "-KILL", "-u", user], capture_output=True)


def isolated_factory(factory: Callable[[], Any], user: str, run: Run = subprocess.run):
    """A driver factory that first stops whatever the previous incident's defender left behind."""

    def make() -> Any:
        stop_all(user, run)
        return factory()

    return make


def _home(user: str, run: Run) -> str:
    """The user's home folder, as the system records it."""
    done = run(["getent", "passwd", user], capture_output=True, text=True)
    fields = str(getattr(done, "stdout", "") or "").strip().split(":")
    return fields[5] if len(fields) >= 7 and fields[5].startswith("/") else f"/home/{user}"


def prepare(
    user: str,
    source: str,
    dest: str,
    setup: str = "",
    exclude: Sequence[str] = (),
    run: Run = subprocess.run,
) -> None:
    """Create ``user`` (no sudo, no login shell), give it a copy of ``source`` at ``dest``, and run
    ``setup`` (for example ``pip install --user -r requirements.txt``) as that user in ``dest``.
    """
    if not NAME.match(user):
        raise SandboxError(f"not a user name: {user!r}")
    parts = Path(dest).as_posix().split("/")
    if not dest.startswith("/") or len([x for x in parts if x]) < 2 or ".." in parts:
        # It is removed and replaced below, as root: never a top-level or relative folder.
        raise SandboxError(
            f"the defender's folder must be an absolute path two levels deep or more, not {dest!r}"
        )

    def sudo(*args: str) -> None:
        if run(["sudo", "-n", *args], capture_output=True).returncode != 0:
            raise SandboxError(f"sudo {' '.join(args[:3])} ... failed")

    if run(["id", "-u", user], capture_output=True).returncode != 0:
        sudo("useradd", "--create-home", "--user-group", "--shell", "/usr/sbin/nologin", user)
    home = _home(user, run)
    skip = set(exclude) | {".git"}
    staging = tempfile.mkdtemp(prefix="flagwake-defender-")
    shutil.copytree(source, staging, dirs_exist_ok=True, symlinks=True,
                    ignore=lambda d, names: [n for n in names if n in skip])  # fmt: skip
    sudo("rm", "-rf", "--", dest)
    sudo("chown", "-R", f"{user}:{user}", "--", staging)  # never follows a link
    sudo("mv", "--", staging, dest)
    sudo("chmod", "700", "--", home)
    if setup:
        path = os.environ.get("PATH", "/usr/bin:/bin")
        argv = wrap(["/bin/sh", "-c", setup], user, dest, (), path, home)
        done = run(argv)
        if done.returncode != 0:
            raise SandboxError(f"the setup command failed as {user} (exit {done.returncode})")
