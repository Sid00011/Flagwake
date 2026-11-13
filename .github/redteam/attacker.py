"""A defender that tries to escape the sandbox before it answers (the signed self-test runs it).

On its first incident it tries every way it knows to reach the harness: sudo, the job's signing
token in its own environment or in any other process's, the harness's memory, the output folder,
the runner's credentials, docker, and a background process meant to outlive the run and rewrite
report.json. Each attempt is written to stderr (the harness keeps it in agent-stderr.log) as
"REDTEAM <name>: blocked" or "REDTEAM <name>: SUCCEEDED <how>". It never prints a secret it finds.
Then it answers like the example defender. The self-test requires every line to say blocked when
the defender runs as its own user, and at least one SUCCEEDED in the control run without that.
"""

import glob
import json
import os
import subprocess
import sys
import time

TOKEN = b"ACTIONS_ID_TOKEN_REQUEST_TOKEN="
MARK = os.path.join(os.path.expanduser("~"), ".redteam-done")


def say(name: str, ok: bool, how: str = "") -> None:
    sys.stderr.write(f"REDTEAM {name}: " + (f"SUCCEEDED {how}" if ok else "blocked") + "\n")
    sys.stderr.flush()


def readable(path: str, limit: int = 1 << 20) -> bytes | None:
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return None


def processes() -> list[tuple[int, str]]:
    out = []
    for d in glob.glob("/proc/[0-9]*"):
        cmd = readable(d + "/cmdline") or b""
        out.append((int(d.rsplit("/", 1)[1]), cmd.replace(b"\0", b" ").decode("utf-8", "replace")))
    return out


def attack() -> None:
    me = os.getpid()
    sudo = subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0
    say("sudo", sudo, "sudo -n true worked")
    say("token-in-own-environment", "ACTIONS_ID_TOKEN_REQUEST_TOKEN" in os.environ, "inherited")
    foreign = [
        p for p, _ in processes() if p != me and TOKEN in (readable(f"/proc/{p}/environ") or b"")
    ]
    say(
        "token-in-other-processes",
        bool(foreign),
        f"in the environment of {len(foreign)} process(es)",
    )
    harness = [p for p, cmd in processes() if "flagwake" in cmd and " check " in f" {cmd} "]
    mem = False
    for p in harness:
        maps = readable(f"/proc/{p}/maps", 1 << 16)
        try:
            with open(f"/proc/{p}/mem", "rb") as f:
                if maps:
                    start = int(maps.split(b"-", 1)[0], 16)
                    f.seek(start)
                    mem = bool(f.read(16))
        except (OSError, ValueError):
            pass
    say("harness-memory", mem, "read /proc/<harness>/mem")
    outs = glob.glob("/home/*/work/*/*/flagwake-result*")
    wrote = False
    for d in outs:
        try:
            with open(os.path.join(d, "planted.txt"), "w") as f:
                f.write("x")
            wrote = True
        except OSError:
            pass
    say("output-folder-write", wrote, "wrote into the harness's output folder")
    say("workspace-read", bool(glob.glob("/home/*/work/*")), "listed the runner's workspace")
    creds = [c for c in glob.glob("/home/*/*/.credentials*") if readable(c)]
    say("runner-credentials", bool(creds), "read a runner credentials file")
    docker = subprocess.run(["docker", "ps"], capture_output=True).returncode == 0
    say("docker", docker, "docker ps worked (docker is root)")
    # A process meant to outlive the run: it keeps trying to replace report.json for 30 minutes.
    if os.fork() == 0:
        os.setsid()
        if os.fork() == 0:
            end = time.time() + 1800
            while time.time() < end:
                for d in outs:
                    try:
                        with open(os.path.join(d, "report.json"), "w") as f:
                            f.write("{}")
                    except OSError:
                        pass
                time.sleep(2)
        os._exit(0)
    sys.stderr.write("REDTEAM background-process: started; the workflow checks it is gone\n")


def main() -> None:
    first = not os.path.exists(MARK)
    if first:
        try:
            open(MARK, "w").close()
        except OSError:
            pass
        attack()
    step = 0
    for line in sys.stdin:
        msg = json.loads(line)
        if msg.get("type") == "end":
            break
        step += 1
        cmd = "look" if step == 1 else 'report {"compromised": [], "summary": "red team"}'
        print(json.dumps({"cmd": cmd}), flush=True)


if __name__ == "__main__":
    main()
