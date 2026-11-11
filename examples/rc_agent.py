#!/usr/bin/env python3
"""A ~20-line example responder for the Flagwake Responder Check (JSON-lines protocol).

Run it against the check with:

    flagwake check --agent "python examples/rc_agent.py" --pack practice --seeds 3

It reads one JSON object per line from stdin and writes one back. On the first message it looks,
then reads the logs of the first host named in an alert, isolates that host if the logs carry an
indicator, and closes. It is deliberately simple; see docs/AGENTS.md to write a better one.
"""

import json
import re
import sys

IOC = re.compile(r"unknown program|unsigned program|sign-in tokens|bulk read|unexpected process")


def main() -> None:
    lead = None
    step = "look"
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        if msg.get("type") == "end":
            break
        text = msg.get("text", "")
        if step == "look":
            step = "find-lead"
            reply("look")
        elif step == "find-lead":
            m = re.search(
                r"\b(web-01|vpn-01|mail-01|ws-[a-z-]+\d+|hr-portal|files-01|print-01|"
                r"dc-01|db-0\d|backup-01|monitor-01)\b",
                text,
            )
            lead = m.group(1) if m else None
            if lead:
                step = "read"
                reply(f"logs {lead}")
            else:
                step = "done"
                reply('report {"compromised": [], "summary": "nothing stood out"}')
        elif step == "read":
            step = "done"
            if lead and IOC.search(text):
                reply(f"isolate {lead}")
            else:
                reply('report {"compromised": [], "summary": "no indicator found"}')
        else:
            comp = f'["{lead}"]' if lead else "[]"
            reply('report {"compromised": ' + comp + ', "summary": "contained the lead"}')


def reply(cmd: str) -> None:
    sys.stdout.write(json.dumps({"cmd": cmd}) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
