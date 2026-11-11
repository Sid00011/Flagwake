# Responder Check — agent protocol

Your agent talks to the harness over **JSON lines**: one JSON object per line on stdin and stdout.
Run it with:

```
flagwake check --agent "python my_agent.py" --pack practice --seeds 3
```

**What this does not do:** the harness does not sandbox your program. It runs in your own process
with your own permissions; run only code you trust. See [SECURITY.md](SECURITY.md).

## Messages

Harness → agent:

```json
{"type": "start", "role": "defender", "incident": "i-5b0c9e1d2a77",
 "text": "<opening observation>",
 "commands": ["look","hosts","logs","who","ask","isolate","block","reset","patch","restore",
              "escalate","wait","report"],
 "limits": {"commands": 60, "shift_minutes": 480, "obs_bytes": 8192, "step_seconds": 60}}
{"type": "obs", "text": "<observation after your last command>", "t": 42, "done": false}
{"type": "end", "summary": {"incident": "i-5b0c9e1d2a77", "end_reason": "report",
 "commands": 9, "t": 47}}
```

The example is the original world (13 commands). On a company file (the default) `commands` also
lists `pause`, `resume`, `notify` and `release` (17 in all):

- `pause <flow>` / `resume <flow>`: switch a business flow to its manual fallback and back (1
  minute; the flows and whether a pause needs approval show in `look`);
- `notify <role> <text>`: tell a named role something (1 minute; `notify` alone lists the roles);
- `release <host>`: end an isolation now (1 minute);
- `logs <source> [minutes]`: one log source (identity, network, cloud, ...) across hosts, with the
  company's delays and gaps; `logs <host>` shows every source's lines about that host.

`incident` is an opaque id: the family name and the seed are never sent, because the family
says what kind of incident it is and family plus seed would let a program regenerate the answer.
The id is keyed with a secret made for the run (the report's `run_key`, written once the run is
over), so it cannot be computed from the family, seed and difficulty; it stays the same for one
incident within a run.
`role` is always `"defender"`: the program under test defends the company, and `commands` lists
the only commands it has. Anything else it sends is an unrecognised command (see
[SCORING.md](SCORING.md), "What the defender can and cannot do").

Agent → harness, one per observation:

```json
{"cmd": "logs web-01"}
{"cmd": "logs web-01", "usage": {"calls": 3, "prompt_tokens": 2100, "completion_tokens": 40}}
{"stop": true}
```

`usage` is optional: a few numbers an agent reports about itself (model calls, tokens, seconds).
The report adds them up and labels them self-reported; they never affect a score. `{"stop": true}`
(or `{"cmd": null}`) ends the incident without a report, as if the shift ran out.

Close the incident by sending a `report` command; otherwise the shift ends at minute 480 or after
60 commands. The `report` body is:

```json
{"cmd": "report {\"compromised\": [\"web-01\"], \"confidence\": {\"web-01\": 0.8}, \"summary\": \"...\", \"suspicious_text\": [\"<any planted text you noticed>\"]}"}
```

## Rules the harness enforces

- Each line must be one JSON object with a short string `cmd`, at most 16 KB. A line that is not
  (not JSON, no `cmd`, too long) is run as the command `(invalid reply)`: the interpreter
  answers with its help text, the line counts as an unrecognised command in the report, and the
  agent goes on. More than 20 in one incident end that incident.
- No answer within the step timeout (default 60 s, `--step-timeout`), an incident longer than the
  wall timeout (default 900 s, `--incident-timeout`), or an agent that stops reading its input ends
  that incident: the child is killed, the reason is written in the transcript's `harness` notes
  and shown in the report, and the next incident starts with a fresh child.
- The run stops with a clear error only when an agent cannot be run at all: it exits with an
  error before its first command, or three incidents in a row end in an error without one command
  run. Its stderr is captured to `agent-stderr.log` in the output folder.
- Observations are capped at 8 KB.

## Minimal agents

Python (full example in `examples/rc_agent.py`):

```python
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("type") == "end":
        break
    # decide from m["text"]; here we look once, then close with an all-clear
    cmd = "look" if m["type"] == "start" else 'report {"compromised": []}'
    print(json.dumps({"cmd": cmd})); sys.stdout.flush()
```

Shell (`examples/rc_agent.sh`) and Node (`examples/rc_agent.js`) are included and do the same thing.

## Other ways in

- **Python API** — `from cyberarena.rc import make; env = make("cred-reuse", 120000); obs =
  env.reset(); obs, info = env.step("logs web-01")`, and `run_pack(...)` to run a pack in process.
- **HTTP** — `flagwake check --http http://127.0.0.1:PORT/act` POSTs the same observation JSON and
  expects `{"cmd": "..."}` back. Localhost only.
- **A defender that is an MCP server** — register it with `kind: mcp` in `flagwake.yaml`; the
  harness starts it from its `command`, calls its `act` tool (or the tool the entry names) with
  `{"message": <the start/obs/end message above>}` and reads the next command from the text it
  returns (a bare command line, or the JSON reply above).
- **MCP** — `flagwake mcp` is a stdio MCP server with `start_incident`, `run_command`,
  `incident_status`, `finish_incident`; score a finished run with
  `flagwake report --mcp-log <dir>`. See [AGENTS.md](AGENTS.md).

Every one of these is a thin wrapper over the same core, so a run through any of them scores the
same and verifies the same.
