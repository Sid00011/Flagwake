# Try your agent in the Responder Check

One page, copy-paste steps. Everything runs on your machine; nothing is sent anywhere except the
model calls you configure yourself. Python 3.11 or newer.

```
pip install flagwake-<version>-py3-none-any.whl     # or: pip install .  (from the repository)
flagwake baselines --pack practice --seeds 2         # the 10 reference programs, a few seconds: what the numbers mean
```

**First, `flagwake doctor`** (about a minute). It runs three practice incidents and says, in
plain words, what is wrong and how to fix it: endpoint unreachable, key missing or refused, wrong
address, replies it cannot read, too slow.

```
flagwake doctor                                      # the model endpoint in FLAGWAKE_LLM_BASE_URL (below)
flagwake doctor --agent "python my_agent.py"         # an agent of your own
flagwake doctor --http http://127.0.0.1:8000/act     # an HTTP agent
```

## The page, without the command line

`Start-Flagwake.bat` (Windows) or `sh start-flagwake.sh` sets up a private environment the first
time and starts `flagwake ui`, a page on 127.0.0.1 that walks through adding a defender, the
connection check, a run and the result in plain words. It covers a model on this computer (found
automatically), a model online (its key stays in memory until the page stops; or name an
environment variable that holds it) and your own HTTP service. Defenders it saves are ordinary
`flagwake.yaml` entries, so the command line sees them too.

What still needs the command line: defenders that start a program on this computer (`command`
and `mcp`; the page allows them only when started with the option `--allow-commands`, and then asks
for a confirmation), extra request fields such as switching a model's reasoning off
(`extra_body`), caps other than the defaults, `--repeat` for the run-to-run spread, one family at
a time, `replay` and `verify`.

## Any defender, any machine: the registry

Register a defender once in `flagwake.yaml`, check that it behaves as a defender, then run it.
Nothing here depends on a particular model, vendor, framework or operating system; pick the kind
that matches how your defender runs:

| kind | what it is | the entry needs |
|---|---|---|
| `command` | any program, any language, that reads and writes [JSON lines](PROTOCOL.md) | `command` |
| `http` | any service on this machine that answers the same JSON over `POST` | `url` (localhost) |
| `mcp` | any stdio MCP server with a tool that returns the next command | `command`, optional `tool` |
| `model-endpoint` | any chat-completions endpoint, hosted or local, driven by the reference program | `base_url`, `model`, optional `key_env`, `extra_body` |
| `baseline` | a scripted program shipped with the check | `baseline` |

```
flagwake init
flagwake defenders add --name mine --kind command --command "python my_agent.py"
flagwake defenders test mine
flagwake run --defender mine --pack practice --seeds 1
flagwake view
```

Run without flags, `defenders add` asks one question per field. Every entry may also carry
`caps` (`max_commands`, `step_timeout`, `incident_timeout`, and for a model endpoint `max_calls`,
`token_budget`, `max_tokens`) and self-reported `meta` (`model_label`, `version`, `description`),
which the report records next to the run but never scores. A key never goes in the file: put it in
an environment variable and name the variable in `key_env`. Commands start in the folder that holds
`flagwake.yaml`, without a shell, as you, unsandboxed; a registry folder copied to another machine
runs there as long as that machine has the programs its commands name (the conformance test
says plainly when it does not). Unknown fields are rejected, so a typo cannot pass silently.

`defenders test` runs canary incidents and reports seven checks: it starts and
answers the protocol, sends only the commands it was given, stays within its caps, closes with a report the
checker can read, does not retry a refused approval forever, survives a garbled observation and
does not hang. `flagwake run` runs the suite first when the entry has no current result, and the
report header prints `conformance: passed 7/7` or the failing checks.

**Practice or fresh.** Practice seeds (120000 upward) appear in these docs. `flagwake run` draws
fresh incidents for each run unless you say `--pack practice`, every report says which pack it
used, and a warning appears when a defender's practice index is far better than its fresh one.

**Start with the practice pack.** `--pack practice --seeds 1` is 20 incidents (one per family) and
uses seeds that appear in the docs. The default run (fresh, 10 seeds per family) is 200
incidents drawn for that run; use it once the practice run works.

The sections below show each way in with `flagwake check`, the one-off command that needs no
registry; every one of them has a registry kind above.

## (a) A hosted model through a chat-completions endpoint

`examples/reference_llm_agent.py` (standard library only) speaks the protocol and asks the model for
one command per observation. Any endpoint that serves the widely used `/v1/chat/completions` API works.

```
export FLAGWAKE_LLM_BASE_URL=https://<provider>/v1      # Windows: set FLAGWAKE_LLM_BASE_URL=...
export FLAGWAKE_LLM_MODEL=<model id>
export FLAGWAKE_LLM_KEY=<your key>                      # read from the environment only
flagwake check --agent "python examples/reference_llm_agent.py" --pack practice --seeds 1 --out try1
```

The key goes only into the request header to the URL you set; it is never printed or written.
Limits per incident: `--max-calls 30`, `--token-budget 150000`, `--max-tokens 256`, `--timeout 40`
(each also as `FLAGWAKE_LLM_MAX_CALLS` etc.). Pass flags inside the quotes:
`--agent "python examples/reference_llm_agent.py --max-calls 15"`. Check the wiring with no model
at all: `--agent "python examples/reference_llm_agent.py --dry"`. The same agent runs from the
installed package as `python -m cyberarena.rc.model_agent`. In the registry this is
`kind: model-endpoint` with `base_url`, `model` and `key_env: FLAGWAKE_LLM_KEY` (or any variable
name you choose).

## (b) A free local model server

Any local server that exposes a chat-completions endpoint works the same way, with no key:

```
export FLAGWAKE_LLM_BASE_URL=http://localhost:<port>/v1   # see your server's docs for the port
export FLAGWAKE_LLM_MODEL=<a model the server has loaded>
flagwake check --agent "python examples/reference_llm_agent.py --timeout 55" --pack practice --seeds 1
```

Models that reason before they answer can spend the whole reply limit (`--max-tokens`, 256 by
default) on hidden reasoning and return an empty reply, which counts as an unrecognised command.
Switch that reasoning off for the run with `FLAGWAKE_LLM_EXTRA_BODY`, a JSON object merged into
every request body (your server's docs name the field); it cannot replace the model, the messages,
the temperature or the reply limit.

In the registry: `kind: model-endpoint`, `base_url: http://localhost:<port>/v1`, and the field
as `extra_body: {"<field>": <value>}`; `caps` with `step_timeout: 120` and `max_tokens` for slow or
verbose models.

Slow local models: keep `--timeout` under the harness's `--step-timeout` (60 s by default), or raise
both: `flagwake check --step-timeout 120 --agent "python examples/reference_llm_agent.py --timeout 110" --pack practice --seeds 1`.

## (c) Your own agent

- **JSON lines** (any language): read one JSON object per line on stdin, answer `{"cmd": "..."}`
  per line on stdout. [PROTOCOL.md](PROTOCOL.md) has the messages and a 10-line example;
  `examples/rc_agent.py`, `.js` and `.sh` are complete ones.
  `flagwake check --agent "python my_agent.py" --pack practice --seeds 1 --out mine`
- **MCP** (stdio): `flagwake mcp --log-dir my-run` serves four tools (`start_incident`,
  `run_command`, `incident_status`, `finish_incident`). Run your client over the practice seeds
  (120000 upward, any family from [SCENARIOS.md](SCENARIOS.md)), then score the folder:
  `flagwake report --mcp-log my-run --out my-run-report`.

- **A defender that is itself an MCP server:** register it as `kind: mcp`; the harness starts it,
  calls its `act` tool with each message and reads the next command from the reply.

## (d) The HTTP adapter

Serve `POST` on localhost; the harness sends the same JSON as the protocol (`start`, `obs`, `end`)
and expects `{"cmd": "..."}` back (`{"stop": true}` ends the incident):

```
flagwake check --http http://127.0.0.1:8000/act --pack practice --seeds 1 --out mine-http
```

Only `127.0.0.1` and `localhost` are accepted. In the registry: `kind: http`, `url: ...`.

## Time and calls

| run (default company, 20 families) | incidents | model calls (reference agent) | time |
|---|---|---|---|
| practice, `--seeds 1` | 20 | typically 5–17 an incident; at most 30 an incident (600) | 3–25 min |
| default (fresh, 10 seeds) | 200 | the same per incident; at most 6,000 | 30 min – 5 h |

Time is almost all model latency (1–5 s a call hosted, more for a large local model); the harness
itself runs the 200 incidents in about a second. The call cap per incident bounds the worst case.
A rehearsal with a scripted stand-in model made 191 calls for the 120 practice incidents in 40 s;
real models investigate more and make more calls. The report shows the calls and tokens your agent
reported (labelled self-reported).

## Read the report in one minute

Open `try1/report.html`. The first screen has everything:

1. **The big number** — business damage index: 0 = what the oracle achieved, 100 = what doing
   nothing cost, above 100 = worse than doing nothing, with its 95% interval and n. The profile
   sets it next to two reference programs on the same incidents and says "too few incidents to conclude"
   when the intervals overlap.
2. **Six panels** — hosts contained, actions on benign targets, planted orders obeyed, critical
   actions without approval, quiet incidents closed cleanly, unrecognised commands.
3. **Your three worst incidents** — one line each; tap one for the details and the command that
   replays it (`flagwake replay try1/report.json --incident family:seed`).
4. **The verify line** — green means every score was re-derived from the transcripts
   (self-reported fields such as tokens are labelled and not checked).
   Anyone can re-check: `flagwake verify try1/report.json`.
5. **The Defender profile** — three plain findings, failures by type with counts, which problems
   came from the harness (unreadable replies, failed calls, timeouts) and which from the defender.
6. **What it does not measure** — read it.

## Honest caveats

- Small models score poorly: many unrecognised commands, planted orders obeyed, quiet incidents spoiled
  by unneeded isolation. That is what the check is for, not a fault of the setup.
- The company, people, attacker and evidence are fictional and abstract. A score says how an agent
  behaved in *this* world; it says nothing about your network or real intrusions.
- It is not a certification, not a ranking and not a benchmark of models. The weights of the damage
  index are design choices ([SCORING.md](SCORING.md), [LIMITATIONS.md](LIMITATIONS.md)).
- Model replies vary between runs. Use `--repeat 3` to see the spread before reading much into one
  number.
- `flagwake check` runs your agent as a normal program with your permissions; it is not sandboxed.
