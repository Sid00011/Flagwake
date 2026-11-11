# Two ways to connect a defender

## Mode A: native protocol

The defender speaks the check's text commands, one per line, through a thin adapter: JSON lines on
stdin/stdout (`kind: command`), a local HTTP endpoint (`http`), an MCP server whose `act` tool
returns the next command (`mcp`), or a chat-completions endpoint driven by the shipped reference
scaffold (`model-endpoint`). It is simple and universal, but the defender has to be adapted to the
protocol. Reports say `integration: native protocol via <adapter>`. docs/PROTOCOL.md has the
messages.

## Mode B: the environment as tools (preferred for a real deployment)

The simulated company is served as a mock security platform, through interfaces a defender
already uses, so the defender needs no change: its own loop, its own instructions, its own tools.

- **MCP over HTTP**: JSON-RPC 2.0 posted to `/mcp` (`initialize`, `tools/list`, `tools/call`,
  `ping`); **MCP over stdio** with `flagwake tools serve --stdio`.
- **REST**: `POST /v1/tools/<name>` with the arguments as a JSON object; `GET /v1/alerts` to poll;
  `POST /v1/webhooks {"url": ...}` to receive `ticket.opened`, `alert`, `ticket.closed` and
  `run.complete` events at a URL on the same machine; the OpenAPI document at `/openapi.json`.
- Everything binds to 127.0.0.1 and needs the bearer token printed by `flagwake tools serve` (or
  passed to a defender the harness starts, in `FLAGWAKE_TOOLS_TOKEN`, with `FLAGWAKE_MCP_URL`,
  `FLAGWAKE_API_URL` and `FLAGWAKE_OPENAPI_URL`). Bodies are capped at 64 KB.
- **No instruction text from the harness.** The defender sees the open ticket (the company line
  and any handover note), the alerts, and the tool descriptions below, which are short, neutral and
  the same for every defender. Nothing tells it how to behave.
- The incidents of a pack are a queue of tickets: closing one opens the next. A ticket ends when
  the defender closes it, when the 480 simulated minutes end, or at 120 calls; a defender silent
  for the incident time limit has its ticket closed unfinished.

```bash
flagwake tools serve --world harlow-pine --pack practice --seeds 1    # prints the addresses and token
flagwake tools test --command "python my_defender.py"                 # connect-and-test
flagwake tools catalogue                                              # the tool descriptions (JSON)
```

In the defender registry, `mode: tools` on a `kind: command` entry starts the command with the
addresses in its environment; `flagwake defenders test` then runs the connect-and-test check (read
an alert, call a read tool, close a ticket, on two canary incidents) instead of the protocol suite.

### The mapping (one tool call, one world command)

Every call is translated to exactly one world command and recorded in the transcript as that
command, so scoring, `verify` and every measure are the same as in mode A. Simulated time passes
as for the command.

| tool | arguments | recorded as |
|---|---|---|
| `get_alerts` | none | `look` |
| `get_alert` | `alert_id` | `look` |
| `list_business_flows` | none | `look` |
| `list_hosts` | none | `hosts` |
| `get_host` | `host` | `hosts` |
| `search_logs` | `host` or `source`, optional `minutes`, `account` | `logs <host or source> [minutes]` (the account filter applies to the returned lines) |
| `get_user` | `account` | `who <account>` |
| `contact_user` | `account`, `topic` | `ask <account> <topic>` |
| `isolate_host` | `host`, optional `minutes` | `isolate <host> [minutes]` |
| `release_host` | `host` | `release <host>` |
| `disable_account` | `account` | `block <account>` |
| `reset_credentials` | `account` | `reset <account>` |
| `restore_host` | `host` | `restore <host>` |
| `patch_host` | `host` | `patch <host>` |
| `block_address` | `address` | `block <address>` |
| `request_approval` | `action` (a tool name), `target` | `escalate <verb> <target>` |
| `pause_flow` | `flow` | `pause <flow>` |
| `resume_flow` | `flow` | `resume <flow>` |
| `notify_role` | `role`, `message` | `notify <role> <message>` (spaces collapsed, 300 characters) |
| `wait` | `minutes` | `wait <minutes>` |
| `close_ticket` | `summary`, `compromised`, `confidence`, `suspicious_text` (all optional) | `report <the draft merged with these fields>` |
| `update_ticket` | the same fields | no world command: it edits the draft `close_ticket` submits (no simulated time) |

A call to an unknown tool, with arguments that do not match the schema, or that gives an address
to `disable_account` (or an account to `block_address`) gets a plain error and is recorded as a
command the world does not know: it counts as unrecognised and takes no time. A well-formed call
that names a host, account, flow or role that does not exist is recorded as the same world
command the native protocol would run (the world answers "no host named ..."), so both modes count
it the same way, and the defender gets a plain error.

Responses are JSON: `ok`, `result` (or `error`), the simulated `time`, `ticket_open`, and `events`
(new alerts, approvals answered, hosts reconnected). They are built from the world state right
after the command; no ground-truth field ever appears in one (a test checks every family).

## What a report discloses (fidelity)

Every report records, inside the hashed part: the integration mode; the adapter (a subprocess, an
HTTP endpoint, a built-in program, a model with the reference scaffold, a command in tools mode, an
external defender); whether the harness supplied any instruction text (mode B: none; a bare model
in mode A: the reference scaffold's, named); a hash of the fixed framing of the mode (the command
list and help, or the tool catalogue); and a hash over the hash of every observation or tool
response of every incident, which `verify` recomputes from the transcripts (for mode B by
re-running the recorded calls through the same mapping). Settings declared for the defender
(model label, version, temperature, scaffold name) are self-reported and outside the hash.
The result page says: "This result is for the defender and scaffold as configured, not for the
underlying model alone."

## Bare models

A model without a loop of its own is not a defender. Two reference scaffolds are shipped, each one
clearly named scaffold among others: the native-protocol program behind `kind: model-endpoint`
(results labelled "model + reference scaffold") and `examples/reference_tool_agent.py` for a model
with tool calls in mode B ("model + reference tool loop"). Companies testing their own defender use
mode B with their own loop and never touch either. The native-protocol scaffold shows its model the
fixed instruction, the opening observation, the last six exchanges in full and one line per earlier
command with the start of what it showed, so a model does not lose what it read early in a long
incident.

## Same decisions, same score

A test drives every shipped program through both modes on the same incidents (both shipped
companies and the original world) and requires identical commands and identical outcomes.
