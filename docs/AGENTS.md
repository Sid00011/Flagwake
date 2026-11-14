# Responder Check — connecting your agent

Five ways to connect, all thin wrappers over one core, so a run through any of them scores and
verifies the same. The main path is the registry (`flagwake init`, `defenders add`, `run`: see the
README); `flagwake check`, used below, is the one-off form that needs no registry. The [protocol](PROTOCOL.md) and the [scoring](SCORING.md) are defined elsewhere.

**What this does not do:** it runs no model of its own and sends nothing to the internet. The HTTP
adapter and `flagwake serve` talk to localhost only; the MCP server speaks over stdin/stdout.

Each of these can be registered in `flagwake.yaml` and run with `flagwake run`
([TRY_YOUR_AGENT.md](TRY_YOUR_AGENT.md), "Any defender, any machine"); nothing ties the check to a
particular model, framework or operating system.

## 1. A subprocess (recommended)

```
flagwake check --agent "python my_agent.py" --pack practice --seeds 3
```

Your program speaks JSON lines ([PROTOCOL.md](PROTOCOL.md)). Examples in Python, Node and shell are
in `examples/rc_agent.*`.

## 2. The Python API

```python
from cyberarena.rc import make
env = make("cred-reuse", 120000, "standard")
obs = env.reset()
obs, info = env.step("logs web-01")
```

Run a whole pack in process with `cyberarena.rc.runner.run_pack(driver_factory, specs)`, where a
driver is `callable(shift) -> command | None`, or wrap a text agent with `text_driver`.

## 3. HTTP (localhost)

```
flagwake check --http http://127.0.0.1:8000/act --pack practice
```

The harness POSTs the observation JSON and expects `{"cmd": "..."}`. It refuses any host other than
`127.0.0.1`/`localhost`.

## 4. MCP (stdio)

```
flagwake mcp --log-dir my-run
```

Tools: `start_incident(family, seed, difficulty)`, `run_command(command)`, `incident_status()`,
`finish_incident()`. The server runs in the default company; `--world` names another shipped
company, `legacy` or your company file, and `start_incident` offers that company's families. A
finished incident writes a transcript that records its company; score the folder with:

```
flagwake report --mcp-log my-run --out my-run-report
```

For transcripts made in a company file, give the same file again: `--world company.yaml`.

## 5. A language-model agent (optional)

`examples/reference_llm_agent.py` speaks the protocol to any chat-completions endpoint (the
de-facto `/v1/chat/completions` API). It needs no key to exist and the project never runs it for you.

```
export FLAGWAKE_LLM_BASE_URL=http://localhost:8080/v1   # a chat-completions base URL (ends in /v1)
export FLAGWAKE_LLM_MODEL=<the model your endpoint serves>
# export FLAGWAKE_LLM_KEY=<token>   # only if your endpoint needs one
flagwake check --agent "python examples/reference_llm_agent.py" --pack practice --seeds 3
```

The key is read from the environment and sent only in the request header to the base URL you chose;
it is never printed or written to disk. It keeps to the endpoint's rate limits by itself (`--rpm N`
sets a pace; see "Time, calls and rate limits" in [TRY_YOUR_AGENT.md](TRY_YOUR_AGENT.md)), and
speed never changes a score. Try the wiring with no model at all:

```
flagwake check --agent "python examples/reference_llm_agent.py --dry" --pack practice --seeds 1
```

### A free local model

A local model server that exposes a chat-completions endpoint works too; point
`FLAGWAKE_LLM_BASE_URL` at its `/v1` address and set `FLAGWAKE_LLM_MODEL` to a model it serves.
Step-by-step instructions, run times and call counts: [TRY_YOUR_AGENT.md](TRY_YOUR_AGENT.md).
**Caveat:**
small local models do poorly at restraint and injection resistance — a high injection-violation
rate and a lot of false containment are the usual result, and that is the point of measuring it.

## CI example

`examples/ci/` has a minimal GitHub Actions workflow that runs `flagwake check --pack practice
--fail-under <n>` so a change that makes your agent behave worse fails the build. Copy and adjust
it; it is an example, not a dependency.
