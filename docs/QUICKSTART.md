# Responder Check — 10-minute quickstart

You need git and Python 3.11+. The reference programs need no other package and no API key.
Work in a copy of this repository (`git clone https://github.com/Sid00011/Flagwake`, then its
folder): step 3 uses the example program in `examples/`. For the demo, the reference programs and
the local page alone, `pip install flagwake` is enough.

```bash
python -m venv .venv
. .venv/bin/activate                     # Windows: .venv\Scripts\activate
pip install .

# 0) See it work in two seconds: two example defenders, a report, verify, a caught edit
flagwake demo

# 1) See the shipped reference programs, so you know what the numbers mean
flagwake baselines --pack practice --seeds 10

# 2) Run the careful scripted analyst and open its report
flagwake check --agent baseline:careful --pack practice --seeds 5 --out out
#   -> out/report.json and out/report.html (local files; nothing is sent anywhere)

# 3) Re-derive every number from the transcripts
flagwake verify out/report.json

# 4) Register YOUR defender (any program, service or endpoint), check it, run it, look at it
flagwake init
flagwake defenders add --name mine --kind command --command "python examples/rc_agent.py"
flagwake defenders test mine
flagwake run --defender mine --pack practice --seeds 5
flagwake view
#   fresh incidents (the default pack) are the ones to quote: flagwake run --defender mine

```

## Read the report in a minute

The first screen says, in one line, the business-damage index (0 = as good as the oracle, 100 = as
bad as doing nothing), how many compromised hosts were contained, the injection-violation rate, the
approval compliance, the restraint on quiet incidents, and your three worst incidents as short
failure traces, each with the `flagwake replay` command that prints its full transcript. A
"what this does not measure" box is always there.

## What next

- Run a real model or your own agent, step by step: [TRY_YOUR_AGENT.md](TRY_YOUR_AGENT.md).
- Write a better agent: [PROTOCOL.md](PROTOCOL.md) and [AGENTS.md](AGENTS.md).
- Understand the numbers: [SCORING.md](SCORING.md); the incidents: [SCENARIOS.md](SCENARIOS.md).
- The method and the reference programs' numbers: [TECHNICAL_NOTE.md](TECHNICAL_NOTE.md).
- What it does not do: [LIMITATIONS.md](LIMITATIONS.md); how it is kept safe: [SECURITY.md](SECURITY.md).

**What this does not do:** it does not measure exploit skill or real forensics, and it is no
substitute for testing your agent in your own environment. The company, hosts and people are
fictional and abstract; the attacker follows a fixed script.
