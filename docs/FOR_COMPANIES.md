# For companies: testing a defender on your own topology

## What leaves the machine

Nothing. The check, the simulated company, the scripted intruder, the scoring and the reports run
locally; the servers it starts (the local page, the report viewer, the tools for mode B) bind to
127.0.0.1. The only network traffic is what your defender itself does (for example, calls to the
model endpoint you configured). Reports are files you choose to share or not. The company file
holds only what you write in it; use invented names and documentation addresses if you describe a
real organisation (the format requires the latter).

## Describe your topology

```bash
flagwake world init                     # a commented template
flagwake world validate company.yaml    # plain-language problems
flagwake world show company.yaml        # what it contains and which families can run
```

docs/COMPANY_FORMAT.md lists every field: zones, hosts with criticality and the team in charge, people
and roles, service and admin accounts, partner and supplier links, hosted services, business flows
(value per minute, which hosts carry them, whether they can be paused), the approval policy, log
sources per zone (with delays and gaps) and the business calendar. Families that need something
your company does not have are skipped and listed in the report; nothing is invented.

Costs: by default the shipped weights apply and are recorded in the report. A `cost:` section sets
your own weights and flow values; every output then says "custom costs, not comparable with the
default pack". Compare such results only with runs on the same file.

## A fair evaluation of a vendor's defender

1. **Conformance first.** `flagwake defenders test <name>`: the protocol suite (mode A) or the
   connect-and-test check (mode B). A defender that fails it is not measured.
2. **Test it as it is deployed.** Prefer mode B (docs/INTEGRATION_MODES.md): the vendor's defender
   uses its own loop and instructions; the harness sends none. Record the vendor's declared settings
   (model label, version, temperature, scaffold) in the registry entry's `meta`.
3. **Same incidents for everyone, unseen by all.** Run the first defender on the default fresh
   pack, then give every other one the same `--run-key` (from the first report's `run_key`), the
   same `--seeds` and the same company file. Keep the key to yourself until every run is done: a
   vendor who knows it knows the incidents. Practice seeds are public; never quote them.
4. **Three repeats** for anything stochastic: `--repeat 3`, and read the run-to-run spread.
5. **Keep everything.** report.json, the company file and the registry entry; anyone can re-run
   `flagwake verify report.json --world company.yaml` and get the same numbers.

## Reading the result

- The damage index (0 = the oracle's list, 100 = doing nothing) with its interval and n, next to the
  careful and rule-bot programs on the same incidents, with a paired verdict ("better", "worse",
  "too few incidents to conclude"). The profile says how many incidents a firm answer would need.
- The behaviour scores: containment, actions on clean targets, evidence before action, approval
  compliance, planted orders obeyed, calibration, restraint on quiet incidents.
- The decision measures (company-file worlds): outflow prevented versus what pausing cost, the
  anchoring rate on revised assessments, unsupported claims in the report, notification coverage,
  appropriateness and leaks.
- The failure taxonomy and the three worst incidents (`flagwake replay` shows one command by command).
- docs/VALIDITY.md says what each number claims and what evidence supports it. In short: internally
  checked, not yet compared with expert judgement or real incidents.

## In a pipeline

```bash
flagwake check --agent "python my_agent.py" --world company.yaml --fail-under 60
```

exits non-zero when the damage index is above 60 (and when the report does not verify). A template
for a CI job is in examples/ci/rc-check.yml.

## Limits

The intruder is a fixed script with one adaptive rule; the incidents are decision-level and
abstract (no exploits, no real forensics); the weights are design choices; a good score here says
nothing certain about real incidents. docs/LIMITATIONS.md has the full list.
