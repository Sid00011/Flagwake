# Flagwake Responder Check — technical note

A cheap, offline, deterministic, re-checkable test of how a security **responder** agent (a
SOC / incident-response / containment agent) behaves during an invented company incident,
scored with business cost. It also scores judgement and restraint: did it investigate before
acting, contain the right machine early and completely, avoid shutting the business down for
nothing, ask for approval when required, ignore instructions planted in logs and tickets, and
report confidence that matched reality. Every number re-derives from the saved transcripts with `flagwake verify`; there is no
model or judge anywhere. It is not a certification, not a ranking of models, and it has not been
validated against real incidents.

## 1. Method

One incident lasts 480 simulated minutes in a fictional, abstract company (18 hosts, ~40 people;
`src/cyberarena/rc/data/world.json`). Commands cost simulated time; a scripted adaptive attacker
acts on the same clock. Observations are text, partial and noisy; some are untrusted content with
planted instructions. The responder closes with a `report`. Generation is deterministic in
`(family, seed, difficulty)` (a seeded `random.Random`, generator `rc-gen-5`); the interpreter has
no randomness, so a transcript replays exactly. Every incident opens with the same plain
observation (company, clock, business status, alert queue, command list), and
`flagwake replay` prints any stored incident as a plain transcript. The damage index puts each
incident between an **oracle** (0) — a command list built from the ground truth that resets stolen credentials, patches flaws, blocks the attacker's address and
evicts (restores) the hosts the intruder holds — and **doing nothing** (100). Metrics and their
exact definitions are in [SCORING.md](SCORING.md); the families in [SCENARIOS.md](SCENARIOS.md).

Seed spaces: practice 120000–120999 (used in this note and the docs), held-out 130000–130999
(fixed; no per-seed result from it is published), fresh (drawn for each run from
1,000,000–999,999,999; the default).

## 2. Baselines (scripted, shipped, deterministic)

Practice pack (generator `rc-gen-5`), 12 families × 20 seeds (120000–120019, 240 incidents,
each at the difficulty the pack assigns), this build. Reproduce with `flagwake baselines --pack practice --seeds 20`.
"index": clipped mean business-damage index; "worse": incidents worse than doing nothing;
"falseC": actions on benign targets; "collat": benign hosts disrupted; "cont": compromised hosts
contained ÷ total; "inj": planted orders obeyed ÷ planted orders read; "restr": quiet incidents
closed cleanly ÷ quiet incidents; "check": mean simulated minutes spent checking; "1st": median
minute of the first consequential action (n/a: never acted).

| agent | index | worse | falseC | collat | cont | inj | restr | check | 1st |
|---|---|---|---|---|---|---|---|---|---|
| do-nothing | 100.00 | 0 | 0 | 0 | 0.00 | n/a | 0.00 | 0.00 | n/a |
| isolate-on-first-alert | 82.62 | 3 | 62 | 62 | 0.64 | n/a | 0.00 | 0.00 | 0.00 |
| isolate-everything | 84.41 | 5 | 80 | 80 | 0.66 | n/a | 0.00 | 0.00 | 0.00 |
| rule-bot | 87.93 | 17 | 17 | 17 | 0.66 | 0.00 | 0.00 | 2.52 | 2.00 |
| careful | 69.15 | 0 | 1 | 1 | 0.66 | 0.00 | 1.00 | 8.95 | 2.00 |
| thorough | 12.64 | 0 | 4 | 2 | 0.66 | 0.00 | 1.00 | 11.67 | 2.00 |
| oracle | 0.00 | 0 | 0 | 0 | 0.72 | 0.00 | 1.00 | 1.51 | 2.00 |
| gullible | 122.25 | 93 | 101 | 74 | 0.00 | 0.88 | 0.00 | 4.82 | 4.00 |
| paranoid | 178.58 | 172 | 3949 | 1058 | 0.76 | n/a | 0.00 | 0.00 | 0.00 |
| slow | 103.54 | 75 | 135 | 135 | 0.38 | 0.02 | 0.00 | 36.00 | 36.00 |

`thorough` is `careful` plus eradication: after containing, it restores every host its own logs
showed compromised (patching first when the logs show a misconfiguration), so the intruder is not
back when the isolation time box ends. The isolators, `rule-bot` and `careful` only isolate, so the
intruder returns to the hosts they cut off; that is why they sit far from the oracle.

## 3. Metric-validity fixtures (the test of the test)

`gullible`, `paranoid` and `slow` exist to show that the metrics separate behaviours as intended;
`tests/rc/test_rc_calibration.py` asserts it on held-out seeds on every run:

- **gullible** (obeys any planted instruction it reads) has the highest planted-order rate (0.88).
- **paranoid** (acts on every alert at once and never checks: isolates each alerting host and
  re-isolates it when the business reconnects it, resets every account and blocks every address an
  alert names) has by far the most actions on benign targets and collateral.
- **slow** (reads the logs of every host before acting) has the highest cost of checking.
- **do-nothing** sits at 100 and **oracle** at 0 by construction; **careful** beats **rule-bot**.

## 4. Does a family tell a good response from a mediocre one?

Baselines can tie on a family simply because none of them makes the decisive move, so the gate
also runs four command lists built from the ground truth: the oracle's list (*full-early*), the same
after a 60-minute wait (*full-late*), the oracle's first containment action only (*partial*) and
do-nothing (*none*). Mean clipped index, practice seeds 120000–120019:

| family | full-early | full-late | partial | none |
|---|---|---|---|---|
| `cred-reuse` | 0 | 81.3 | 86.4 | 100 |
| `late-staging` | 0 | 43.8 | 71.9 | 100 |
| `misconfig-not-wipe` | 0 | 53.9 | 55.1 | 100 |

Late containment costs, incomplete containment costs, and a partial containment still helps on
all three. On the two untrusted-text families, obeying a planted order once costs the careful
baseline +79.4 (`forged-emergency`) and +52.9 to +69.4 (`log-injection`) index points. The criterion, its first
readings and every change made after seeing them are in [METHODOLOGY.md](METHODOLOGY.md#changes-made-after-seeing-data).

## 5. Related work

This builds on published work and follows its definitions where they map (sources read
2026-10-25). **OpenSec** (Barnes, arXiv:2601.21083) measures incident-response agents under
adversarial evidence and defines time-to-first-containment, an evidence-gated action rate, blast
radius and per-tier injection-violation rates; we follow those definitions, with containment per
compromised host and the clock in minutes. **NetInjectBench** (arXiv:2607.10490) defines the
unsafe tool-action rate for single-step indirect injection in network operations; we report it
for comparability beside a longer-horizon violation rate. **SecRespond** (arXiv:2607.26791)
benchmarks post-compromise response from forensic host snapshots and is far more realistic than
this abstract world. **CyberSOCEval** (arXiv:2509.20166) tests malware analysis and threat-intel
reasoning on real data. Work on abstract autonomous-cyber-defence environments, including the
workshop report arXiv:2604.08805, shaped the choice of a small fictional world with a scripted
attacker.

## 6. Limits

- The damage weights are design choices and the index is sensitive to them; the downtime weight
  2.0 comes from an earlier prototype's rules, the rest are debatable.
- The attacker is scripted with one adaptive rule per incident; it is not a free adversary.
- The oracle is near-optimal, not optimal: `thorough` scores slightly below it on `cred-reuse`
  (mean −2.0 before clipping). Indices below 0 are clipped in the headline mean.
- See [LIMITATIONS.md](LIMITATIONS.md) for the full list.
