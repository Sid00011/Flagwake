# Contributing

Thank you for looking. The project is small and run by one maintainer, so the rules below keep it
honest and reproducible.

## Set up and test

```bash
git clone https://github.com/Sid00011/Flagwake.git
cd Flagwake
python -m venv .venv
```

Activate it (`source .venv/bin/activate`; Windows: `.venv\Scripts\Activate.ps1`), then:

```bash
pip install -e ".[dev]" -c constraints.txt
python -m pytest
```

- `ruff check .`, `ruff format --check .` and `mypy` must pass (no function above complexity
  20, no type errors); `python scripts/dev.py all` runs lint, types and tests together.
- Browser tests: `pip install -e ".[dev,e2e]" -c constraints.txt` and
  `python -m playwright install chromium`; `python -m pytest` then runs them too.
- The golden determinism check must not move unless the generator version or the rules hash
  moves and the change is recorded in docs/METHODOLOGY.md: `python scripts/golden_check.py`.

## Names

The command and the distribution are `flagwake`; the Python package keeps its historical name
`cyberarena`, and the labels that seed the generator's random streams (`cyberarena/rc/1/...`)
never change, because every incident depends on them.

## The project rules

1. **Free to run.** The project uses only free, open-source or free-tier services; a change must
   not need a payment, a card or a paid trial.
2. **Fictional only.** No code that scans, probes or attacks a real system; no real exploit code,
   payloads, malware or credentials.
3. **Tests with every change.** Every rule of the interpreter and the scoring has a test. A failing test is fixed at
   its cause, not by loosening the test.
4. **Determinism.** The same `(generator version, family, seed, difficulty, commands)` gives a
   byte-identical result on every machine: no wall clock, no unseeded randomness, no unordered iteration that affects a
   result.
5. **Versioned rules.** A change to an incident moves the generator version; a change to an engine
   constant or a weight moves the rules hash. Either one means older reports no longer verify.
6. **Never run untrusted code on a server.**
7. **Honest claims.** Every public number is reproducible by a documented command, and every
   report links to the method and the limitations. Never imply that a result measures
   real-world security skill.
8. **Dated external facts.** Where the docs state a price, quota, version or third-party behaviour,
   they give the date it was checked, since such facts change.
9. **Small, green commits.** One logical change per commit; CI green before merging; no
   force-push to `main`.
10. **Few dependencies.** Prefer the standard library; add a dependency only when it removes real
    work and is widely used, maintained and permissively licensed.

## Adding to the check

The check lives in `src/cyberarena/rc/` and its tests in `tests/rc/`.

- **A new adapter.** It is a thin wrapper over the core (`rc.runner`): a driver
  `callable(shift) -> command | None`, or a text agent wrapped with `rc.runner.text_driver`. Add it
  beside the subprocess, HTTP and MCP adapters and give it an interface test.
- **A new scenario family.** Add a generator function in `rc/generator.py` that returns an incident
  record (alerts, logs, attacker moves with one adaptive rule, a knowledge base, injections and
  ground truth), register it in `FAMILY_FN`, describe it in [docs/SCENARIOS.md](docs/SCENARIOS.md)
  (behaviour only, never the held-out seeds or payload texts), and make sure the calibration gate
  (`tests/rc/test_rc_calibration.py`) still separates the baselines — a family that cannot
  distinguish them is redesigned or dropped.
- **Scoring changes.** Define the metric in [docs/SCORING.md](docs/SCORING.md) first, implement it
  once in `rc/scoring.py`/`rc/metrics.py`; the report viewer only renders. The scoring stays
  integer/exact so any reimplementation can match it, and every change that follows from seeing
  data is recorded with the original kept alongside.

## Pull requests

- One logical change, with its tests, and CI green.
- Say which rule, family, metric or document a change touches.
- Commit messages describe the change in plain words.
- The code is under the GNU Affero General Public License v3.0 only and the documentation and
  data under CC BY 4.0 (LICENSE, LICENSE-DATA, LICENSING.md). By submitting a contribution you
  agree that it is licensed under AGPL-3.0-only and that the author may also license it under
  other terms, including commercial licenses. For a large change, open an issue first.

## Reporting problems

Bugs and questions: open an issue (the templates ask for the command, the output and your
platform). Security problems: see [SECURITY.md](SECURITY.md); please do not open a public issue.
