## What and why

<!-- One logical change. Which issue, family, metric or document does it touch? -->

## Checks

- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `python -m pytest` passes (browser tests too if the report viewer changed)
- [ ] `python scripts/golden_check.py` is unchanged, or the change bumps the generator version or the rules hash and is recorded in docs/METHODOLOGY.md
- [ ] Every new public number has a documented command that reproduces it
- [ ] The commit messages describe the change
