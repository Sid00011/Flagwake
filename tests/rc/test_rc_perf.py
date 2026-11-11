"""Performance budget for the Responder Check: a full default run and a single incident are fast.

Thresholds are generous (the real numbers are far below) so this does not flake on a slow runner;
it guards against an accidental quadratic blow-up, not against a few hundred milliseconds.
"""

from __future__ import annotations

import time

from cyberarena.rc.runner import baseline_driver, build_pack, run_baseline_pack, run_incident


def test_default_pack_runs_in_budget():
    specs = build_pack("heldout", per_family=10)  # 120 incidents, the default run
    assert len(specs) == 120
    start = time.perf_counter()
    result = run_baseline_pack("rule-bot", specs)
    elapsed = time.perf_counter() - start
    assert len(result["outcomes"]) == 120
    assert elapsed < 30, f"120 incidents took {elapsed:.1f}s (budget 30s)"


def test_single_incident_is_fast():
    spec = {"family": "cred-reuse", "seed": 120000, "difficulty": "standard"}
    start = time.perf_counter()
    run_incident(spec, baseline_driver("careful"))
    assert time.perf_counter() - start < 0.5
