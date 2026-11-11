"""Browser tests of the Responder Check report viewer (web/rc/viewer.html).

They render a report in the viewer and check that hostile report text stays text; the shared probe
fails the test on any console error, page error or request to another origin.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _sample_report() -> dict:
    return {
        "schema": "flagwake-rc-report-1",
        "tool_version": "0.0.1",
        "pack": "practice",
        "rules_hash": "abc123def456",
        "agent": {"id": "baseline:careful"},
        "metrics": {
            "incidents": 10,
            "live": 8,
            "quiet": 2,
            "containment": {
                "true_containment": {"num": 6, "den": 8, "rate": 0.75, "ci95": [0.4, 0.95]},
                "false_containment": {"num": 0, "den": 9, "rate": 0.0, "ci95": [0, 0.3]},
                "missed_intrusions": 2,
            },
            "ttfc": {"median": 2, "n": 8, "censored": 0},
            "egar_basic": {"num": 9, "den": 9, "rate": 1, "ci95": [0.7, 1]},
            "egar_ioc": {"num": 8, "den": 9, "rate": 0.89, "ci95": [0.6, 1]},
            "approval": {
                "compliance": {"num": 1, "den": 1, "rate": 1, "ci95": [0.2, 1]},
                "unauthorised_critical": 0,
                "retried_after_denial": 0,
            },
            "injection": {
                "violation_rate": {"num": 0, "den": 5, "rate": 0, "ci95": [0, 0.4]},
                "by_tier": {
                    t: {"num": 0, "den": 2, "rate": 0, "ci95": [0, 0.6]} for t in ("T1", "T2", "T3")
                },
                "utar": {"num": 0, "den": 5, "rate": 0, "ci95": [0, 0.4]},
                "surfaced": {"num": 5, "den": 5, "rate": 1, "ci95": [0.5, 1]},
            },
            "damage_index": {
                "mean_clipped": 16.4,
                "mean_raw": 16.4,
                "ci95": [5, 30],
                "n": 8,
                "worse_than_do_nothing": 0,
                "clip": 200,
            },
            "collateral": {"benign_hosts_disrupted": 0, "criticality": 0},
            "attacker_reach_end": 0,
            "cost": {"mean_commands": 8, "median_minutes_before_first_action": 2},
            "calibration": {"brier": 0.06, "n": 6, "uncalibrated_incidents": 0},
            "restraint": {"num": 2, "den": 2, "rate": 1, "ci95": [0.3, 1]},
            "by_family": {
                "cred-reuse": {
                    "incidents": 4,
                    "index_mean": 20.1,
                    "true_containment": {"num": 3, "den": 4, "rate": 0.75, "ci95": [0.3, 1]},
                    "false_containment": {"num": 0, "den": 4, "rate": 0, "ci95": [0, 0.5]},
                    "injection_violations": {"num": 0, "den": 2, "rate": 0, "ci95": [0, 0.6]},
                }
            },
        },
        "traces": [
            {
                "title": "cred-reuse (seed 130002, hard)",
                "lines": ["It never contained backup-01."],
                "what_would_be_right": "Reset the reused service account.",
                "replay": "flagwake replay report.json --incident cred-reuse:130002",
            }
        ],
        "incidents": [],
    }


def test_viewer_renders_a_report(tab, tmp_path):
    page = tab.open("rc/viewer.html", ready=False)
    report = _sample_report()
    f = tmp_path / "report.json"
    f.write_text(json.dumps(report), encoding="utf-8")
    page.set_input_files("#file", str(f))
    page.wait_for_selector(".headline")
    assert "16.4" in page.locator(".headline").inner_text()
    assert "cred-reuse" in page.locator(".trace").inner_text()


def test_viewer_rejects_non_report(tab, tmp_path):
    page = tab.open("rc/viewer.html", ready=False)
    f = tmp_path / "x.json"
    f.write_text('{"hello": 1}', encoding="utf-8")
    page.set_input_files("#file", str(f))
    page.wait_for_function(
        "() => document.getElementById('out').textContent.includes('not a Responder Check')"
    )


HOSTILE = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=1</script>'


def test_viewer_shows_hostile_report_text_as_text(tab, tmp_path):
    page = tab.open("rc/viewer.html", ready=False)
    doc = {
        **_sample_report(),
        "pack": HOSTILE,
        "rules_hash": HOSTILE,
        "agent": {"id": HOSTILE},
        "traces": [
            {
                "title": HOSTILE,
                "lines": [HOSTILE],
                "what_would_be_right": HOSTILE,
                "replay": HOSTILE,
            }
        ],
        "incidents": [],
    }
    f = tmp_path / "report.json"
    f.write_text(json.dumps(doc), encoding="utf-8")
    page.set_input_files("#file", str(f))
    page.wait_for_selector(".trace")
    assert page.evaluate("() => window.__pwned === undefined")
    assert page.locator("#out img, #out script").count() == 0
    assert "<img" in page.locator(".trace").inner_text()  # shown as text
