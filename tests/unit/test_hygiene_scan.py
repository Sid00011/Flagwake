""" "No secrets, no payments" scan.

The scan must flag each listed term and must FAIL when grep
itself fails, instead of passing silently. Words are assembled at run time so this file does
not trip the scan.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "hygiene_scan.sh"
BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None, reason="bash not available")

TERMS = [
    "api" + "_key = 1",
    "API" + "-KEY",
    "s" + "k-abc123",
    "pass" + "word",
    "str" + "ipe",
    "pay" + "pal",
    "nv" + "api-abcdefgh12345",
    "AIz" + "aSyA1234567890abcdefghij",
    "gs" + "k_abcdefgh1234",
]


def run_scan(tmp_path: Path, target: str = ".") -> subprocess.CompletedProcess[str]:
    shutil.copy(SCRIPT, tmp_path / "hygiene_scan.sh")
    return subprocess.run(
        [BASH, "hygiene_scan.sh", target], cwd=tmp_path, capture_output=True, text=True
    )


def test_clean_tree_passes(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("risk_level = 'task-runner'\n", encoding="utf-8")
    r = run_scan(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize("term", TERMS)
def test_each_spec_term_fails_the_scan(tmp_path: Path, term: str) -> None:
    (tmp_path / "bad.py").write_text(f"x = '{term}'\n", encoding="utf-8")
    r = run_scan(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr


def test_a_marked_line_with_a_reason_passes(tmp_path: Path) -> None:
    word = "pass" + "word"
    (tmp_path / "ok.html").write_text(
        f'<input type="{word}"> <!-- hygiene-ok: hides the key while it is typed -->\n',
        encoding="utf-8",
    )
    assert run_scan(tmp_path).returncode == 0


@pytest.mark.parametrize(
    "text",
    [
        "x = '{w}'  # hygiene-ok:\n",  # a marker without a reason
        "# hygiene-ok: the next line\nx = '{w}'\n",  # a marker on another line
        "x = '{w}'  # hygiene-ok: fine\ny = '{w}'\n",  # one marked line, one not
    ],
)
def test_a_marker_excuses_only_its_own_line_and_needs_a_reason(tmp_path: Path, text: str) -> None:
    (tmp_path / "bad.py").write_text(text.format(w="pass" + "word"), encoding="utf-8")
    r = run_scan(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr


def test_the_tracked_tree_passes() -> None:
    """The repository itself is clean (CI runs the same scan on a checkout)."""
    r = subprocess.run([BASH, str(SCRIPT), "src"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_scan_covers_workflow_files(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "x.yml").write_text("env:\n  KEY: " + "pass" + "word\n", encoding="utf-8")
    assert run_scan(tmp_path).returncode == 1


def test_grep_error_fails_the_scan(tmp_path: Path) -> None:
    r = run_scan(tmp_path, "no-such-directory")
    assert r.returncode != 0, r.stdout + r.stderr


def test_ci_runs_the_scan_script() -> None:
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "bash scripts/hygiene_scan.sh" in ci


def test_only_the_vendored_axe_file_is_skipped(tmp_path: Path) -> None:
    """tests/e2e/vendor/axe.min.js (pinned by its SHA-256) is skipped; the name elsewhere fails."""
    vendor = tmp_path / "tests" / "e2e" / "vendor"
    vendor.mkdir(parents=True)
    (vendor / "axe.min.js").write_text("var f = '" + "pass" + "word';\n", encoding="utf-8")
    assert run_scan(tmp_path).returncode == 0
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "axe.min.js").write_text("var a = 1;\n", encoding="utf-8")
    r = run_scan(tmp_path)
    assert r.returncode == 1 and "only allowed in tests/e2e/vendor" in r.stdout, r.stdout
