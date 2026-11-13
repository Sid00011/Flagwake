"""Collect every run of the results workflow into results/ and docs/RESULTS.md.

Every run of .github/workflows/results.yml is listed, including runs that failed or produced no
report: a results page that only shows the runs someone liked would be the cherry-picking the
attempt log exists to expose. Each report is checked with flagwake verify --provenance --attempts
before it is listed, and the line says what the check found.

Usage: python scripts/collect_results.py [--repo Sid00011/Flagwake] [--write]
Needs the gh CLI (signed in) and flagwake with the provenance extra.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEEP = ("report.json", "report.sigstore.json", "attempt-ticket.txt", "attempt-ticket.sigstore.json")


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=True).stdout


def verify(folder: Path, repo: str) -> tuple[bool, list[str]]:
    argv = ["flagwake", "verify", str(folder / "report.json"), "--provenance",
            str(folder / "report.sigstore.json"), "--repo", repo, "--attempts"]  # fmt: skip
    done = subprocess.run(argv, capture_output=True, text=True)
    return done.returncode == 0, done.stdout.splitlines()


def row(doc: dict, ok: bool, lines: list[str], run: dict, slug: str) -> dict:
    m = doc["metrics"]
    di = m["damage_index"]
    usage: dict[str, object] = {}
    for inc in doc.get("incidents", []):
        for k, v in (inc.get("usage") or {}).items():
            usage[k] = v if isinstance(v, str) else float(usage.get(k, 0) or 0) + v  # type: ignore[arg-type]
    harness = next((x.split("harness: ", 1)[1] for x in lines if "harness: " in x), "?")
    return {
        "run": run["databaseId"], "url": run["url"], "date": run["createdAt"][:10],
        "ref": run["headBranch"], "slug": slug, "model": usage.get("model", "?"),
        "index": di["mean_clipped"], "ci": di["ci95"], "n": di["n"],
        "worse": di["worse_than_do_nothing"],
        "contained": m["containment"]["true_containment"]["rate"],
        "planted": m["injection"]["violation_rate"]["rate"],
        "failed_calls": int(usage.get("failed_calls", 0) or 0),
        "calls": int(usage.get("calls", 0) or 0),
        "attempt": doc.get("provenance", {}).get("attempt", ""),
        "verified": ok, "harness": harness,
    }  # fmt: skip


def collect(repo: str, out: Path) -> list[dict]:
    fields = "databaseId,headBranch,conclusion,createdAt,url"
    listing = gh("run", "list", "--repo", repo, "--workflow", "results.yml", "--limit", "200",
                 "--json", fields)  # fmt: skip
    runs = json.loads(listing)
    rows: list[dict] = []
    for run in runs:
        tmp = Path(tempfile.mkdtemp(prefix="flagwake-results-"))
        try:
            gh("run", "download", str(run["databaseId"]), "--repo", repo, "--dir", str(tmp))
        except subprocess.CalledProcessError:
            pass  # a run without artifacts is still listed below
        found = sorted(p for p in tmp.glob("result-*") if (p / "report.json").is_file())
        for folder in found:
            slug = folder.name.removeprefix("result-")
            ok, lines = verify(folder, repo)
            doc = json.loads((folder / "report.json").read_text(encoding="utf-8"))
            rows.append(row(doc, ok, lines, run, slug))
            dest = out / f"{run['databaseId']}-{slug}"
            dest.mkdir(parents=True, exist_ok=True)
            for name in KEEP:
                if (folder / name).is_file():
                    shutil.copy2(folder / name, dest / name)
        if not found:
            rows.append({"run": run["databaseId"], "url": run["url"], "date": run["createdAt"][:10],
                         "ref": run["headBranch"], "slug": "-", "model": "-", "verified": None,
                         "conclusion": run["conclusion"]})  # fmt: skip
        shutil.rmtree(tmp, ignore_errors=True)
    return rows


def page(rows: list[dict], repo: str) -> str:
    def pct(x: float | None) -> str:
        return "-" if x is None else f"{100 * x:.0f}%"

    out = [
        "# Signed results",
        "",
        "Every run of the results workflow (`.github/workflows/results.yml`), newest first, good",
        "or bad. Each model ran through Flagwake's signing workflow with Flagwake's reference",
        "model agent and the same small pack (fresh incidents, drawn inside each run); each report",
        "was checked with `flagwake verify --provenance --attempts` before it was listed. The",
        "model id is what the model's server reported. These are results of one agent scaffold",
        "on one pack size, under the free rate limits of GitHub Models: not a ranking of models,",
        "and not real incidents (docs/LIMITATIONS.md).",
        "",
        "| date | model | damage index [95% range] | worse than nothing | hosts contained "
        "| planted orders obeyed | model calls (failed) | attempt | check | run |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        if r.get("verified") is None:
            out.append(f"| {r['date']} | (no report: {r.get('conclusion') or 'unfinished'}) "
                       f"| | | | | | | | [{r['run']}]({r['url']}) |")  # fmt: skip
            continue
        lo, hi = r["ci"]
        check = ("signed, " + ("official" if "release" in r["harness"] else "unreleased")
                 if r["verified"] else "FAILED")  # fmt: skip
        index = "-" if r["index"] is None else f"{r['index']:.1f}"
        out.append(f"| {r['date']} | {r['model']} | {index} [{lo:.0f}-{hi:.0f}] | {r['worse']} "
                   f"| {pct(r['contained'])} | {pct(r['planted'])} "
                   f"| {r['calls']} ({r['failed_calls']}) | {r['attempt']} | {check} "
                   f"| [{r['run']}]({r['url']}) |")  # fmt: skip
    folder = "results/<run>-<model>"
    out += ["", f"Files: `{folder}/` (report, signature, attempt ticket). Re-check one:", "",
            "```bash", 'pip install "flagwake[provenance]"',
            f"flagwake verify {folder}/report.json --provenance {folder}/report.sigstore.json "
            f"--repo {repo} --attempts --require-official", "```", ""]  # fmt: skip
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="Sid00011/Flagwake")
    ap.add_argument("--write", action="store_true", help="write results/ and docs/RESULTS.md")
    args = ap.parse_args()
    out = ROOT / "results" if args.write else Path(tempfile.mkdtemp(prefix="flagwake-results-"))
    rows = collect(args.repo, out)
    text = page(rows, args.repo)
    if args.write:
        (ROOT / "docs" / "RESULTS.md").write_text(text, encoding="utf-8", newline="\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
