"""Keep the packaged copy of the Responder Check report viewer equal to web/rc.

`flagwake serve` serves the viewer from src/cyberarena/rc/web, so a wheel works without the
repository. This script copies web/rc there (--write) or fails if the two differ (--check, run
in CI).

Usage: python scripts/export_rc_web.py --write | --check
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "web" / "rc"
PKG = ROOT / "src" / "cyberarena" / "rc" / "web"


def _files(base: Path) -> dict[str, bytes]:
    files = sorted(p for p in base.rglob("*") if p.is_file())
    return {p.relative_to(base).as_posix(): p.read_bytes() for p in files}


def write() -> None:
    if PKG.exists():
        shutil.rmtree(PKG)
    shutil.copytree(SRC, PKG)
    print(f"synced {PKG}")


def check() -> int:
    site, pkg = _files(SRC), _files(PKG)
    problems = [
        f"src/cyberarena/rc/web/{rel} is out of sync with web/rc (run --write)"
        for rel in sorted(set(site) | set(pkg))
        if site.get(rel) != pkg.get(rel)
    ]
    for p in problems:
        print(p)
    return 1 if problems else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if args.write:
        write()
        return 0
    return check()


if __name__ == "__main__":
    raise SystemExit(main())
