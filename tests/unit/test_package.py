"""Smoke tests: the package imports and the CLI entry point runs."""

import importlib.metadata
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

import cyberarena
from cyberarena import cli


def test_version_labels() -> None:
    assert cyberarena.__version__ == "0.5.0rc6"


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.startswith("flagwake 0.5.0rc6")


def test_cli_no_args_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([]) == 0
    assert "usage: flagwake" in capsys.readouterr().out


def test_module_entry_point() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "cyberarena.cli", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "flagwake 0.5.0rc6" in proc.stdout


def _holder(root: Path) -> str:
    """The copyright holder named on the second line of NOTICE."""
    line = (root / "NOTICE").read_text(encoding="utf-8").splitlines()[1]
    assert line.startswith("Copyright (C) 2026 ")
    return line.split("Copyright (C) 2026 ")[1].split(" (")[0].strip()


def test_license_and_citation_agree() -> None:
    """LICENSE is the unmodified AGPL-3.0 text (so tools recognise it), NOTICE names the holder and
    the commercial option, LICENSE-DATA is CC BY 4.0, and CITATION.cff and pyproject say the same;
    no file still states the earlier restrictive terms."""
    root = Path(__file__).resolve().parents[2]
    holder = _holder(root)
    license_text = (root / "LICENSE").read_text(encoding="utf-8")
    assert license_text.lstrip().startswith("GNU AFFERO GENERAL PUBLIC LICENSE")
    assert "Version 3, 19 November 2007" in license_text
    notice = (root / "NOTICE").read_text(encoding="utf-8")
    assert "AGPL-3.0-only" in notice and "LICENSING.md" in notice
    data = (root / "LICENSE-DATA").read_text(encoding="utf-8")
    assert f"Copyright (c) 2026 {holder}\n" in data
    assert "Attribution 4.0 International" in data and "NonCommercial" not in data
    cff = (root / "CITATION.cff").read_text(encoding="utf-8")
    assert "cff-version: 1.2.0" in cff
    assert f'  - name: "{holder}"' in cff
    assert "license: AGPL-3.0-only" in cff
    for name in ("README.md", "CONTRIBUTING.md", "LICENSING.md", "pyproject.toml", "CITATION.cff"):
        text = (root / name).read_text(encoding="utf-8")
        assert "PolyForm" not in text and "BY-NC-ND" not in text, name
    assert "AGPL" in (root / "README.md").read_text(encoding="utf-8")


def test_pyproject_authors_match_license_holder() -> None:
    root = Path(__file__).resolve().parents[2]
    pyproject = (root / "pyproject.toml").read_text("utf-8")
    assert f'authors = [{{ name = "{_holder(root)}" }}]' in pyproject
    assert 'license = "AGPL-3.0-only"' in pyproject
    assert 'license-files = ["LICENSE", "LICENSE-DATA", "NOTICE"]' in pyproject


def test_flagwake_command_is_declared_and_installed() -> None:
    """The ``flagwake`` command is declared in pyproject.toml and present in the installed
    package's metadata."""
    root = Path(__file__).resolve().parents[2]
    scripts = tomllib.loads((root / "pyproject.toml").read_text("utf-8"))["project"]["scripts"]
    assert scripts == {"flagwake": "cyberarena.cli:main"}
    installed = {
        ep.name: ep.value
        for ep in importlib.metadata.entry_points(group="console_scripts")
        if ep.name in scripts
    }
    assert installed == scripts, 'reinstall with: pip install -e ".[dev]"'


def test_the_package_data_covers_every_shipped_data_file():
    """A data file the package-data patterns miss would be absent from the wheel."""
    import fnmatch
    import tomllib
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    conf = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    patterns = conf["tool"]["setuptools"]["package-data"]["cyberarena.rc"]
    base = root / "src" / "cyberarena" / "rc"
    for f in list((base / "data").rglob("*.json")) + list((base / "web").rglob("*.*")):
        rel = f.relative_to(base).as_posix()
        depth = rel.count("/")
        assert any(fnmatch.fnmatch(rel, p) and depth == p.count("/") for p in patterns), rel


def test_release_publishes_from_github_without_a_stored_token() -> None:
    """Releases reach PyPI only through trusted publishing: a short-lived identity, an approval in
    the pypi environment, actions pinned by commit, and a tag that must name the package version."""
    import re

    root = Path(__file__).resolve().parents[2]
    wf = (root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert 'tags: ["v*"]' in wf and "secrets." not in wf
    assert "id-token: write" in wf and "name: pypi" in wf
    assert re.search(r"pypa/gh-action-pypi-publish@[0-9a-f]{40}\b", wf)
    uses = re.findall(r"uses: (\S+)", wf)
    assert uses and all(re.search(r"@[0-9a-f]{40}$", u) for u in uses), uses
    assert '"v$version" != "$GITHUB_REF_NAME"' in wf
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = project["version"]
    assert version == cyberarena.__version__


def test_the_name_is_kept_out_of_the_licenses() -> None:
    """The name and mark are reserved (AGPL section 7(e)) in LICENSING.md, NOTICE and the README."""
    root = Path(__file__).resolve().parents[2]
    licensing = (root / "LICENSING.md").read_text(encoding="utf-8")
    assert "## Name and mark" in licensing and "AGPL section 7(e)" in licensing
    assert "section 7(e)" in (root / "NOTICE").read_text(encoding="utf-8")
    assert "**Name and mark:**" in (root / "README.md").read_text(encoding="utf-8")


def test_the_action_and_the_signed_example_use_this_version() -> None:
    root = Path(__file__).resolve().parents[2]
    action = (root / "action.yml").read_text(encoding="utf-8")
    assert f"default: flagwake[provenance]=={cyberarena.__version__}" in action
    workflow = f"Sid00011/Flagwake/.github/workflows/check.yml@v{cyberarena.__version__}"
    for name in (".github/workflows/check.yml", "examples/ci/flagwake-signed.yml",
                 "docs/SIGNED_RESULTS.md"):  # fmt: skip
        assert workflow in (root / name).read_text(encoding="utf-8"), name
