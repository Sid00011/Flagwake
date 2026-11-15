"""A UTF-8 byte-order mark is not content: files that some Windows editors save with one (a report,
a company file, the list of defenders) read exactly as the same file without it."""

from __future__ import annotations

from pathlib import Path

from cyberarena.cli import main
from cyberarena.rc import registry as reg
from cyberarena.rc.company import digest, load_company
from cyberarena.rc.world_cli import TEMPLATE

BOM = b"\xef\xbb\xbf"


def _with_bom(src: Path, dst: Path) -> Path:
    dst.write_bytes(BOM + src.read_bytes())
    return dst


def test_verify_and_replay_read_a_report_saved_with_a_bom(tmp_path, capsys):
    out = tmp_path / "chk"
    args = ["check", "--agent", "baseline:rule-bot", "--pack", "practice", "--seeds", "1"]
    assert main([*args, "--out", str(out)]) == 0
    marked = _with_bom(out / "report.json", tmp_path / "marked.json")
    capsys.readouterr()

    assert main(["verify", str(marked)]) == 0
    assert "OK" in capsys.readouterr().out

    assert main(["replay", str(marked), "--incident", "cred-reuse:120000"]) == 0
    assert "[minute 0] start" in capsys.readouterr().out


def test_an_edited_report_with_a_bom_still_fails_on_the_edit(tmp_path, capsys):
    out = tmp_path / "chk"
    args = ["check", "--agent", "baseline:rule-bot", "--pack", "practice", "--seeds", "1"]
    assert main([*args, "--out", str(out)]) == 0
    text = (out / "report.json").read_text(encoding="utf-8")
    edited = tmp_path / "edited.json"
    edited.write_bytes(BOM + text.replace('"mean_clipped": ', '"mean_clipped": 1', 1).encode())
    capsys.readouterr()

    assert main(["verify", str(edited)]) == 1
    said = capsys.readouterr().out
    assert "mean_clipped" in said
    assert "cannot read" not in said


def test_a_company_file_with_a_bom_reads_the_same(tmp_path):
    plain = tmp_path / "company.yaml"
    plain.write_text(TEMPLATE, encoding="utf-8")
    marked = _with_bom(plain, tmp_path / "marked.yaml")
    assert digest(load_company(marked)) == digest(load_company(plain))


def test_a_defender_list_with_a_bom_reads_the_same(tmp_path):
    doc = {"version": reg.REGISTRY_VERSION, "defenders": [
        {"name": "careful", "kind": "baseline", "baseline": "careful"}]}  # fmt: skip
    plain = tmp_path / "flagwake.yaml"
    plain.write_text(reg.dump_yaml(reg.validate(doc)), encoding="utf-8")
    marked = _with_bom(plain, tmp_path / "marked.yaml")
    assert reg.load(marked) == reg.load(plain)
