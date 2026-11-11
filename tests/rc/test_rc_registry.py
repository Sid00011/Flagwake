"""The defender registry: the strict flagwake.yaml subset, entry validation, the registry commands
(init, defenders add/list/show/remove, run, view) and the report fields they add."""

from __future__ import annotations

import json
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

from cyberarena.cli import main
from cyberarena.rc import registry as reg
from cyberarena.rc.registry import RegistryError
from cyberarena.rc.verify import verify

ROOT = Path(__file__).resolve().parents[2]
AGENT = f'"{sys.executable}" "{ROOT / "examples" / "rc_agent.py"}"'

GOOD = """\
# a comment
version: 1
defenders:
  - name: careful
    kind: baseline
    baseline: careful   # trailing comment
    meta:
      model_label: "scripted #1"
      version: 2
  - name: local-9b
    kind: model-endpoint
    role: defender
    base_url: http://localhost:8080/v1
    model: 'rc-m1'
    key_env: MY_KEY
    extra_body: {"reasoning_effort": "none"}
    caps:
      max_calls: 30
      step_timeout: 120.5
"""


def test_the_yaml_subset_reads_a_registry():
    doc = reg.validate(reg.parse_yaml(GOOD))
    a, b = doc["defenders"]
    assert a == {"name": "careful", "kind": "baseline", "role": "defender", "baseline": "careful",
                 "meta": {"model_label": "scripted #1", "version": "2"}}  # fmt: skip
    assert b["extra_body"] == {"reasoning_effort": "none"}
    assert b["caps"] == {"max_calls": 30, "step_timeout": 120.5}
    assert b["model"] == "rc-m1"


def test_dump_round_trips():
    doc = reg.validate(reg.parse_yaml(GOOD))
    assert reg.validate(reg.parse_yaml(reg.dump_yaml(doc))) == doc


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("version: 1\ndefenders:\n\t- name: a\n", "tabs"),
        ("version: 1\nversion: 1\n", "duplicate"),
        ("version: 1\n---\n", "one document"),
        ("version: 1\ndefenders: &x []\n", "references"),
        ("version: 1\ndefenders: !!python/object []\n", "references"),
        ("version: 1\nnote: |\n  text\n", "block text"),
        ("version: 1\ndefenders: {bad json}\n", "JSON"),
        ('version: 1\nx: "open\n', "quoted"),
        ("version: 1\n   extra: 1\n", "indentation"),
        ("version: 1\nx: a: b\n", "quote a value"),
    ],
)
def test_the_parser_rejects_what_it_does_not_support(text, why):
    with pytest.raises(RegistryError, match=why):
        reg.parse_yaml(text)


def _entry(**kw):
    base = {"name": "x", "kind": "command", "command": "python agent.py"}
    base.update(kw)
    return base


@pytest.mark.parametrize(
    ("entry", "why"),
    [
        (_entry(name="Bad Name"), "name must be"),
        (_entry(name="../up"), "name must be"),
        (_entry(kind="shell"), "kind must be"),
        (_entry(colour="red"), "unknown field 'colour'"),
        (_entry(url="http://127.0.0.1:1/"), "belongs to kind http"),
        (_entry(api_key="sk-123"), "never put a key"),  # hygiene-ok: fake key, must be refused
        (_entry(role="attacker"), "role must be 'defender'"),
        (_entry(command="python a.py\nrm -rf /"), "one line"),
        (_entry(command=""), "needs command"),
        (_entry(caps={"max_commands": 61}), "from 1 to 60"),
        (_entry(caps={"max_calls": 2.5}), "whole number"),
        (_entry(caps={"wall": 3}), "unknown cap"),
        (_entry(meta={"colour": "red"}), "unknown meta"),
        ({"name": "h", "kind": "http", "url": "http://example.com/act"}, "127.0.0.1"),
        ({"name": "m", "kind": "model-endpoint", "base_url": "http://x/v1"}, "needs model"),
        ({"name": "m", "kind": "model-endpoint", "base_url": "http://x/v1", "model": "a",
          "extra_body": {"model": "other"}}, "cannot set model"),
        ({"name": "m", "kind": "model-endpoint", "base_url": "http://x/v1", "model": "a",
          "key_env": "my key; echo"}, "not allowed"),
        ({"name": "b", "kind": "baseline", "baseline": "nobody"}, "baseline must be"),
    ],
)  # fmt: skip
def test_entries_are_validated_strictly(entry, why):
    with pytest.raises(RegistryError, match=why):
        reg.validate_entry(entry)


def test_unknown_top_level_fields_and_versions_are_rejected():
    with pytest.raises(RegistryError, match="unknown top-level"):
        reg.validate({"version": 1, "defenders": [], "extra": 1})
    with pytest.raises(RegistryError, match="version must be 1"):
        reg.validate({"version": 2, "defenders": []})
    with pytest.raises(RegistryError, match="used twice"):
        reg.validate({"version": 1, "defenders": [_entry(), _entry()]})


def test_only_the_command_string_reaches_a_command_line():
    entry = reg.validate_entry(
        {"name": "m", "kind": "model-endpoint", "base_url": "http://localhost:1/v1",
         "model": "$(whoami)", "extra_body": {"a": "; rm -rf /"},
         "caps": {"max_calls": 5, "max_tokens": 64}}
    )  # fmt: skip
    argv = reg.model_argv(entry)
    assert argv[1:] == ["-m", "cyberarena.rc.model_agent", "--max-calls", "5", "--max-tokens", "64"]
    env = reg.model_env(entry)
    assert env["FLAGWAKE_LLM_MODEL"] == "$(whoami)"
    assert json.loads(env["FLAGWAKE_LLM_EXTRA_BODY"]) == {"a": "; rm -rf /"}


def test_a_key_is_passed_only_through_the_named_variable(monkeypatch):
    monkeypatch.setenv("MY_KEY", "secret-value")
    monkeypatch.setenv("FLAGWAKE_LLM_KEY", "stale")
    entry = reg.validate_entry({"name": "m", "kind": "model-endpoint", "model": "a",
                                "base_url": "http://localhost:1/v1",
                                "key_env": "MY_KEY"})  # fmt: skip
    assert reg.model_env(entry)["FLAGWAKE_LLM_KEY"] == "secret-value"
    del entry["key_env"]
    assert "FLAGWAKE_LLM_KEY" not in reg.model_env(entry)
    assert "secret-value" not in json.dumps(reg.manifest(entry))


# --------------------------------------------------------------------------- commands


def _cli(tmp_path, *argv):
    return main([*argv, "--config", str(tmp_path / "flagwake.yaml")])


def test_init_add_list_show_remove(tmp_path, capsys):
    assert _cli(tmp_path, "init") == 0
    assert _cli(tmp_path, "init") == 2  # never overwrites without --force
    assert _cli(tmp_path, "defenders", "add", "--name", "careful", "--kind", "baseline",
                "--baseline", "careful", "--model-label", "scripted") == 0  # fmt: skip
    assert _cli(tmp_path, "defenders", "add", "--name", "mine", "--kind", "command",
                "--command", AGENT, "--max-commands", "30",
                "--step-timeout", "20") == 0  # fmt: skip
    assert _cli(tmp_path, "defenders", "add", "--name", "mine", "--kind", "baseline",
                "--baseline", "careful") == 2  # fmt: skip
    assert _cli(tmp_path, "defenders", "add", "--name", "bad", "--kind", "http",
                "--url", "http://10.0.0.1/act") == 2  # fmt: skip
    doc = reg.load(tmp_path / "flagwake.yaml")
    assert [e["name"] for e in doc["defenders"]] == ["careful", "mine"]
    assert doc["defenders"][1]["caps"] == {"max_commands": 30, "step_timeout": 20}
    capsys.readouterr()
    assert _cli(tmp_path, "defenders", "list") == 0
    out = capsys.readouterr().out
    assert "careful" in out and "mine" in out and "not run" in out
    assert _cli(tmp_path, "defenders", "show", "mine") == 0
    assert "max_commands: 30" in capsys.readouterr().out
    assert _cli(tmp_path, "defenders", "remove", "careful") == 0
    assert _cli(tmp_path, "defenders", "remove", "careful") == 2
    assert [e["name"] for e in reg.load(tmp_path / "flagwake.yaml")["defenders"]] == ["mine"]


def test_add_asks_questions_when_no_name_is_given(tmp_path):
    from cyberarena.rc import registry_cli

    assert _cli(tmp_path, "init") == 0
    answers = iter(["asked", "baseline", "rule-bot"] + [""] * 6 + ["scripted", "", ""])
    args = type("A", (), {"config": str(tmp_path / "flagwake.yaml"), "name": None})()
    assert registry_cli._add(args, ask=lambda _q: next(answers)) == 0
    entry = reg.get(reg.load(tmp_path / "flagwake.yaml"), "asked")
    assert entry == {"name": "asked", "kind": "baseline", "role": "defender",
                     "baseline": "rule-bot", "meta": {"model_label": "scripted"}}  # fmt: skip


def test_a_broken_registry_file_is_reported_with_its_line(tmp_path, capsys):
    (tmp_path / "flagwake.yaml").write_text("version: 1\ndefenders:\n  - name: x\n    kind: nope\n")
    assert _cli(tmp_path, "defenders", "list") == 2
    assert "kind must be" in capsys.readouterr().err


def test_run_writes_a_labelled_verifiable_report(tmp_path, capsys):
    _cli(tmp_path, "init")
    _cli(tmp_path, "defenders", "add", "--name", "mine", "--kind", "command", "--command", AGENT,
         "--model-label", "<b>example</b>")  # fmt: skip
    _cli(tmp_path, "defenders", "add", "--name", "careful", "--kind", "baseline",
         "--baseline", "careful")  # fmt: skip
    assert _cli(tmp_path, "run", "--all", "--pack", "practice", "--seeds", "1") == 0
    out = capsys.readouterr().out
    assert "pack practice (public seeds" in out
    assert "conformance: passed 7/7" in out
    assert "conformance: built-in" in out
    report = tmp_path / "flagwake-runs" / "mine" / "practice" / "report.json"
    doc = json.loads(report.read_text(encoding="utf-8"))
    assert verify(doc) == []
    agent = doc["agent"]
    assert agent["role"] == "defender"
    assert agent["manifest"]["meta"]["model_label"] == "<b>example</b>"
    assert agent["conformance"]["status"] == "passed"
    html = (report.parent / "report.html").read_text(encoding="utf-8")
    assert "<b>example</b>" not in html and "&lt;b&gt;example&lt;/b&gt;" in html
    # The manifest and conformance sit outside the hashed scoring part.
    from cyberarena.rc.report import report_hash

    edited = {**doc, "agent": {**agent, "manifest": {"meta": {"model_label": "other"}}}}
    assert report_hash(edited) == doc["report_hash"] and verify(edited) == []


def test_run_needs_a_defender_and_a_known_name(tmp_path, capsys):
    _cli(tmp_path, "init")
    assert _cli(tmp_path, "run") == 2
    assert _cli(tmp_path, "run", "--defender", "ghost") == 2
    assert "no defender named 'ghost'" in capsys.readouterr().err


def test_contamination_warning_when_practice_is_far_better(tmp_path):
    from cyberarena.rc.registry_cli import contamination_warning

    folder = tmp_path / "d"
    (folder / "heldout").mkdir(parents=True)
    held = {"metrics": {"damage_index": {"mean_clipped": 80.0, "ci95": [70.0, 90.0]}}}
    (folder / "heldout" / "report.json").write_text(json.dumps(held))
    far = {"metrics": {"damage_index": {"mean_clipped": 30.0, "ci95": [20.0, 40.0]}}}
    near = {"metrics": {"damage_index": {"mean_clipped": 70.0, "ci95": [60.0, 80.0]}}}
    assert "may have been learned" in contamination_warning(folder, "practice", far)
    assert contamination_warning(folder, "practice", near) is None
    assert contamination_warning(tmp_path / "none", "practice", far) is None


def test_view_serves_the_viewer_and_one_report_on_localhost(tmp_path):
    from cyberarena.rc.serve import make_server

    report = tmp_path / "report.json"
    report.write_text('{"schema": "flagwake-rc-report-1"}', encoding="utf-8")
    httpd = make_server(0, report)
    assert httpd.server_address[0] == "127.0.0.1"
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        base = f"http://127.0.0.1:{port}"
        with urllib.request.urlopen(base + "/report.json") as r:
            assert json.loads(r.read())["schema"] == "flagwake-rc-report-1"
        with urllib.request.urlopen(base + "/?report=latest") as r:
            page = r.read().decode()
            assert "connect-src 'self'" in r.headers["Content-Security-Policy"]
        assert "viewer.js" in page
        for bad in ("/../flagwake.yaml", "/report.json/../x", "/js/../../registry.py"):
            with pytest.raises(urllib.error.HTTPError):
                urllib.request.urlopen(base + bad)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_view_picks_the_newest_report(tmp_path, monkeypatch):
    import os

    from cyberarena.rc.registry_cli import latest_report

    monkeypatch.chdir(tmp_path)
    path = tmp_path / "flagwake.yaml"
    assert latest_report(path) is None
    for i, name in enumerate(("a", "b")):
        f = tmp_path / "flagwake-runs" / name / "heldout" / "report.json"
        f.parent.mkdir(parents=True)
        f.write_text("{}")
        os.utime(f, (1_000_000 + i, 1_000_000 + i))
    assert latest_report(path).parent.parent.name == "b"


def test_every_saved_registry_shows_how_to_plug_in_any_kind(tmp_path):
    _cli(tmp_path, "init")
    text = (tmp_path / "flagwake.yaml").read_text(encoding="utf-8")
    for kind in reg.KINDS:
        assert f"kind: {kind}" in text
    assert reg.validate(reg.parse_yaml(text)) == {"version": 1, "defenders": []}


def test_a_program_missing_on_this_machine_is_named(tmp_path, capsys):
    _cli(tmp_path, "init")
    _cli(tmp_path, "defenders", "add", "--name", "elsewhere", "--kind", "command",
         "--command", "no-such-program-xyz --flag")  # fmt: skip
    assert _cli(tmp_path, "defenders", "test", "elsewhere") == 2
    assert "'no-such-program-xyz'" in capsys.readouterr().err
    assert _cli(tmp_path, "run", "--defender", "elsewhere", "--seeds", "1") == 2
    assert "not found on this machine" in capsys.readouterr().err


def test_a_registry_moves_between_machines(tmp_path):
    """Relative commands run from the registry's folder, wherever that folder is."""
    import shutil

    for name in ("a", "b"):
        (tmp_path / name).mkdir()
    agent = ROOT / "examples" / "rc_agent.py"
    shutil.copy(agent, tmp_path / "a" / "agent.py")
    cfg = tmp_path / "a" / "flagwake.yaml"
    main(["init", "--config", str(cfg)])
    main(["defenders", "add", "--name", "rel", "--kind", "command", "--command",
          f'"{sys.executable}" agent.py', "--config", str(cfg)])  # fmt: skip
    shutil.copytree(tmp_path / "a", tmp_path / "b" / "copy")
    moved = tmp_path / "b" / "copy" / "flagwake.yaml"
    assert main(["defenders", "test", "rel", "--config", str(moved)]) == 0


def test_a_model_endpoint_gets_the_step_timeout_for_each_call():
    entry = reg.validate_entry({"name": "slow", "kind": "model-endpoint", "model": "a",
                                "base_url": "https://example.invalid/v1",
                                "caps": {"step_timeout": 120}})  # fmt: skip
    assert reg.model_argv(entry)[-2:] == ["--timeout", "115"]
    entry["caps"] = {}
    assert "--timeout" not in reg.model_argv(entry)


def test_run_uses_the_entry_world_and_the_world_option(tmp_path):
    from cyberarena.rc.registry import load, save
    from cyberarena.rc.world_cli import TEMPLATE

    _cli(tmp_path, "init")
    _cli(tmp_path, "defenders", "add", "--name", "big", "--kind", "baseline",
         "--baseline", "careful")  # fmt: skip
    doc = load(tmp_path / "flagwake.yaml")
    doc["defenders"][0]["world"] = "fenwick-brae"
    save(tmp_path / "flagwake.yaml", doc)
    assert _cli(tmp_path, "run", "--defender", "big", "--pack", "practice", "--seeds", "1") == 0
    report = tmp_path / "flagwake-runs" / "big" / "practice" / "report.json"
    first = json.loads(report.read_text(encoding="utf-8"))
    assert first["world"]["name"] == "fenwick-brae" and verify(first) == []
    (tmp_path / "company.yaml").write_text(TEMPLATE, encoding="utf-8")  # relative to the registry
    assert _cli(tmp_path, "run", "--defender", "big", "--pack", "practice", "--seeds", "1",
                "--world", str(tmp_path / "company.yaml")) == 0  # fmt: skip
    second = json.loads(report.read_text(encoding="utf-8"))
    assert second["world"]["custom"] and verify(second, tmp_path / "company.yaml") == []
    assert second["families_skipped"]  # the template company lacks two families' needs


def test_a_key_is_not_registered_for_plain_http_to_another_machine():
    from cyberarena.rc.registry import RegistryError, validate_entry

    def entry(url, **extra):
        return {"name": "m", "kind": "model-endpoint", "base_url": url, "model": "x", **extra}

    with pytest.raises(RegistryError, match="https"):
        validate_entry(entry("http://192.168.1.5:8080/v1", key_env="MY_KEY"))
    assert validate_entry(entry("https://models.example.com/v1", key_env="MY_KEY"))
    assert validate_entry(entry("http://127.0.0.1:8080/v1", key_env="MY_KEY"))
    assert validate_entry(entry("http://192.168.1.5:8080/v1"))  # no key, nothing to protect


def test_any_value_in_any_entry_field_gets_a_plain_error_not_a_crash():
    """flagwake.yaml is edited by hand: whatever is in a field, the answer is a RegistryError
    with the reason or a clean copy, never another exception."""
    from cyberarena.rc.registry import RegistryError, validate_entry

    bases = [
        {"name": "a", "kind": "command", "command": "python x.py", "mode": "tools",
         "caps": {"step_timeout": 30}, "meta": {"model_label": "m"}, "world": "harlow-pine"},
        {"name": "b", "kind": "http", "url": "http://127.0.0.1:8000/act"},
        {"name": "c", "kind": "mcp", "command": "python s.py", "tool": "act"},
        {"name": "d", "kind": "model-endpoint", "base_url": "http://localhost:8080/v1",
         "model": "m", "key_env": "K", "extra_body": {"think": False}},
        {"name": "e", "kind": "baseline", "baseline": "careful"},
    ]  # fmt: skip
    junk = (None, [], {}, [1], {"a": 1}, 5, -1, 1.5, True, "", "x", "a" * 3000, "a\nb",
            ["a", ["b"]], {"id": []}, "‮", "http://", "ftp://x")  # fmt: skip
    tried = 0
    for base in bases:
        assert validate_entry(base)["name"] == base["name"]
        for field in [*base, "role", "caps", "meta", "world", "mode", "baseline", "unknown"]:
            for value in junk:
                try:
                    out = validate_entry({**base, field: value})
                except RegistryError as exc:
                    assert 0 < len(str(exc)) < 600
                else:
                    json.dumps(out)
                tried += 1
    for value in junk:
        with pytest.raises(RegistryError):
            validate_entry(value if not isinstance(value, dict) or value else 7)
    assert tried > 500
