"""Agent interfaces: the JSON-lines subprocess protocol, the MCP server, the HTTP adapter, the
Python API and the CLI wiring."""

from __future__ import annotations

import io
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from cyberarena.rc import mcp
from cyberarena.rc.protocol import (
    INVALID_REPLY,
    MAX_BAD_LINES,
    http_driver_factory,
    subprocess_driver_factory,
)
from cyberarena.rc.runner import make, run_incident

# --------------------------------------------------------------------------- Python API


def test_python_api_make_step():
    env = make("cred-reuse", 120005, "standard")
    obs = env.reset()
    assert "minute 0 of 480" in obs["text"]
    obs, info = env.step("hosts")
    assert "Hosts" in obs["text"] and info["verb"] == "hosts"


# --------------------------------------------------------------------------- subprocess protocol

ECHO = (
    "import sys,json\n"
    "for line in sys.stdin:\n"
    "    line=line.strip()\n"
    "    if not line: continue\n"
    "    m=json.loads(line)\n"
    "    if m.get('type')=='end': break\n"
    "    print(json.dumps({'cmd':'look'}));sys.stdout.flush()\n"
)
CLOSER = (
    "import sys,json\n"
    "for line in sys.stdin:\n"
    "    line=line.strip()\n"
    "    if not line: continue\n"
    "    m=json.loads(line)\n"
    "    if m.get('type')=='end': break\n"
    "    print(json.dumps({'cmd':'report {\\\"compromised\\\": []}'}));sys.stdout.flush()\n"
)


def test_subprocess_agent_runs():
    factory = subprocess_driver_factory([sys.executable, "-I", "-c", CLOSER])
    spec = {"family": "quiet", "seed": 120000, "difficulty": "standard"}
    shift, tr, outcome = run_incident(spec, factory())
    assert shift.done
    assert tr["commands"] and tr["commands"][0].startswith("report")


def test_subprocess_agent_that_never_answers_is_killed():
    code = "import time\ntime.sleep(30)\n"
    factory = subprocess_driver_factory([sys.executable, "-I", "-c", code], step_timeout=1.0)
    spec = {"family": "quiet", "seed": 120000, "difficulty": "standard"}
    t0 = time.monotonic()
    agent = factory()
    shift, tr, _o = run_incident(spec, agent)
    assert time.monotonic() - t0 < 10  # killed after the 1 s step timeout, not after 30 s
    assert shift.done and tr["commands"] == []
    assert tr["harness"]["error"] == "no answer within 1s"
    assert agent.proc.poll() is not None  # the child is gone


def test_subprocess_agent_printing_garbage_is_bounded():
    code = (
        "import sys\n"
        "for line in sys.stdin:\n"
        "    sys.stdout.write('not json at all\\n');sys.stdout.flush()\n"
    )
    factory = subprocess_driver_factory([sys.executable, "-I", "-c", code], step_timeout=5.0)
    spec = {"family": "quiet", "seed": 120000, "difficulty": "standard"}
    shift, tr, outcome = run_incident(spec, factory())
    assert tr["commands"] == [INVALID_REPLY] * MAX_BAD_LINES  # each one a failed command
    assert tr["harness"] == {
        "error": f"more than {MAX_BAD_LINES} invalid replies",
        "invalid_replies": MAX_BAD_LINES + 1,
    }
    assert outcome["cost"]["unrecognised_commands"] == MAX_BAD_LINES


# --------------------------------------------------------------------------- HTTP adapter


def test_http_adapter_rejects_non_localhost():
    with pytest.raises(ValueError):
        http_driver_factory("http://example.com/act")()


def test_http_adapter_runs_against_localhost():
    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            n = int(self.headers["Content-Length"])
            self.rfile.read(n)
            body = json.dumps({"cmd": "look"}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        spec = {"family": "quiet", "seed": 120000, "difficulty": "standard"}
        shift, tr, _o = run_incident(spec, http_driver_factory(f"http://127.0.0.1:{port}/act")())
        assert shift.done and len(tr["commands"]) >= 1
    finally:
        srv.shutdown()


# --------------------------------------------------------------------------- MCP


def _mcp(messages, log_dir):
    inp = io.StringIO("\n".join(json.dumps(m) for m in messages) + "\n")
    out = io.StringIO()
    mcp.serve(inp, out, log_dir=str(log_dir))
    return [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]


def test_mcp_round_trip(tmp_path):
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "start_incident",
                "arguments": {"family": "cred-reuse", "seed": 120005},
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "run_command", "arguments": {"command": "look"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "finish_incident", "arguments": {}},
        },
    ]
    resps = _mcp(msgs, tmp_path)
    assert resps[0]["result"]["serverInfo"]["name"] == "flagwake-rc"
    assert {t["name"] for t in resps[1]["result"]["tools"]} == {
        "start_incident",
        "run_command",
        "incident_status",
        "finish_incident",
    }
    assert "minute 0 of 480" in resps[2]["result"]["content"][0]["text"]
    assert resps[4]["result"]["structuredContent"]["done"]
    assert list(tmp_path.glob("*.json"))  # a transcript was written


def test_mcp_unknown_tool_is_an_error(tmp_path):
    resps = _mcp(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "nope", "arguments": {}},
            }
        ],
        tmp_path,
    )
    assert resps[0]["error"]["code"] == -32601


def _mcp_incident(server, family, seed=120005, difficulty="standard"):
    """Start, look and finish one incident on an MCP server object."""
    server.start_incident({"family": family, "seed": seed, "difficulty": difficulty})
    server.run_command({"command": "look"})
    return server.finish_incident({})["structuredContent"]["written"]


def test_mcp_serves_the_default_company_with_all_its_families(tmp_path):
    from cyberarena.rc import rules

    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}]
    start = _mcp(msgs, tmp_path)[0]["result"]["tools"][0]
    assert start["name"] == "start_incident"
    families = start["inputSchema"]["properties"]["family"]["enum"]
    assert tuple(families) == rules.families(rules.default_world()) and len(families) == 20
    server = mcp.Server(str(tmp_path))
    written = json.loads(
        open(_mcp_incident(server, "signal-in-the-flood"), encoding="utf-8").read()
    )
    assert written["rules"] == 2 and written["world"]["name"] == "harlow-pine"


@pytest.mark.parametrize("name", ["harlow-pine", "fenwick-brae", "legacy"])
def test_mcp_transcripts_score_and_verify_in_the_company_they_ran_in(tmp_path, name, capsys):
    from cyberarena.cli import main
    from cyberarena.rc.verify import verify
    from cyberarena.rc.world import resolve_world

    server = mcp.Server(str(tmp_path / "log"), resolve_world(name))
    for family in ("cred-reuse", "quiet"):
        _mcp_incident(server, family)
    out = tmp_path / "out"
    assert main(["report", "--mcp-log", str(tmp_path / "log"), "--out", str(out)]) == 0
    doc = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert doc["pack"] == "mcp" and len(doc["incidents"]) == 2 and verify(doc) == []
    if name == "legacy":
        assert doc.get("rules", 1) == 1
    else:
        assert doc["rules"] == 2 and doc["world"]["name"] == name
    capsys.readouterr()


def test_mcp_transcripts_of_a_custom_company_need_its_file(tmp_path, capsys):
    from cyberarena.cli import main
    from cyberarena.rc.world import world_from_file
    from cyberarena.rc.world_cli import TEMPLATE

    company = tmp_path / "company.yaml"
    company.write_text(TEMPLATE, encoding="utf-8")
    server = mcp.Server(str(tmp_path / "log"), world_from_file(company))
    _mcp_incident(server, "cred-reuse")
    out = tmp_path / "out"
    assert main(["report", "--mcp-log", str(tmp_path / "log"), "--out", str(out)]) == 2
    assert "--world" in capsys.readouterr().err
    argv = [
        "report",
        "--mcp-log",
        str(tmp_path / "log"),
        "--out",
        str(out),
        "--world",
        str(company),
    ]
    assert main(argv) == 0
    doc = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert doc["world"]["custom"] is True
    capsys.readouterr()


def test_mcp_transcripts_from_two_companies_are_not_mixed(tmp_path, capsys):
    from cyberarena.cli import main
    from cyberarena.rc.world import resolve_world

    for name in ("harlow-pine", "fenwick-brae"):
        _mcp_incident(mcp.Server(str(tmp_path / "log"), resolve_world(name)), "cred-reuse")
    assert main(["report", "--mcp-log", str(tmp_path / "log"), "--out", str(tmp_path / "o")]) == 2
    assert "different companies" in capsys.readouterr().err


def test_mcp_refuses_a_family_the_company_cannot_run(tmp_path):
    server = mcp.Server(str(tmp_path))
    with pytest.raises(ValueError, match="unknown family"):
        server.start_incident({"family": "no-such-family", "seed": 1})
    with pytest.raises(ValueError, match="unknown difficulty"):
        server.start_incident({"family": "quiet", "seed": 1, "difficulty": "nightmare"})
    with pytest.raises(ValueError, match="whole number"):
        server.start_incident({"family": "quiet", "seed": True})


# --------------------------------------------------------------------------- CLI


def test_cli_check_and_verify(tmp_path):
    from cyberarena.cli import main

    out = tmp_path / "chk"
    rc = main(
        [
            "check",
            "--agent",
            "baseline:careful",
            "--pack",
            "practice",
            "--seeds",
            "1",
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    assert (out / "report.json").is_file() and (out / "report.html").is_file()
    assert main(["verify", str(out / "report.json")]) == 0


def test_cli_baselines_runs(tmp_path, capsys):
    from cyberarena.cli import main

    assert main(["baselines", "--pack", "practice", "--seeds", "1"]) == 0
    assert "oracle" in capsys.readouterr().out


def test_cli_replay_prints_a_plain_transcript(tmp_path, capsys):
    from cyberarena.cli import main

    out = tmp_path / "chk"
    main(
        [
            "check",
            "--agent",
            "baseline:rule-bot",
            "--pack",
            "practice",
            "--seeds",
            "1",
            "--out",
            str(out),
        ]
    )
    capsys.readouterr()
    assert main(["replay", str(out / "report.json")]) == 0
    text = capsys.readouterr().out
    doc = json.loads((out / "report.json").read_text(encoding="utf-8"))
    first = doc["incidents"][0]
    assert text.startswith(f"Incident {first['family']}:{first['seed']} ")
    assert "[minute 0] start" in text and "Harlow & Pine Logistics" in text
    # Every stored command appears with the minute it was issued and the minutes it took.
    entries = [line for line in text.splitlines() if line.startswith("[minute ") and "] > " in line]
    assert [e.split("] > ", 1)[1].rsplit("  (took ", 1)[0] for e in entries] == first["commands"]
    assert all(e.endswith(" min)") for e in entries)
    assert f"Business cost: damage {first['outcome']['damage']} " in text
    assert "Ground truth: " in text


def test_the_command_has_only_the_checker_subcommands():
    from cyberarena.cli import COMMANDS, build_parser

    assert set(COMMANDS) == {
        "check", "replay", "baselines", "doctor", "mcp", "serve", "verify", "report",
        "init", "defenders", "run", "view", "ui", "world", "tools", "demo", "ci",
    }  # fmt: skip
    parser = build_parser()
    assert parser.parse_args(["demo"]).out == "flagwake-demo"  # the checker's own demo
    for gone in ("rate", "rating"):
        with pytest.raises(SystemExit):
            parser.parse_args([gone])


def test_agent_command_split_keeps_windows_paths(monkeypatch):
    from cyberarena.rc import cli

    monkeypatch.setattr(cli.sys, "platform", "win32")
    line = r'"C:\Program Files\Py\python.exe" my agent.py --dry'
    assert cli.split_command(line) == [r"C:\Program Files\Py\python.exe", "my", "agent.py", "--dry"]
    monkeypatch.setattr(cli.sys, "platform", "linux")
    assert cli.split_command("python 'my agent.py' --dry") == ["python", "my agent.py", "--dry"]


def test_the_help_groups_every_command_once_and_starts_with_the_demo(capsys):
    from cyberarena import cli

    listed = [name for _title, commands in cli.GROUPS for name, _text in commands]
    assert sorted(listed) == sorted(cli.COMMANDS) and len(listed) == len(set(listed))
    assert cli.GROUPS[0][1][0][0] == "demo"
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    text = capsys.readouterr().out
    assert text.startswith("usage: flagwake <command>") and "Start here:" in text
    assert all(len(line) <= 100 for line in text.splitlines())
    assert cli.main([]) == 0 and "Start here:" in capsys.readouterr().out
    with pytest.raises(SystemExit):  # a command keeps its own argparse help
        cli.main(["verify", "--help"])
    assert "usage: flagwake verify" in capsys.readouterr().out


def test_cli_check_verifies_whatever_order_the_families_are_given_in(tmp_path):
    from cyberarena.cli import main

    out = tmp_path / "chk"
    argv = ["check", "--agent", "baseline:careful", "--pack", "practice", "--seeds", "1",
            "--family", "quiet", "--family", "cred-reuse", "--family", "quiet",
            "--out", str(out)]  # fmt: skip
    assert main(argv) == 0
    assert main(["verify", str(out / "report.json")]) == 0
