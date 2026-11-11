"""The conformance suite behind `flagwake defenders test`: a well-behaved defender passes all seven
checks and each misbehaving scripted program fails the check it was written to break. Also the
role handshake and the MCP-server defender kind."""

from __future__ import annotations

import sys
import textwrap

import pytest

from cyberarena.rc import registry as reg
from cyberarena.rc.conformance import CHECKS, run_conformance, summary_line
from cyberarena.rc.engine import COMMANDS
from cyberarena.rc.runner import run_incident

GOOD = """
import json, sys
step = 0
for line in sys.stdin:
    msg = json.loads(line)
    if msg.get("type") == "end":
        break
    step += 1
    cmd = "look" if step == 1 else 'report {"compromised": [], "summary": "ok"}'
    print(json.dumps({"cmd": cmd}), flush=True)
"""

# Each misbehaving program and the one check it must fail.
BAD = {
    "protocol": """
import sys
for line in sys.stdin:
    print("hello, I am not JSON", flush=True)
""",
    "valid_commands": """
import json, sys
n = 0
for line in sys.stdin:
    if json.loads(line).get("type") == "end":
        break
    n += 1
    cmd = "nmap -sS 10.0.0.0/24" if n == 1 else 'report {"compromised": []}'
    print(json.dumps({"cmd": cmd}), flush=True)
""",
    "caps": """
import json, sys
for line in sys.stdin:
    if json.loads(line).get("type") == "end":
        break
    print(json.dumps({"cmd": "look", "usage": {"calls": 999}}), flush=True)
""",
    "report": """
import json, sys
for line in sys.stdin:
    if json.loads(line).get("type") == "end":
        break
    print(json.dumps({"cmd": "report all clear, nothing to see"}), flush=True)
""",
    "denial": """
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if msg.get("type") == "end":
        break
    if "refused" in msg.get("text", "") or "denied" in msg.get("text", ""):
        print(json.dumps({"cmd": "escalate isolate db-01"}), flush=True)
    else:
        print(json.dumps({"cmd": 'report {"compromised": []}'}), flush=True)
""",
    "malformed": """
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if msg.get("type") == "end":
        break
    int(msg.get("t", 0))  # crashes on a clock that is not a number
    cmd = "look" if msg.get("type") == "start" else 'report {"compromised": []}'
    print(json.dumps({"cmd": cmd}), flush=True)
""",
    "no_hang": """
import json, sys, time
for line in sys.stdin:
    msg = json.loads(line)
    if msg.get("type") == "end":
        break
    if msg.get("type") == "obs":
        time.sleep(30)
    print(json.dumps({"cmd": "look"}), flush=True)
""",
}


def _entry(tmp_path, code, name="t", **caps):
    script = tmp_path / f"{name}.py"
    script.write_text(textwrap.dedent(code), encoding="utf-8")
    entry = {"name": name, "kind": "command", "command": f'"{sys.executable}" "{script}"',
             "caps": {"step_timeout": 2, "incident_timeout": 60, "max_commands": 12,
                      **caps}}  # fmt: skip
    return reg.validate_entry(entry)


def _run(tmp_path, entry):
    return run_conformance(entry, reg.driver_factory(entry, tmp_path, tmp_path / "out"))


def test_a_well_behaved_defender_passes_all_seven(tmp_path):
    result = _run(tmp_path, _entry(tmp_path, GOOD))
    assert [c["id"] for c in result["checks"]] == [cid for cid, _ in CHECKS]
    assert result["status"] == "passed", result["checks"]
    assert summary_line(result) == "conformance: passed 7/7"


@pytest.mark.parametrize("broken", sorted(BAD))
def test_each_misbehaviour_fails_its_check(tmp_path, broken):
    caps = {"max_calls": 5} if broken == "caps" else {}
    result = _run(tmp_path, _entry(tmp_path, BAD[broken], **caps))
    failed = {c["id"] for c in result["checks"] if not c["passed"]}
    assert broken in failed, result["checks"]
    assert result["status"] == "failed"
    assert dict(CHECKS)[broken] in summary_line(result)


def test_an_unrunnable_program_fails_without_hanging(tmp_path):
    command = f'"{sys.executable}" -c "raise SystemExit(3)"'
    entry = reg.validate_entry({"name": "gone", "kind": "command", "command": command})
    result = _run(tmp_path, entry)
    assert result["passed"] == 0 and "could not be run" in result["checks"][0]["detail"]


def test_baselines_are_reported_as_built_in(tmp_path):
    entry = reg.validate_entry({"name": "c", "kind": "baseline", "baseline": "careful"})
    result = _run(tmp_path, entry)
    assert result["status"] == "built-in"
    assert "built-in" in summary_line(result)


def test_the_start_message_names_the_role_and_only_the_rules_commands(tmp_path):
    seen = tmp_path / "seen.txt"
    code = f"""
import json, sys
first = None
for line in sys.stdin:
    msg = json.loads(line)
    if msg.get("type") == "start":
        first = msg
        open({str(seen)!r}, "w").write(json.dumps(msg))
    if msg.get("type") == "end":
        break
    print(json.dumps({{"cmd": 'report {{"compromised": []}}'}}), flush=True)
"""
    import json

    from cyberarena.rc.engine import RULES1_COMMANDS, RULES2_COMMANDS
    from cyberarena.rc.world import WORLD

    entry = _entry(tmp_path, code)
    factory = reg.driver_factory(entry, tmp_path, tmp_path / "out")
    spec = {"family": "cred-reuse", "seed": 120000, "difficulty": "standard"}
    # The default company runs rules 2 (16 commands); the legacy world keeps the original 13.
    for world, want in ((None, RULES2_COMMANDS), (WORLD, RULES1_COMMANDS)):
        run_incident(spec, factory(), world=world)
        start = json.loads(seen.read_text())
        assert start["type"] == "start" and start["role"] == "defender"
        assert start["commands"] == list(want)
        assert set(start) == {"type", "role", "incident", "text", "commands", "limits"}
    assert len(RULES1_COMMANDS) == 13 and set(RULES1_COMMANDS) < set(RULES2_COMMANDS)
    assert COMMANDS == RULES2_COMMANDS


MCP_SERVER = """
import json, sys
step = 0
for line in sys.stdin:
    msg = json.loads(line)
    mid = msg.get("id")
    method = msg.get("method")
    if method == "initialize":
        out = {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "d"}}
    elif method == "tools/list":
        out = {"tools": [{"name": "act", "inputSchema": {"type": "object"}}]}
    elif method == "tools/call":
        m = msg["params"]["arguments"]["message"]
        if m.get("type") == "end":
            out = {"content": [{"type": "text", "text": "bye"}]}
        else:
            step += 1
            text = "look" if step == 1 else '{"cmd": "report {\\\\"compromised\\\\": []}"}'
            out = {"content": [{"type": "text", "text": text}]}
    else:
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": out}), flush=True)
"""


def test_an_mcp_server_defender_is_driven_through_its_tool(tmp_path):
    script = tmp_path / "mcp_defender.py"
    script.write_text(textwrap.dedent(MCP_SERVER), encoding="utf-8")
    entry = reg.validate_entry({"name": "m", "kind": "mcp",
                                "command": f'"{sys.executable}" "{script}"',
                                "caps": {"step_timeout": 5}})  # fmt: skip
    factory = reg.driver_factory(entry, tmp_path, tmp_path / "out")
    shift, tr, _o = run_incident(
        {"family": "quiet", "seed": 120000, "difficulty": "standard"}, factory()
    )
    assert tr["commands"][0] == "look" and shift.end_reason == "report"
    assert _run(tmp_path, entry)["status"] == "passed"


def test_an_mcp_server_without_the_tool_is_refused(tmp_path):
    from cyberarena.rc.protocol import ProtocolError

    script = tmp_path / "mcp_defender.py"
    script.write_text(textwrap.dedent(MCP_SERVER), encoding="utf-8")
    entry = reg.validate_entry({"name": "m", "kind": "mcp", "tool": "decide",
                                "command": f'"{sys.executable}" "{script}"'})  # fmt: skip
    factory = reg.driver_factory(entry, tmp_path, tmp_path / "out")
    with pytest.raises(ProtocolError, match="no tool named 'decide'"):
        run_incident({"family": "quiet", "seed": 120000, "difficulty": "standard"}, factory())
