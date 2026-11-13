"""Mode B, the company as tools: the 1:1 mapping, malformed calls, fairness against the native
protocol, no ground truth in any response, the HTTP and MCP surfaces, and verify."""

from __future__ import annotations

import copy
import io
import json
import urllib.error
import urllib.request

import pytest

from cyberarena.rc import rules
from cyberarena.rc.baselines import ALL_AGENTS
from cyberarena.rc.report import TOOLS, build_report, report_hash
from cyberarena.rc.runner import baseline_driver, pack_specs, run_pack, start_shift
from cyberarena.rc.scoring import score_shift
from cyberarena.rc.toolsapi import MAX_CALLS, TOOL_NAMES, ToolIncident
from cyberarena.rc.toolsrun import (
    MAX_BODY,
    TicketDesk,
    ToolsServer,
    mcp_handle,
    native_to_call,
    openapi,
    run_program_as_tools,
    serve_stdio,
)
from cyberarena.rc.verify import verify
from cyberarena.rc.world import WORLD, shipped_world

W = shipped_world()


def incident(family: str = "privileged-laptop-to-payments", seed: int = 120001) -> ToolIncident:
    return ToolIncident(start_shift({"family": family, "seed": seed, "difficulty": "standard"}, W),
                        "i-test")  # fmt: skip


def _any(kind: str) -> str:
    return {"host": "ws-ops-01", "account": "k.mensah", "flow": "dispatch"}[kind]


# (tool, arguments, the world command it must be recorded as)
CASES = [
    ("get_alerts", {}, "look"),
    ("list_business_flows", {}, "look"),
    ("list_hosts", {}, "hosts"),
    ("get_host", {"host": "db-02"}, "hosts"),
    ("search_logs", {"host": "db-02", "minutes": 30}, "logs db-02 30"),
    ("search_logs", {"source": "identity"}, "logs identity"),
    ("search_logs", {"host": "db-02", "account": "k.mensah"}, "logs db-02"),
    ("get_user", {"account": "k.mensah"}, "who k.mensah"),
    ("contact_user", {"account": "k.mensah", "topic": "travelling"}, "ask k.mensah travelling"),
    ("isolate_host", {"host": "ws-ops-01", "minutes": 30}, "isolate ws-ops-01 30"),
    ("isolate_host", {"host": "ws-ops-01"}, "isolate ws-ops-01"),
    ("release_host", {"host": "ws-ops-01"}, "release ws-ops-01"),
    ("disable_account", {"account": "k.mensah"}, "block k.mensah"),
    ("reset_credentials", {"account": "k.mensah"}, "reset k.mensah"),
    ("restore_host", {"host": "ws-ops-01"}, "restore ws-ops-01"),
    ("patch_host", {"host": "ws-ops-01"}, "patch ws-ops-01"),
    ("block_address", {"address": "203.0.113.9"}, "block 203.0.113.9"),
    ("request_approval", {"action": "isolate_host", "target": "db-02"}, "escalate isolate db-02"),
    ("request_approval", {"action": "pause_flow", "target": "payroll-transfer"},
     "escalate pause payroll-transfer"),
    ("pause_flow", {"flow": "dispatch"}, "pause dispatch"),
    ("resume_flow", {"flow": "dispatch"}, "resume dispatch"),
    ("notify_role", {"role": "security-lead", "message": "looking   into it"},
     "notify security-lead looking into it"),
    ("wait", {"minutes": 5}, "wait 5"),
    ("close_ticket", {"compromised": []}, 'report {"compromised": []}'),
]  # fmt: skip


def test_every_tool_has_a_case():
    assert {c[0] for c in CASES} | {"get_alert", "update_ticket"} == set(TOOL_NAMES)


@pytest.mark.parametrize("tool,args,line", CASES)
def test_each_tool_maps_to_one_world_command(tool, args, line):
    inc = incident()
    resp = inc.call(tool, args)
    assert resp["ok"], resp
    assert inc.commands == [line]
    assert inc.calls == [{"tool": tool, "args": args}]
    assert score_shift(inc.shift)["cost"]["unrecognised_commands"] == 0


def test_get_alert_and_the_ticket_draft():
    inc = incident()
    alerts = inc.call("get_alerts", {})["result"]["alerts"]
    one = inc.call("get_alert", {"alert_id": alerts[0]["id"]})
    assert one["ok"] and one["result"]["alert"] == alerts[0] and inc.commands == ["look", "look"]
    r = inc.call("update_ticket", {"summary": "draft", "compromised": ["db-02"]})
    assert r["ok"] and inc.commands == ["look", "look"]  # a draft runs no world command
    inc.call("close_ticket", {"confidence": {"db-02": 0.7}})
    assert inc.shift.report["compromised"] == ["db-02"]
    assert inc.shift.report["summary"] == "draft" and inc.shift.done


MALFORMED = [
    ("no_such_tool", {}),
    ("get_alerts", ["not", "an", "object"]),
    ("isolate_host", {}),
    ("isolate_host", {"host": "ws-ops-01", "extra": 1}),
    ("isolate_host", {"host": "ws-ops-01", "minutes": "ten"}),
    ("isolate_host", {"host": "ws-ops-01", "minutes": 9999}),
    ("disable_account", {"account": "203.0.113.9"}),
    ("block_address", {"address": "k.mensah"}),
    ("search_logs", {"host": "db-02", "source": "identity"}),
    ("get_alert", {"alert_id": "A999"}),
    ("notify_role", {"role": "it lead", "message": "x"}),
    ("notify_role", {"role": "security-lead", "message": "x" * 5000}),
    ("contact_user", {"account": "k.mensah", "topic": "anything"}),
]


@pytest.mark.parametrize("tool,args", MALFORMED)
def test_a_malformed_call_is_a_plain_error_and_an_unrecognised_command(tool, args):
    inc = incident()
    resp = inc.call(tool, args)
    assert not resp["ok"] and isinstance(resp["error"], str) and len(resp["error"]) < 200
    assert len(inc.commands) == 1 and inc.commands[0].startswith("tool:")
    assert score_shift(inc.shift)["cost"]["unrecognised_commands"] == 1
    assert inc.shift.now == 0  # it cost no simulated time


def test_a_call_naming_nothing_runs_as_the_native_command_would():
    inc = incident()
    resp = inc.call("restore_host", {"host": "no-such-host"})
    assert not resp["ok"] and "no host named" in resp["error"]
    assert inc.commands == ["restore no-such-host"]  # the native protocol records the same line
    assert score_shift(inc.shift)["cost"]["unrecognised_commands"] == 0


def test_the_call_cap_closes_the_ticket():
    inc = incident()
    for _ in range(MAX_CALLS):
        inc.call("update_ticket", {"summary": "x"})
    assert inc.done and inc.call("get_alerts", {}) == {"ok": False, "error": "the ticket is closed"}


@pytest.mark.parametrize("world", [W, shipped_world("fenwick-brae"), WORLD],
                         ids=["harlow-pine", "fenwick-brae", "legacy"])  # fmt: skip
def test_every_program_scores_the_same_through_both_modes(world):
    specs = pack_specs("practice", 2, world=world)
    for name in ALL_AGENTS:
        s = TicketDesk(specs, world)
        run_program_as_tools(name, s)
        tools = s.result()
        native = run_pack(lambda n=name: baseline_driver(n), specs, world=world)
        assert [t["commands"] for t in tools["transcripts"]] == [
            t["commands"] for t in native["transcripts"]
        ], name
        assert tools["outcomes"] == native["outcomes"], name


TRUTH_KEYS = {
    "truth",
    "quiet",
    "siphons",
    "payloads",
    "flaws",
    "attacker_ips",
    "fragile",
    "family",
    "seed",
    "difficulty",
    "required_evidence",
    "correct_actions",
    "notes",
}


def _keys(obj, out):
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(k)
            _keys(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _keys(v, out)
    return out


def test_no_ground_truth_reaches_a_tool_response():
    from cyberarena.rc.gen2 import FAMILIES

    world = shipped_world("fenwick-brae")
    sources = frozenset(s["source"] for s in world.log_sources)
    for name in ("thorough", "gullible", "paranoid"):
        for fam in FAMILIES:
            spec = {"family": fam, "seed": 120004, "difficulty": "hard"}
            inc = ToolIncident(start_shift(spec, world), "i-x")
            agent = ALL_AGENTS[name]()
            sent = [inc.opening]
            while not inc.done:
                line = agent.next_command(inc.shift)
                if line is None:
                    break
                sent.append(inc.call(*native_to_call(line, sources)))
            blob = json.dumps(sent)
            assert not (_keys(sent, set()) & TRUTH_KEYS), (name, fam)
            assert inc.shift.incident["truth"]["notes"][:40] not in blob
            assert f'"{fam}"' not in blob


def test_hostile_text_in_arguments_stays_data():
    inc = incident()
    nasty = '<script>alert(1)</script>\x00\x1b[31m"; rm -rf / #'
    r = inc.call("notify_role", {"role": "security-lead", "message": nasty})
    assert r["ok"]
    assert "\n" not in inc.commands[0] and len(inc.commands[0]) < 400
    r = inc.call("update_ticket", {"summary": nasty, "compromised": [nasty]})
    inc.call("close_ticket", {})
    assert inc.shift.report["summary"] == nasty  # stored as text; the renderers escape it
    json.dumps(inc.calls)  # the record is plain JSON


def test_a_tools_report_verifies_and_tampering_is_caught():
    specs = pack_specs("practice", 1, world=W)[:6]
    s = TicketDesk(specs, W)
    run_program_as_tools("careful", s)
    doc = build_report(s.result(), {"id": "x"}, "practice", world=W,
                       integration={"mode": TOOLS, "adapter": "built-in program"})  # fmt: skip
    assert verify(doc) == [] and doc["integration"]["mode"] == TOOLS
    assert doc["integration"]["instruction_text"] == "none"
    for where in ("args", "sent"):
        d = copy.deepcopy(doc)
        inc = d["incidents"][0]
        if where == "args":
            inc["calls"][1]["args"] = {"host": "web-01"}
        else:
            inc["sent_hashes"][1] = "0" * 64
        d["report_hash"] = report_hash(d)
        assert any("cannot replay" in p or "sent" in p for p in verify(d)), where


def _post(url, body, token=None, ctype="application/json"):
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    headers = {"Content-Type": ctype}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_the_http_server_needs_the_token_and_serves_rest_and_mcp():
    specs = pack_specs("practice", 1, world=W)[:2]
    s = TicketDesk(specs, W)
    srv = ToolsServer(s).start()
    try:
        a = srv.addresses()
        assert _post(a["api"] + "/tools/get_alerts", {})[0] == 401
        assert _post(a["api"] + "/tools/get_alerts", {}, "wrong")[0] == 401
        code, r = _post(a["api"] + "/tools/get_alerts", {}, a["token"])
        assert code == 200 and r["ok"] and r["result"]["ticket"]["id"].startswith("i-")
        assert _post(a["api"] + "/tools/get_alerts", b"x", a["token"], "text/plain")[0] == 415
        assert _post(a["api"] + "/tools/get_alerts", b"{" + b" " * MAX_BODY + b"}",
                     a["token"])[0] == 413  # fmt: skip
        code, r = _post(a["api"] + "/webhooks", {"url": "http://example.org/hook"}, a["token"])
        assert code == 400 and "this machine" in r["error"]
        init = _post(a["mcp"], {"jsonrpc": "2.0", "id": 1, "method": "initialize"}, a["token"])[1]
        assert init["result"]["capabilities"] == {"tools": {}}
        lst = _post(a["mcp"], {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, a["token"])[1]
        assert [t["name"] for t in lst["result"]["tools"]] == list(TOOL_NAMES)
        call = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "close_ticket", "arguments": {"compromised": []}},
        }
        out = _post(a["mcp"], call, a["token"])[1]["result"]
        assert not out["isError"] and json.loads(out["content"][0]["text"])["ok"]
        assert len(s.transcripts) == 1  # the first ticket closed; the second is open
        with urllib.request.urlopen(a["openapi"], timeout=10) as r:
            doc = json.loads(r.read())
        assert all(f"/v1/tools/{n}" in doc["paths"] for n in TOOL_NAMES)
    finally:
        srv.close()


def test_mcp_over_stdio_and_bad_messages():
    s = TicketDesk(pack_specs("practice", 1, world=W)[:1], W)
    lines = [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "get_alerts", "arguments": {}}}),
             "not json", json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
             json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "rm", "arguments": {}}})]  # fmt: skip
    out = io.StringIO()
    serve_stdio(s, io.StringIO("\n".join(lines) + "\n"), out)
    replies = [json.loads(x) for x in out.getvalue().splitlines()]
    assert len(replies) == 3  # the notification gets no answer
    assert replies[1]["error"]["code"] == -32700 and replies[2]["error"]["code"] == -32602
    assert mcp_handle(s, {"jsonrpc": "1.0"})["error"]["code"] == -32600
    assert openapi()["components"]["securitySchemes"]["token"]["scheme"] == "bearer"


def test_registry_mode_tools_is_limited_to_what_the_harness_can_start(tmp_path):
    from cyberarena.rc.registry import RegistryError, validate_entry

    with pytest.raises(RegistryError, match="mode tools"):
        validate_entry({"name": "x", "kind": "http", "url": "http://127.0.0.1:9/act",
                        "mode": "tools"})  # fmt: skip
    e = validate_entry({"name": "b", "kind": "baseline", "baseline": "careful", "mode": "tools",
                        "world": "fenwick-brae"})  # fmt: skip
    from cyberarena.rc.toolsrun import run_tools_entry

    world = shipped_world("fenwick-brae")
    specs = pack_specs("practice", 1, world=world)[:3]
    result, integ = run_tools_entry(e, tmp_path, tmp_path / "out", specs, 1, world)
    assert integ["mode"] == TOOLS and len(result["outcomes"]) == 3
    assert rules.from_ref(result["world"]) is world


def test_the_reference_tool_loop_runs_a_model_through_the_tools(tmp_path, monkeypatch):
    """examples/reference_tool_agent.py against a fake model that lists hosts, then closes."""
    import http.server
    import sys
    import threading
    from pathlib import Path

    from cyberarena.rc.toolsrun import run_command_as_tools

    seen = []

    class Fake(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            return

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append(body)
            tools_done = sum(1 for m in body["messages"] if m["role"] == "tool")
            name, args = (
                ("list_hosts", {})
                if tools_done == 0
                else ("close_ticket", {"compromised": [], "summary": "nothing found"})
            )
            msg = {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": f"c{tools_done}",
                        "type": "function",
                        "function": {"name": name, "arguments": json.dumps(args)},
                    }
                ],
            }
            out = json.dumps({"choices": [{"message": msg}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    srv = http.server.HTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("FLAGWAKE_LLM_BASE_URL", f"http://127.0.0.1:{srv.server_address[1]}/v1")
    monkeypatch.setenv("FLAGWAKE_LLM_MODEL", "fake")
    try:
        desk = TicketDesk(pack_specs("practice", 1, world=W)[:2], W)
        example = Path(__file__).resolve().parents[2] / "examples" / "reference_tool_agent.py"
        run_command_as_tools([sys.executable, str(example)], desk, tmp_path, tmp_path / "o", 120)
    finally:
        srv.shutdown()
    assert [t["end_reason"] for t in desk.transcripts] == ["report", "report"]
    assert [c["tool"] for c in desk.transcripts[0]["calls"]] == [
        "get_alerts",
        "list_hosts",
        "close_ticket",
    ]
    assert seen and seen[0]["messages"][0]["role"] == "system"  # the scaffold's own instruction
    assert {t["function"]["name"] for t in seen[0]["tools"]} == set(TOOL_NAMES)


def test_a_client_that_hangs_up_is_not_reported_as_an_error(capsys):
    from cyberarena.rc.toolsrun import _Server

    srv = ToolsServer(TicketDesk(pack_specs("practice", 1, world=W)[:1], W))
    try:
        for exc in (ConnectionResetError("gone"), ValueError("a real bug")):
            try:
                raise exc
            except Exception:
                _Server.handle_error(srv.httpd, None, ("127.0.0.1", 1))
        err = capsys.readouterr().err
        assert "ConnectionResetError" not in err and "a real bug" in err
    finally:
        srv.httpd.server_close()
        srv.hooks.close()


def test_tools_mode_enforces_the_same_command_cap():
    specs = pack_specs("practice", 1, world=W)[:2]
    s = TicketDesk(specs, W, max_commands=3)
    resp = None
    for _ in range(3):
        resp = s.call("get_alerts", {})
    assert resp is not None and resp["ticket_open"] is False and "cap" in resp["note"]
    assert len(s.transcripts) == 1 and len(s.transcripts[0]["commands"]) == 3
