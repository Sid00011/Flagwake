"""Every flagwake command in the README quick start, QUICKSTART.md and TRY_YOUR_AGENT.md runs.

The commands are read from the documents themselves (fenced blocks and inline code), so a doc
edit that breaks a command fails here. Only what cannot run offline is substituted: placeholders
such as <provider> and <model id> point at a local fake model server, the documented HTTP agent
address at a local scripted agent, "python" at this interpreter (an active virtual environment),
and my_agent.py at the shipped example agent. Environment setup lines (venv, activate, pip) are
covered by the clean-install check of a release, not here.
"""

from __future__ import annotations

import io
import json
import re
import shlex
import shutil
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from rckit import FakeModel

from cyberarena.cli import main

ROOT = Path(__file__).resolve().parents[2]
DOCS = {
    "readme": ROOT / "README.md",
    "quickstart": ROOT / "docs" / "QUICKSTART.md",
    "try": ROOT / "docs" / "TRY_YOUR_AGENT.md",
}
SKIP_PREFIX = ("python -m venv", ". .venv", "source ", "pip ", "set ")


def commands(path: Path) -> list[str]:
    """Shell lines of the fenced blocks (Responder Check part) plus inline `flagwake ...` spans."""
    text = path.read_text(encoding="utf-8")
    if path.name == "README.md":  # only the quick start; the development block is not a demo
        start = text.index("## Quick start")
        text = text[start : text.index("\n## ", start + 1)]
    out: list[str] = []
    blocks = re.findall(r"```(?:bash|sh|shell)?\n(.*?)```", text, re.S)
    for block in blocks:
        for line in block.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    for span in re.findall(r"`(flagwake [^`]+)`", re.sub(r"```.*?```", "", text, flags=re.S)):
        if len(span.split()) > 2:  # `flagwake doctor` alone is a mention, not a command
            out.append(span)
    return out


class Agent(BaseHTTPRequestHandler):
    """A local HTTP agent: one look, then an all-clear report."""

    def do_POST(self):  # noqa: N802 (http.server API)
        msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        cmd = "look" if msg.get("type") == "start" else 'report {"compromised": []}'
        body = json.dumps({"cmd": cmd}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        pass


MCP_SESSION = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
        "name": "start_incident", "arguments": {"family": "quiet", "seed": 120000}}},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
        "name": "run_command", "arguments": {"command": 'report {"compromised": []}'}}},
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
        "name": "finish_incident", "arguments": {}}},
]  # fmt: skip


@pytest.mark.parametrize("doc", sorted(DOCS))
def test_documented_commands_run(doc, tmp_path, monkeypatch):
    lines = commands(DOCS[doc])
    assert any(line.startswith("flagwake ") for line in lines)
    shutil.copytree(ROOT / "examples", tmp_path / "examples")
    shutil.copy(ROOT / "examples" / "rc_agent.py", tmp_path / "my_agent.py")
    monkeypatch.chdir(tmp_path)
    fake = FakeModel([("ok", "Command: `look`"), ("ok", 'report {"compromised": []}')])
    http = ThreadingHTTPServer(("127.0.0.1", 0), Agent)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    agent_url = f"http://127.0.0.1:{http.server_address[1]}/act"
    subs = {
        "https://<provider>/v1": fake.url,
        "http://localhost:<port>/v1": fake.url,
        "<model id>": "fake-model",
        "<a model the server has loaded>": "fake-model",
        "<your key>": "test-token-docs",
        "http://127.0.0.1:8000/act": agent_url,
        "family:seed": "cred-reuse:120000",
    }
    # The guide runs doctor on "the model endpoint in FLAGWAKE_LLM_BASE_URL (below)": as a reader
    # who exported the variables first.
    monkeypatch.setenv("FLAGWAKE_LLM_BASE_URL", fake.url)
    monkeypatch.setenv("FLAGWAKE_LLM_MODEL", "fake-model")
    ran = []
    try:
        for line in lines:
            if line.startswith(SKIP_PREFIX):
                continue
            for a, b in subs.items():
                line = line.replace(a, b)
            if line.startswith("export "):
                name, _, value = line[len("export ") :].split("#")[0].strip().partition("=")
                monkeypatch.setenv(name, value)
                continue
            assert line.startswith("flagwake "), f"{doc}: unexpected command line: {line}"
            argv = shlex.split(line, comments=True)[1:]
            argv = [a.replace("python ", f'"{sys.executable}" ', 1) if a.startswith("python ")
                    else a for a in argv]  # fmt: skip
            stdin = io.StringIO("")
            if argv[0] == "mcp":
                stdin = io.StringIO("\n".join(json.dumps(m) for m in MCP_SESSION) + "\n")
            monkeypatch.setattr(sys, "stdin", stdin)
            if argv[:2] == ["tools", "serve"] and "--stdio" not in argv:
                # would wait for a defender: serve over stdio with nobody connected instead, so it
                # closes every ticket unfinished and still writes a verified report
                argv += ["--stdio", "--seeds", "1", "--out", str(tmp_path / "tools-out")]
            if argv[0] == "view":  # would serve until stopped: check it finds a report instead
                from cyberarena.rc import registry_cli

                monkeypatch.setattr(
                    "cyberarena.rc.serve.serve",
                    lambda port, report, open_browser: 0 if report.is_file() else 1,
                )
                assert registry_cli.latest_report(tmp_path / "flagwake.yaml") is not None
            code = main(argv)
            assert code == 0, f"{doc}: exit {code}: {line}"
            ran.append(argv[0])
    finally:
        fake.close()
        http.shutdown()
    assert ran, doc
