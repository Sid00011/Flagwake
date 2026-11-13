"""`flagwake doctor` against a local fake model server and small scripted agents.

Each case must finish well within a minute and name the likely fix in plain words.
"""

from __future__ import annotations

import argparse
import io
import sys
import time
import urllib.error

import pytest
from rckit import FakeModel

from cyberarena.rc.doctor import doctor

GOOD = [("ok", "Command: `logs ws-ops-01`"), ("ok", 'report {"compromised": []}')]


def _doctor(monkeypatch, script=None, url=None, key=None, agent=None, timeout=40.0):
    fake = FakeModel(script) if script else None
    for k in ("FLAGWAKE_LLM_BASE_URL", "FLAGWAKE_LLM_MODEL", "FLAGWAKE_LLM_KEY"):
        monkeypatch.delenv(k, raising=False)
    if fake or url:
        monkeypatch.setenv("FLAGWAKE_LLM_BASE_URL", url or fake.url)
        monkeypatch.setenv("FLAGWAKE_LLM_MODEL", "fake-model")
    if key:
        monkeypatch.setenv("FLAGWAKE_LLM_KEY", key)
    out = io.StringIO()
    t0 = time.monotonic()
    try:
        code = doctor(argparse.Namespace(agent=agent, http=None, timeout=timeout), out)
    finally:
        if fake:
            fake.close()
    seconds = time.monotonic() - t0
    assert seconds < 60, seconds
    return code, out.getvalue(), fake


def test_a_working_endpoint_passes(monkeypatch):
    code, text, fake = _doctor(monkeypatch, GOOD)
    assert code == 0, text
    assert "PASS  endpoint reachable" in text and "the report verifies" in text
    assert "All checks passed." in text
    assert all(r["auth"] is None for r in fake.requests)


def test_missing_settings_say_what_to_set(monkeypatch):
    code, text, _ = _doctor(monkeypatch)
    assert code == 1 and "FLAGWAKE_LLM_BASE_URL or FLAGWAKE_LLM_MODEL is not set" in text


def test_unreachable_endpoint(monkeypatch):
    code, text, _ = _doctor(monkeypatch, url="http://127.0.0.1:9/v1", timeout=3)
    assert code == 1
    assert "endpoint unreachable" in text or "too slow" in text  # a closed port may not answer
    assert "fix:" in text


def test_missing_key(monkeypatch):
    code, text, _ = _doctor(monkeypatch, [("http", 401)])
    assert code == 1 and "the endpoint wants a key" in text and "FLAGWAKE_LLM_KEY" in text


def test_refused_key_is_never_printed(monkeypatch):
    code, text, fake = _doctor(monkeypatch, [("http", 403)], key="test-token-abcdef")
    assert code == 1 and "refused the key" in text and "test-token-abcdef" not in text
    assert fake.requests[0]["auth"] == "Bearer test-token-abcdef"


def test_wrong_path(monkeypatch):
    code, text, _ = _doctor(monkeypatch, [("http", 404)])
    assert code == 1 and "HTTP 404" in text and "/v1" in text


def test_not_chat_completions(monkeypatch):
    code, text, _ = _doctor(monkeypatch, [("raw", b"<html>hello</html>")])
    assert code == 1 and "not chat-completions JSON" in text


def test_unparseable_replies(monkeypatch):
    code, text, _ = _doctor(monkeypatch, [("ok", "look"), ("ok", "I am not sure what to do.")])
    assert code == 1 and "replies unparseable" in text and "only the command" in text


def test_too_slow(monkeypatch):
    code, text, _ = _doctor(monkeypatch, [("slow", 4.0)], timeout=2)
    assert code == 1 and "too slow" in text


AGENT_OK = (
    "import sys,json\n"
    "for line in sys.stdin:\n"
    "    m=json.loads(line)\n"
    "    if m.get('type')=='end': break\n"
    "    print(json.dumps({'cmd': 'report {\"compromised\": []}'}), flush=True)\n"
)
AGENT_GARBAGE = "import sys\nfor line in sys.stdin:\n    print('hello', flush=True)\n"


def _agent_file(tmp_path, code):
    f = tmp_path / "agent.py"
    f.write_text(code, encoding="utf-8")
    return f'"{sys.executable}" -I "{f}"'


def test_an_agent_command_is_checked(monkeypatch, tmp_path):
    agent = _agent_file(tmp_path, AGENT_OK)
    code, text, _ = _doctor(monkeypatch, agent=agent)
    assert code == 0, text
    assert "every command was understood" in text


@pytest.mark.parametrize(
    ("code_text", "expect"),
    [
        (AGENT_GARBAGE, "replies unparseable"),
        ("import sys\nsys.exit(3)\n", "could not be run"),
    ],
)
def test_a_broken_agent_gets_a_plain_diagnosis(monkeypatch, tmp_path, code_text, expect):
    agent = _agent_file(tmp_path, code_text)
    code, text, _ = _doctor(monkeypatch, agent=agent)
    assert code == 1 and expect in text, text


def _redirecting_pair():
    """Server A answers every POST with a redirect to server B; B records Authorization."""
    import http.server
    import threading

    seen: list[str] = []

    class B(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def _any(self):
            seen.append(self.headers.get("Authorization", ""))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        do_GET = do_POST = _any  # noqa: N815

    b = http.server.ThreadingHTTPServer(("127.0.0.1", 0), B)
    target = f"http://127.0.0.1:{b.server_address[1]}/stolen"

    class A(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()

    a = http.server.ThreadingHTTPServer(("127.0.0.1", 0), A)
    for s in (a, b):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{a.server_address[1]}/v1", seen, (a, b)


def test_a_redirect_never_carries_the_key_elsewhere(monkeypatch):
    from cyberarena.rc.doctor import probe_endpoint
    from cyberarena.rc.model_agent import Model

    base, seen, servers = _redirecting_pair()
    try:
        level, what, _fix, _t = probe_endpoint(base, "m", "test-token-redirect", 5.0)
        assert level == "FAIL" and "redirected" in what
        monkeypatch.setenv("FLAGWAKE_LLM_BASE_URL", base)
        monkeypatch.setenv("FLAGWAKE_LLM_MODEL", "m")
        monkeypatch.setenv("FLAGWAKE_LLM_KEY", "test-token-redirect")
        monkeypatch.delenv("FLAGWAKE_LLM_EXTRA_BODY", raising=False)
        model = Model(argparse.Namespace(max_tokens=16))
        with pytest.raises(urllib.error.HTTPError):  # a 302 is an error, never a hop elsewhere
            model.ask([{"role": "user", "content": "hi"}], 5.0)
        assert not any("REDIRECT" in a for a in seen), seen
    finally:
        for s in servers:
            s.shutdown()
            s.server_close()


def test_doctor_never_sends_a_key_over_plain_http_to_another_machine(monkeypatch):
    import cyberarena.rc.doctor as d

    calls = []
    monkeypatch.setattr(d, "probe_endpoint", lambda *a, **k: calls.append(a) or ("PASS", "", "", 0))
    code, text, _ = _doctor(monkeypatch, url="http://remote.example/v1", key="test-token-plain")
    assert code == 1 and calls == []
    assert "refusing to send the key" in text and "test-token-plain" not in text
