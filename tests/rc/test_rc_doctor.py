"""`flagwake doctor` against a local fake model server and small scripted agents.

Each case must finish well within a minute and name the likely fix in plain words.
"""

from __future__ import annotations

import argparse
import io
import sys
import time

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
