"""Every way a model connection can fail is named apart, in the provider's own words, with its fix,
for any provider and any model; and the reference agent adapts once to common API differences."""

from __future__ import annotations

import argparse
import io
import json

import pytest
from rckit import FakeModel
from test_rc_reference_agent import OBS, START, _talk

from cyberarena.rc.connection import diagnose
from cyberarena.rc.doctor import doctor
from cyberarena.rc.ui_text import plain_checks

# ------------------------------------------------------------------------- the diagnosis itself


@pytest.mark.parametrize(
    ("line", "main", "connection"),
    [
        ("(model call failed: HTTP 429: Rate limit reached for tokens per day)", "quota", True),
        ("(model call failed: HTTP 401: Invalid API Key)", "key", True),
        ("(model call failed: HTTP 403)", "key", True),
        ("(model call failed: HTTP 404: The model `old-model` does not exist)", "missing", True),
        ("(model call failed: HTTP 400: max_tokens is too large)", "rejected", True),
        ("(model call failed: HTTP 413: Request too large)", "rejected", True),
        ("(model call failed: HTTP 503)", "provider_error", True),
        ("(model call failed: timeout)", "timeout", True),
        ("(model call failed: cannot connect)", "unreachable", True),
        ("(no command in the model reply: cut off by the reply limit)", "cut_off", True),
        ("(no command in the model reply: blocked by the provider's content filter)",
         "filtered", True),
        ("(no command in the model reply: the model refused: I can't help with that)",
         "refused", False),
        ("(no command in the model reply)", "unreadable", False),
        ("(invalid reply)", "unreadable", False),
    ],
)  # fmt: skip
def test_each_line_names_its_cause(line, main, connection):
    diag = diagnose(["look", line, line])
    assert diag["main"] == main and diag["connection"] is connection
    assert diag["empty"] == 2 and "Fix:" in diag["text"]


def test_a_run_of_real_commands_has_no_diagnosis():
    assert diagnose(["look", "logs web-01", 'report {"compromised": []}']) is None


def test_the_providers_words_are_quoted():
    diag = diagnose(["(model call failed: HTTP 404: The model `old-model` does not exist)"])
    assert "The model `old-model` does not exist" in diag["text"]
    assert "retire" in diag["text"]  # the fix says old models get retired


def test_reports_written_before_the_reason_was_in_the_line_still_say_cut_off():
    diag = diagnose(["(no command in the model reply)"] * 3, {"cut_off": 3})
    assert diag["main"] == "cut_off"


def test_a_quota_says_how_long_the_provider_asked_to_wait():
    diag = diagnose(["(model call failed: HTTP 429)"], {"rate_limited": 4, "waited_seconds": 61.5})
    assert "4 answers asked to wait, 62 s in all" in diag["text"]


# ------------------------------------------------------------------------- the reference agent


def test_a_failed_call_keeps_the_providers_words_and_masks_the_key(monkeypatch, capsys):
    key = "sk-test-abcdefghijklmnopqrstuvwxyz0123"  # hygiene-ok: fake key for this test
    fake = FakeModel([("error", (404, f"The model `old-model` does not exist (key {key})"))])
    try:
        code, sent, _err = _talk(monkeypatch, capsys, fake, [START, {"type": "end"}], key=key)
    finally:
        fake.close()
    cmd = sent[0]["cmd"]
    assert code == 0 and cmd.startswith("(model call failed: HTTP 404: The model `old-model`")
    assert key not in cmd and "***" in cmd


def test_a_server_that_wants_other_fields_is_asked_its_way(monkeypatch, capsys):
    fake = FakeModel([("strict", "look")])
    try:
        code, sent, err = _talk(monkeypatch, capsys, fake, [START, OBS, {"type": "end"}])
    finally:
        fake.close()
    assert code == 0 and [m["cmd"] for m in sent] == ["look", "look"]
    first, *_rest, last = [r["body"] for r in fake.requests]
    assert "max_tokens" in first and "temperature" in first
    assert "max_completion_tokens" in last and "max_tokens" not in last
    assert "temperature" not in last
    assert len(fake.requests) == 4  # two adaptations, then each command asked once
    assert "adapted to the endpoint: max_completion_tokens, its default temperature" in err


def test_a_model_with_a_smaller_reply_limit_gets_a_smaller_limit(monkeypatch, capsys):
    fake = FakeModel([("cap", (1500, "look"))])
    try:
        code, sent, err = _talk(monkeypatch, capsys, fake, [START, {"type": "end"}])
    finally:
        fake.close()
    assert code == 0 and sent[0]["cmd"] == "look"
    assert [r["body"]["max_tokens"] for r in fake.requests] == [4096, 2048, 1024]
    assert "reply limit 1024" in err


@pytest.mark.parametrize(
    ("kind", "arg", "why"),
    [
        ("filter", None, "blocked by the provider's content filter"),
        ("refuse", "I can't help with that request.", "the model refused: I can't help"),
    ],
)
def test_a_filtered_or_refused_reply_says_so(monkeypatch, capsys, kind, arg, why):
    fake = FakeModel([(kind, arg)])
    try:
        code, sent, _err = _talk(monkeypatch, capsys, fake, [START, {"type": "end"}])
    finally:
        fake.close()
    cmd = sent[0]["cmd"]
    assert code == 0 and cmd.startswith("(no command in the model reply: " + why)
    assert sent[0]["usage"]["failed_calls"] == 0  # an answer without a command, not a failure


# ------------------------------------------------------------------------- doctor and the page


def _doctor(monkeypatch, script, key="test-token-abcdef"):
    fake = FakeModel(script)
    for k in ("FLAGWAKE_LLM_BASE_URL", "FLAGWAKE_LLM_MODEL", "FLAGWAKE_LLM_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("FLAGWAKE_LLM_BASE_URL", fake.url)
    monkeypatch.setenv("FLAGWAKE_LLM_MODEL", "fake-model")
    monkeypatch.setenv("FLAGWAKE_LLM_KEY", key)
    out = io.StringIO()
    try:
        code = doctor(argparse.Namespace(agent=None, http=None, timeout=40.0), out)
    finally:
        fake.close()
    return code, out.getvalue()


@pytest.mark.parametrize(
    ("status", "message", "said"),
    [
        (429, "Rate limit reached for tokens per day", "refuses requests for now (HTTP 429"),
        (404, "The model `old-model` does not exist", "no such model or API at this address"),
        (400, "Unknown field 'foo'", "the endpoint answered HTTP 400: Unknown field"),
    ],
)
def test_doctor_quotes_the_provider(monkeypatch, status, message, said):
    code, text = _doctor(monkeypatch, [("error", (status, message))])
    assert code == 1 and said in text and message[:20] in text
    assert "test-token-abcdef" not in text


def test_doctor_explains_an_empty_first_reply(monkeypatch):
    code, text = _doctor(monkeypatch, [("ok", ""), ("ok", "Command: `logs ws-ops-01`"),
                                       ("ok", 'report {"compromised": []}')])  # fmt: skip
    assert "an empty reply, normal for a model that reasons first" in text
    assert "Running 3 short incidents" in text


def test_the_page_does_not_blame_the_model_for_the_provider():
    conn = diagnose(["(model call failed: HTTP 429: Rate limit reached for tokens per day)"] * 3)
    result = {"status": "failed", "passed": 4, "total": 7, "connection": conn, "checks": [
        {"id": "protocol", "name": "p", "passed": True, "detail": ""},
        {"id": "valid_commands", "name": "v", "passed": False, "detail": "", "cause": "connection"},
        {"id": "report", "name": "r", "passed": False, "detail": "", "cause": "connection"},
        {"id": "malformed", "name": "m", "passed": False, "detail": "", "cause": "connection"},
    ]}  # fmt: skip
    texts = [c["text"] for c in plain_checks(result) if not c["passed"]]
    assert texts[0].startswith("Not about the model's decisions.") and "rate limit" in texts[0]
    assert (
        texts[1] == texts[2] == "Same cause as above: the provider or the settings, not the model."
    )
    assert not any("follows instructions" in t for t in texts)


def test_the_connection_check_names_a_quota_that_runs_out(tmp_path):
    from cyberarena.rc.conformance import run_conformance
    from cyberarena.rc.registry import driver_factory

    quota = ("error", (429, "Rate limit reached for tokens per day"))
    fake = FakeModel([("ok", "look"), ("ok", 'report {"compromised": []}')] * 4 + [quota] * 200)
    entry = {"name": "m", "kind": "model-endpoint", "role": "defender", "base_url": fake.url,
             "model": "fake-model", "caps": {"step_timeout": 10}}  # fmt: skip
    try:
        result = run_conformance(entry, driver_factory(entry, tmp_path, tmp_path / "log"))
    finally:
        fake.close()
    assert result["connection"]["main"] == "quota"
    failed = [c for c in result["checks"] if not c["passed"]]
    assert failed and all(c.get("cause") == "connection" for c in failed if c["id"] != "no_hang")
    assert json.loads(json.dumps(result)) == result  # stored as it is in a report
