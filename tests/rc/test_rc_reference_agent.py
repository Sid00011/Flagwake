"""The reference model agent, run end to end against a local fake chat-completions server.

No real model and no key: the fake server answers each request from a script (a clean command, a
fenced or chatty reply, an HTTP error, a body that is not JSON, a reply with no command, a reply
slower than the model agent's timeout). The run must finish, verify, and count every bad reply as an
unrecognised command; the caps must stop it; the key must reach only the header.
"""

from __future__ import annotations

import json
import sys
import time

import pytest
from rckit import FakeModel

from cyberarena.rc import model_agent as ref
from cyberarena.rc.protocol import subprocess_driver_factory
from cyberarena.rc.report import build_report
from cyberarena.rc.runner import run_pack
from cyberarena.rc.verify import verify

AGENT = ["-m", "cyberarena.rc.model_agent"]

SPECS = [
    {"family": "cred-reuse", "seed": 120000, "difficulty": "standard"},
    {"family": "quiet", "seed": 120001, "difficulty": "standard"},
]


def _run(monkeypatch, tmp_path, script, *agent_args, specs=SPECS, key=None, extra=None):
    fake = FakeModel(script)
    if extra is None:
        monkeypatch.delenv("FLAGWAKE_LLM_EXTRA_BODY", raising=False)
    else:
        monkeypatch.setenv("FLAGWAKE_LLM_EXTRA_BODY", extra)
    monkeypatch.setenv("FLAGWAKE_LLM_BASE_URL", fake.url)
    monkeypatch.setenv("FLAGWAKE_LLM_MODEL", "fake-model")
    if key:
        monkeypatch.setenv("FLAGWAKE_LLM_KEY", key)
    else:
        monkeypatch.delenv("FLAGWAKE_LLM_KEY", raising=False)
    log = tmp_path / "agent-stderr.log"
    argv = [sys.executable, "-I", *AGENT, *agent_args]
    t0 = time.monotonic()
    try:
        result = run_pack(subprocess_driver_factory(argv, 20.0, str(log)), specs)
    finally:
        fake.close()
    return result, fake, log.read_text(encoding="utf-8"), time.monotonic() - t0


# --------------------------------------------------------------------------- the parser


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        ("look", "look"),
        ("  logs web-01 30  \n", "logs web-01 30"),
        ("```\nlogs ws-ops-01\n```", "logs ws-ops-01"),
        ("```bash\n$ who k.mori\n```", "who k.mori"),
        ("Sure. I'll check first.\n\nCommand: `hosts`", "hosts"),
        ("Next command: **isolate ws-ops-01**", "isolate ws-ops-01"),
        ("1. logs vpn-01\n2. isolate vpn-01", "logs vpn-01"),
        ("I would run `escalate isolate db-02` now.", "escalate isolate db-02"),
        ("I would not isolate web-01 yet.", None),
        ("", None),
        (None, None),
        (
            'Thinking...\nreport {\n  "compromised": ["ws-ops-01"],\n  "summary": "x"\n}',
            'report {"compromised": ["ws-ops-01"], "summary": "x"}',
        ),
        ('```json\nreport {"compromised": []}\n```', 'report {"compromised": []}'),
        ("report not json at all", "report not json at all"),
        ("LOOK", "LOOK"),
    ],
)
def test_parser_picks_the_first_valid_command(reply, expected):
    assert ref.parse_command(reply) == expected


# --------------------------------------------------------------------------- end to end


BAD_SCRIPT = [
    ("ok", "look"),
    ("ok", "```\nhosts\n```"),
    ("http", 500),
    ("raw", b"<html>not json</html>"),
    ("ok", "I am not sure what to do here."),
    ("slow", 3.0),
    ("other", "no choices"),
    ("ok", "Command: `logs ws-ops-01`"),
    ("ok", 'report {"compromised": [], "summary": "done"}'),
]


def test_bad_slow_and_unparseable_replies_are_failed_commands(monkeypatch, tmp_path):
    result, fake, log, seconds = _run(monkeypatch, tmp_path, BAD_SCRIPT, "--timeout", "1")
    assert seconds < 60
    doc = build_report(result, {"id": "reference-agent"}, "practice")
    assert verify(doc) == []
    unrec = doc["metrics"]["cost"]["unrecognised_commands"]
    assert unrec >= 5  # HTTP 500, not JSON, no command, too slow, no choices
    cmds = [c for t in result["transcripts"] for c in t["commands"]]
    assert "(model call failed: HTTP 500)" in cmds
    assert "(model call failed: timeout)" in cmds
    assert "(model call failed: not a chat-completions reply)" in cmds
    assert "(no command in the model reply)" in cmds
    assert "hosts" in cmds and "logs ws-ops-01" in cmds
    usage = doc["agent"]["usage"]
    assert usage["calls"] == len(fake.requests)
    assert "calls" in log and "stopped:" in log  # the per-incident summary
    assert all(r["auth"] is None for r in fake.requests)  # no key, no header
    assert all(r["path"] == "/v1/chat/completions" for r in fake.requests)


def test_call_cap_stops_the_agent(monkeypatch, tmp_path):
    result, fake, log, _s = _run(
        monkeypatch, tmp_path, [("ok", "look")], "--max-calls", "5", specs=SPECS[:1]
    )
    tr = result["transcripts"][0]
    assert tr["commands"] == ["look"] * 5
    assert tr["usage"]["calls"] == 5 and len(fake.requests) == 5
    assert tr["end_reason"] == "unfinished"
    assert "call cap (5) reached" in log


def test_token_budget_stops_the_agent(monkeypatch, tmp_path):
    result, _fake, log, _s = _run(
        monkeypatch, tmp_path, [("ok", "look")], "--token-budget", "300", specs=SPECS[:1]
    )
    assert len(result["transcripts"][0]["commands"]) == 3  # 107 tokens per call
    assert "token budget (300) reached" in log


def test_dead_endpoint_never_hangs(monkeypatch, tmp_path):
    monkeypatch.setenv("FLAGWAKE_LLM_BASE_URL", "http://127.0.0.1:9/v1")  # nothing listens
    monkeypatch.setenv("FLAGWAKE_LLM_MODEL", "fake-model")
    argv = [sys.executable, "-I", *AGENT, "--timeout", "1"]
    t0 = time.monotonic()
    result = run_pack(subprocess_driver_factory(argv, 20.0, str(tmp_path / "e.log")), SPECS)
    assert time.monotonic() - t0 < 60
    for tr in result["transcripts"]:
        assert len(tr["commands"]) == ref.MAX_FAILS_IN_A_ROW
        assert all(c.startswith("(model call failed") for c in tr["commands"])
    assert verify(build_report(result)) == []


def test_key_goes_only_to_the_header(monkeypatch, tmp_path):
    token = "test-token-1234567890"
    result, fake, log, _s = _run(
        monkeypatch, tmp_path, [("ok", 'report {"compromised": []}')], specs=SPECS[1:], key=token
    )
    assert fake.requests and all(r["auth"] == f"Bearer {token}" for r in fake.requests)
    assert token not in log
    assert token not in json.dumps(result)


def test_dry_mode_needs_no_endpoint(monkeypatch, tmp_path):
    monkeypatch.delenv("FLAGWAKE_LLM_BASE_URL", raising=False)
    argv = [sys.executable, "-I", *AGENT, "--dry"]
    result = run_pack(subprocess_driver_factory(argv, 20.0), SPECS[:1])
    assert result["transcripts"][0]["commands"][-1].startswith("report")


def test_extra_body_is_merged_but_cannot_replace_the_core_fields(monkeypatch, tmp_path):
    extra = '{"think": false, "temperature": 1, "model": "other", "options": {"num_ctx": 8192}}'
    _r, fake, _log, _s = _run(
        monkeypatch, tmp_path, [("ok", 'report {"compromised": []}')], specs=SPECS[1:], extra=extra
    )
    body = fake.requests[0]["body"]
    assert body["think"] is False and body["options"] == {"num_ctx": 8192}
    assert (body["model"], body["temperature"]) == ("fake-model", 0)


def test_extra_body_that_is_not_an_object_stops_at_start(monkeypatch):
    from cyberarena.rc import model_agent

    monkeypatch.setenv("FLAGWAKE_LLM_BASE_URL", "http://127.0.0.1:9/v1")
    monkeypatch.setenv("FLAGWAKE_LLM_MODEL", "fake-model")
    monkeypatch.setenv("FLAGWAKE_LLM_EXTRA_BODY", "[1, 2]")
    assert model_agent.main([]) == 2


def test_the_prompt_names_the_ask_topics_and_the_remaining_budget(monkeypatch, tmp_path):
    from cyberarena.rc.engine import ASK_TOPICS

    _r, fake, _log, _s = _run(
        monkeypatch, tmp_path, [("ok", "look"), ("ok", 'report {"compromised": []}')],
        "--max-calls", "7", specs=SPECS[1:],
    )  # fmt: skip
    system = fake.requests[0]["body"]["messages"][0]["content"]
    assert all(t in system for t in ASK_TOPICS)
    lasts = [r["body"]["messages"][-1]["content"] for r in fake.requests]
    assert lasts[0].endswith(
        "[Command 1 of at most 7. At 7 the incident ends without your report.]"
    )
    assert lasts[1].endswith(
        "[Command 2 of at most 7. At 7 the incident ends without your report.]"
    )


def test_notes_list_every_command_with_the_start_of_its_result():
    exchanges = [
        ("OPENING", "hosts"),
        ("Hosts (18)\n web-01     edge   3  up", "logs ws-hr-01 60"),
        ("logs ws-hr-01 · 1 lines\n02:10 ws-hr-01 unknown program", "bogus"),
    ]
    latest = "Unknown command. Commands: look | hosts | logs <host|source>"
    lines = ref.notes(exchanges, latest).split("\n")
    assert lines == [
        ref.NOTES_HEAD,
        "- hosts -> Hosts (18) / web-01 edge 3 up",
        "- logs ws-hr-01 60 -> logs ws-hr-01 · 1 lines / 02:10 ws-hr-01 unknown program",
        "- bogus -> Unknown command.",
    ]
    assert ref.notes([], "anything") == ""


def test_notes_stay_short_and_keep_the_newest_commands():
    long = "x" * 1000
    exchanges = [(long, f"look {i}") for i in range(100)]
    text = ref.notes(exchanges, long)
    assert len(text) <= ref.NOTES_CHARS
    lines = text.split("\n")[1:]
    assert all(len(line) <= len("- look 99 -> ") + ref.NOTE_CHARS for line in lines)
    assert lines[-1].startswith("- look 99 -> ") and not lines[0].startswith("- look 0 ->")


def test_the_prompt_carries_the_notes_of_earlier_commands(monkeypatch, tmp_path):
    _r, fake, _log, _s = _run(
        monkeypatch, tmp_path,
        [("ok", "hosts"), ("ok", "look"), ("ok", 'report {"compromised": []}')],
        specs=SPECS[1:],
    )  # fmt: skip
    lasts = [r["body"]["messages"][-1]["content"] for r in fake.requests]
    assert ref.NOTES_HEAD not in lasts[0]
    assert lasts[2].startswith(ref.NOTES_HEAD + "\n- hosts -> Hosts (")
    assert "\n- look -> " in lasts[2] and "\n\nNow:\n" in lasts[2]


def test_the_prompt_shows_a_report_example_with_confidence():
    assert '"confidence":{"ws-x-01":0.9' in ref.INSTRUCTION
    assert "probability from 0 to 1" in ref.INSTRUCTION


@pytest.mark.parametrize(
    ("body", "confidence"),
    [
        ({"compromised": ["ws-ops-02"], "confidence": 0.8}, {"ws-ops-02": 0.8}),
        ({"compromised": [], "confidence": 0.0}, {}),
        ({"compromised": [], "confidence": {"vpn-01": 70, "web-01": "50%"}},
         {"vpn-01": 0.7, "web-01": 0.5}),
        ({"compromised": [], "confidence": {"ws-fin-01": "low", "db-01": "High"}},
         {"db-01": 0.8, "ws-fin-01": 0.2}),
        ({"compromised": "web-01, db-01",
          "confidence": [{"host": "web-01", "probability": 0.9}, {"name": "db-01", "p": 1}]},
         {"db-01": 1.0, "web-01": 0.9}),
        ({"compromised_hosts": ["db-01"], "probabilities": {"db-01": 0.6}}, {"db-01": 0.6}),
        ({"compromised": [], "confidence": {"severity": "unknown", "web-01": 250}}, {}),
    ],
)  # fmt: skip
def test_common_report_variants_become_the_documented_form(body, confidence):
    line = ref.parse_command("report " + json.dumps(body))
    sent = json.loads(line.split(None, 1)[1])
    assert sent["confidence"] == confidence
    assert isinstance(sent["compromised"], list)
    assert not {"compromised_hosts", "probabilities"} & set(sent)


def test_a_scalar_confidence_is_scored_after_normalising():
    from cyberarena.rc.engine import Shift
    from cyberarena.rc.generator import generate
    from cyberarena.rc.scoring import score_shift

    shift = Shift(generate("cred-reuse", 120000, "standard"))
    shift.reset()
    shift.step(ref.parse_command('report {"compromised": ["ws-ops-02"], "confidence": 0.8}'))
    assert score_shift(shift)["calibration"]["scored"] == "ok"


@pytest.mark.parametrize(
    "reply,expected",
    [
        # a reasoning model's reply: reasoning, then </think>, then the answer
        (
            "Let me look at the logs first.\nisolate the host maybe\n</think>\nlogs ws-ops-03",
            "logs ws-ops-03",
        ),
        ("<think>\nlook around\n</think>\n\nisolate ws-ops-03 60", "isolate ws-ops-03 60"),
        # an opened block that never closes is all reasoning: no command yet
        ("<think>\nlook at the alert, then isolate ws-ops-03", None),
        # a reply with no reasoning block is parsed as before
        ("logs web-01", "logs web-01"),
    ],
)
def test_parser_ignores_a_reasoning_block(reply, expected):
    assert ref.parse_command(reply) == expected


@pytest.mark.parametrize(
    ("url", "safe"),
    [
        ("http://192.168.1.5:8080/v1", False),
        ("http://models.example.com/v1", False),
        ("http://localhost.example.com/v1", False),
        ("https://models.example.com/v1", True),
        ("http://127.0.0.1:8080/v1", True),
        ("http://localhost:8080/v1", True),
        ("http://[::1]:8080/v1", True),
    ],
)
def test_a_key_never_travels_over_plain_http_to_another_machine(url, safe):
    assert (ref.key_transport_problem(url, "k") is None) is safe
    assert ref.key_transport_problem(url, None) is None  # no key, nothing to protect


def test_the_agent_will_not_start_when_its_key_would_travel_in_clear(monkeypatch, capsys):
    monkeypatch.setenv("FLAGWAKE_LLM_BASE_URL", "http://192.168.1.5:8080/v1")
    monkeypatch.setenv("FLAGWAKE_LLM_MODEL", "fake-model")
    monkeypatch.setenv("FLAGWAKE_LLM_KEY", "k")
    monkeypatch.delenv("FLAGWAKE_LLM_EXTRA_BODY", raising=False)
    assert ref.main([]) == 2
    assert "https" in capsys.readouterr().err


# --------------------------------------------------------------------------- the loop, in process


def _talk(monkeypatch, capsys, fake, lines, *argv, key=None):
    """Run the reference program's main loop in this process on the given harness lines;
    return its exit code, its replies and what it wrote to stderr."""
    import io

    monkeypatch.delenv("FLAGWAKE_LLM_EXTRA_BODY", raising=False)
    monkeypatch.setenv("FLAGWAKE_LLM_BASE_URL", fake.url if fake else "")
    monkeypatch.setenv("FLAGWAKE_LLM_MODEL", "fake-model" if fake else "")
    if key:
        monkeypatch.setenv("FLAGWAKE_LLM_KEY", key)
    else:
        monkeypatch.delenv("FLAGWAKE_LLM_KEY", raising=False)
    monkeypatch.setattr(sys, "stdin", io.StringIO("".join(json.dumps(m) + "\n" for m in lines)))
    code = ref.main(list(argv))
    out = capsys.readouterr()
    return code, [json.loads(ln) for ln in out.out.splitlines()], out.err


START = {"type": "start", "incident": "i-0123456789ab", "text": "Incident start.",
         "limits": {"step_seconds": 30}}  # fmt: skip
OBS = {"type": "obs", "text": "nothing new", "t": 3, "done": False}


def test_the_loop_sends_one_command_per_message_and_counts_its_usage(monkeypatch, capsys):
    fake = FakeModel(
        [("ok", "look"), ("ok", "Command: `hosts`"), ("ok", 'report {"compromised": []}')]
    )
    try:
        code, sent, err = _talk(monkeypatch, capsys, fake, [START, OBS, OBS, {"type": "end"}],
                                key="k-test")  # fmt: skip
    finally:
        fake.close()
    assert code == 0
    assert [m["cmd"] for m in sent] == ["look", "hosts", 'report {"compromised": []}']
    assert sent[-1]["usage"]["calls"] == 3 and sent[-1]["usage"]["prompt_tokens"] == 300
    assert "i-0123456789ab" in err and "stopped: end of incident" in err
    assert all(r["auth"] == "Bearer k-test" for r in fake.requests)
    assert "k-test" not in err and all("k-test" not in json.dumps(m) for m in sent)
    # the second request carries the first exchange as notes, then the new observation
    second = fake.requests[1]["body"]["messages"][-1]["content"]
    assert "nothing new" in second and "look" in json.dumps(fake.requests[1]["body"]["messages"])


def test_the_loop_survives_noise_bad_replies_and_a_closed_input(monkeypatch, capsys):
    fake = FakeModel([("ok", "I am not sure what to do."), ("bad", "x"), ("http", 500)])
    try:
        monkeypatch.setattr(sys, "stdin", None)  # replaced by _talk
        code, sent, err = _talk(
            monkeypatch, capsys, fake,
            ["not a message", START, OBS, OBS],  # a stray JSON string, then no end message
        )  # fmt: skip
    finally:
        fake.close()
    assert code == 0
    assert [m["cmd"] for m in sent] == [
        "(no command in the model reply)",
        "(model call failed: not a chat-completions reply)",
        "(model call failed: HTTP 500)",
    ]
    u = sent[-1]["usage"]
    assert (u["calls"], u["failed_calls"], u["no_command"]) == (3, 2, 1)
    assert "stopped: input closed" in err


def test_the_loop_stops_itself_after_too_many_failures_in_a_row(monkeypatch, capsys):
    fake = FakeModel([("http", 503)])
    try:
        lines = [START] + [OBS] * (ref.MAX_FAILS_IN_A_ROW + 2)
        code, sent, err = _talk(monkeypatch, capsys, fake, lines)
    finally:
        fake.close()
    assert code == 0 and sent[-1] == {"stop": True, "usage": sent[-1]["usage"]}
    assert len(sent) == ref.MAX_FAILS_IN_A_ROW + 1
    assert f"{ref.MAX_FAILS_IN_A_ROW} failed replies in a row" in err


def test_the_dry_stub_needs_no_model_and_always_ends_with_a_report(monkeypatch, capsys):
    code, sent, err = _talk(monkeypatch, capsys, None, [START] + [OBS] * 6, "--dry")
    assert code == 0 and "dry stub" in err
    assert [m["cmd"] for m in sent][: len(ref.DRY)] == list(ref.DRY)
    assert sent[-1]["cmd"].startswith("report ") and sent[-1]["usage"]["calls"] == 0


def test_replies_as_content_parts_and_without_usage_are_understood(monkeypatch, capsys):
    parts = {"choices": [{"message": {"content": [{"type": "text", "text": "look"}]}}]}
    fake = FakeModel([("raw", json.dumps(parts).encode())])
    try:
        code, sent, _err = _talk(monkeypatch, capsys, fake, [START, {"type": "end"}])
    finally:
        fake.close()
    assert code == 0 and sent[0]["cmd"] == "look"
    assert sent[0]["usage"]["prompt_tokens"] > 0  # estimated, so the token budget still bites


def test_errors_are_described_without_details():
    import urllib.error

    assert ref._error(TimeoutError()) == "timeout"
    assert ref._error(urllib.error.URLError("refused")) == "cannot connect"
    assert ref._error(KeyError("choices")) == "not a chat-completions reply"
    assert ref._error(RuntimeError("boom")) == "RuntimeError"
