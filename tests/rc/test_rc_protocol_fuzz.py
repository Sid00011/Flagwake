"""Protocol fuzzing: misbehaving agents end their own incident, never the harness or the run.

Each agent below is a tiny child process: malformed JSON, wrong shapes, a huge line, a silent
agent, an agent that floods output without reading its input, one that exits at once. Every run
must finish within a bound, keep going to the next incident, record what went wrong, and still
produce a report that verifies.
"""

from __future__ import annotations

import sys
import time

import pytest

from cyberarena.rc.protocol import (
    INVALID_REPLY,
    MAX_BAD_LINES,
    ProtocolError,
    http_driver_factory,
    incident_label,
    subprocess_driver_factory,
)
from cyberarena.rc.report import build_report
from cyberarena.rc.runner import run_pack
from cyberarena.rc.verify import verify

KEY = "f022" * 8  # a fixed run key, so the test knows the name the program receives
SPECS = [
    {"family": "quiet", "seed": 120000, "difficulty": "standard"},
    {"family": "cred-reuse", "seed": 120001, "difficulty": "standard"},
]
LOOP = "import sys,json\nfor line in sys.stdin:\n    m=json.loads(line)\n"


def _run(code: str, step: float = 2.0, specs=SPECS):
    argv = [sys.executable, "-I", "-c", code]
    t0 = time.monotonic()
    result = run_pack(subprocess_driver_factory(argv, step), specs, key=KEY)
    seconds = time.monotonic() - t0
    doc = build_report(result, {"id": "fuzz"}, "practice")
    assert verify(doc) == []
    return result, doc, seconds


REPLIES = {
    "not json": "print('not json at all', flush=True)",
    "a list": "print('[1, 2]', flush=True)",
    "a number cmd": "print('{\"cmd\": 5}', flush=True)",
    "no cmd": 'print(\'{"command": "look"}\', flush=True)',
    "broken utf-8": "sys.stdout.buffer.write(b'\\xff\\xfe{\\n'); sys.stdout.flush()",
}


@pytest.mark.parametrize("name", sorted(REPLIES))
def test_malformed_replies_are_invalid_commands(name):
    code = LOOP + "    if m.get('type')=='end': break\n    " + REPLIES[name] + "\n"
    result, doc, seconds = _run(code)
    assert seconds < 30
    for tr in result["transcripts"]:
        assert tr["commands"] == [INVALID_REPLY] * MAX_BAD_LINES
        assert tr["harness"]["invalid_replies"] == MAX_BAD_LINES + 1
        assert "invalid replies" in tr["harness"]["error"]
    assert doc["metrics"]["cost"]["unrecognised_commands"] == 2 * MAX_BAD_LINES
    assert doc["harness"]["incidents_with_errors"] == 2


def test_huge_line_is_bounded():
    code = LOOP + "    sys.stdout.write('x' * 3_000_000 + '\\n'); sys.stdout.flush()\n"
    result, _doc, seconds = _run(code, step=5.0)
    assert seconds < 60
    for tr in result["transcripts"]:
        assert set(tr["commands"]) == {INVALID_REPLY}
        assert tr["harness"]["error"]


def test_silent_agent_ends_its_incident_and_the_run_goes_on():
    code = "import time\ntime.sleep(60)\n"
    result, doc, seconds = _run(code, step=1.0)
    assert seconds < 20
    for tr in result["transcripts"]:
        assert tr["commands"] == []
        assert tr["harness"]["error"] == "no answer within 1s"
    assert doc["harness"]["errors"] == {"no answer within 1s": 2}


def test_flooding_agent_that_never_reads_is_bounded():
    code = 'import sys\nwhile True:\n    sys.stdout.write(\'{"cmd": "look"}\\n\')\n'
    result, _doc, seconds = _run(code, step=1.0)
    assert seconds < 30
    for tr in result["transcripts"]:
        assert tr["end_reason"] in ("commands", "unfinished")


def test_one_slow_answer_ends_only_that_incident():
    slow = incident_label("cred-reuse", 120001, "standard", key=KEY)  # what the program gets
    code = (
        LOOP + "    if m.get('type')=='end': break\n"
        f"    if '{slow}' in m.get('incident',''): import time; time.sleep(5)\n"
        "    print(json.dumps({'cmd': 'report {\"compromised\": []}'}), flush=True)\n"
    )
    result, _doc, _s = _run(code, step=1.0)
    quiet, cred = result["transcripts"]
    assert quiet["commands"][0].startswith("report") and "harness" not in quiet
    assert cred["harness"]["error"] == "no answer within 1s"


def test_stop_message_ends_the_incident_cleanly():
    code = LOOP + '    print(\'{"stop": true, "usage": {"calls": 2}}\', flush=True)\n'
    result, doc, _s = _run(code)
    for tr in result["transcripts"]:
        assert tr["commands"] == [] and "harness" not in tr
        assert tr["usage"] == {"calls": 2}
    assert doc["agent"]["usage"]["calls"] == 4


def test_agent_that_cannot_start_stops_the_run_with_a_clear_error():
    with pytest.raises(ProtocolError, match="exited with code 3 before sending a command"):
        _run("import sys\nsys.exit(3)\n")


def test_repeated_failures_stop_the_run():
    code = "import time\ntime.sleep(60)\n"
    specs = [{"family": "quiet", "seed": 120000 + i, "difficulty": "standard"} for i in range(6)]
    t0 = time.monotonic()
    with pytest.raises(ProtocolError, match="3 incidents in a row"):
        run_pack(subprocess_driver_factory([sys.executable, "-I", "-c", code], 1.0), specs)
    assert time.monotonic() - t0 < 20


def test_http_endpoint_that_is_not_running_is_a_clear_error():
    with pytest.raises(ProtocolError, match="nothing answered"):
        run_pack(http_driver_factory("http://127.0.0.1:9/act", 2.0), SPECS[:1])
