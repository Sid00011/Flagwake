"""A defender whose replies carry no command (a reasoning model cut off by its reply limit, an
endpoint that fails) gets a result that says it measures the connection, not its decisions, with
the likely fix; a working defender never does. The page's model settings reach the registry."""

from __future__ import annotations

import argparse
import io
import json
import sys

import pytest
from rckit import FakeModel
from test_rc_ui import page  # noqa: F401 (the running-page fixture)

from cyberarena.rc import registry as reg
from cyberarena.rc.doctor import doctor
from cyberarena.rc.protocol import subprocess_driver_factory
from cyberarena.rc.report import build_report, header_notes, measurement_problem, terminal_summary
from cyberarena.rc.runner import baseline_driver, pack_specs, run_pack
from cyberarena.rc.ui_text import plain_result

# A defender that never gets a command out of its model, and says why in its usage.
SILENT = (
    "import json, sys\n"
    "n = 0\n"
    "for line in sys.stdin:\n"
    "    m = json.loads(line)\n"
    "    if m.get('type') == 'end': break\n"
    "    n += 1\n"
    "    usage = {'calls': 2 * n, 'failed_calls': 0, 'no_command': n, CUT}\n"
    "    reply = {'cmd': '(no command in the model reply)', 'usage': usage}\n"
    "    print(json.dumps(reply), flush=True)\n"
)


def _silent_report(cut: bool) -> dict:
    code = SILENT.replace("CUT", "'cut_off': n" if cut else "'prompt_tokens': 1")
    specs = pack_specs("practice", 1)[:3]
    result = run_pack(subprocess_driver_factory([sys.executable, "-c", code]), specs)
    return build_report(result, {"id": "silent"}, pack_name="custom")


@pytest.mark.parametrize("cut", [True, False])
def test_a_result_without_commands_says_it_measures_the_connection(cut):
    doc = _silent_report(cut)
    problem = measurement_problem(doc)
    assert problem and problem.startswith("Not a measurement of the defender's decisions")
    if cut:
        assert "cut off by the reply limit" in problem and "reasoning effort" in problem
    else:
        assert "flagwake doctor" in problem and "cut off" not in problem
    assert header_notes(doc)[0] == "WARNING: " + problem  # the first line of report.html
    assert "WARNING: Not a measurement" in terminal_summary(doc, True)
    page_text = plain_result(doc)
    assert page_text["verdict"] == "Not a measurement of the defender"
    assert page_text["problem"] == problem == page_text["headline"]
    assert page_text["tone"] == "none"


def test_a_working_defender_never_gets_the_warning():
    specs = pack_specs("practice", 1)
    for name in ("careful", "gullible", "do-nothing"):
        result = run_pack(lambda name=name: baseline_driver(name), specs)
        doc = build_report(result, {"id": f"baseline:{name}"}, pack_name="practice")
        assert measurement_problem(doc) is None, name
        assert plain_result(doc)["problem"] is None
        assert not any(n.startswith("WARNING: Not a") for n in header_notes(doc))


def test_doctor_names_a_reply_limit_that_cuts_the_model_off(monkeypatch):
    fake = FakeModel([("cut", None)])
    for k in ("FLAGWAKE_LLM_BASE_URL", "FLAGWAKE_LLM_MODEL", "FLAGWAKE_LLM_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("FLAGWAKE_LLM_BASE_URL", fake.url)
    monkeypatch.setenv("FLAGWAKE_LLM_MODEL", "fake-model")
    out = io.StringIO()
    try:
        code = doctor(argparse.Namespace(agent=None, http=None, timeout=40.0), out)
    finally:
        fake.close()
    text = out.getvalue()
    assert code == 1
    assert "cut off by the reply limit" in text and "FLAGWAKE_LLM_MAX_TOKENS" in text
    assert "only the command" not in text  # not the advice for a model that rambles


def test_the_page_passes_a_reply_limit_and_extra_fields_to_the_registry(page):  # noqa: F811
    app, call, _wait, fake, tmp = page
    body = {"name": "thinker", "kind": "model-endpoint", "base_url": fake.url,
            "model": "tiny-model", "max_tokens": 8192, "requests_per_minute": 14,
            "extra_body": '{"reasoning_effort": "low"}'}  # fmt: skip
    status, payload, _h = call("POST", "/api/defenders", body)
    assert status == 200, payload
    entry = next(e for e in reg.load(tmp / "flagwake.yaml")["defenders"] if e["name"] == "thinker")
    assert entry["caps"]["max_tokens"] == 8192
    assert entry["extra_body"] == {"reasoning_effort": "low"}
    argv = reg.model_argv(entry)  # what the reference model agent is started with
    assert argv[argv.index("--max-tokens") + 1] == "8192"
    assert argv[argv.index("--rpm") + 1] == "14"  # the pace reaches the model program


@pytest.mark.parametrize(
    ("field", "value", "said"),
    [
        ("max_tokens", 0, "between 1 and 100000"),
        ("max_tokens", 2.5, "whole number"),
        ("max_tokens", "many", "whole number"),
        ("requests_per_minute", 0, "between 1 and 100000"),
        ("requests_per_minute", 1.5, "whole number"),
        ("extra_body", "reasoning low", "JSON object"),
        ("extra_body", "[1, 2]", "JSON object"),
        ("extra_body", '{"model": "other"}', ""),  # the registry refuses reserved fields
    ],
)
def test_the_page_refuses_unusable_model_settings(page, field, value, said):  # noqa: F811
    _app, call, _wait, fake, _tmp = page
    body = {"name": "bad", "kind": "model-endpoint", "base_url": fake.url, "model": "tiny-model",
            field: value}  # fmt: skip
    status, payload, _h = call("POST", "/api/defenders", body)
    assert status == 400, payload
    assert said in json.dumps(payload)
