"""Security of the shipped surfaces: hostile text in the HTML report, the localhost server's route
allowlist and path-traversal guard, report-loader robustness, and verify resisting forgery."""

from __future__ import annotations

import copy
import io

import pytest

from cyberarena.rc.html import build_html
from cyberarena.rc.report import build_report, terminal_summary
from cyberarena.rc.runner import build_pack, run_baseline_pack
from cyberarena.rc.verify import verify

HOSTILE = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "</style></head><body>",
    "‮evil‬",  # right-to-left override
    "\x00\x01\x02 control chars",
    "line\nbreak\r\n",
    "{{7*7}} ${7*7} <%= 7*7 %>",
    "x" * 100000,
]


@pytest.fixture(scope="module")
def doc():
    return build_report(run_baseline_pack("careful", build_pack("practice", 2)))


def test_hostile_agent_id_is_escaped(doc):
    for bad in HOSTILE:
        d = copy.deepcopy(doc)
        d["agent"] = {"id": bad}
        page = build_html(d, True)
        # Every angle bracket from the data is escaped: no live tag is created from it.
        assert "<script>alert(1)</script>" not in page
        assert "<img" not in page.lower()
        assert page.lower().count("<script") == 0  # the page carries no script at all


def test_hostile_trace_text_is_escaped(doc):
    d = copy.deepcopy(doc)
    d["traces"] = [
        {
            "title": "<script>x</script>",
            "seed": 1,
            "difficulty": "hard",
            "lines": ["<img src=x onerror=alert(1)>", "‮"],
            "what_would_be_right": "</div><script>",
            "replay": "flagwake replay <script>",
        }
    ]
    page = build_html(d, True)
    assert "<script>x</script>" not in page
    assert "<img" not in page.lower()
    assert "</div><script>" not in page


def test_terminal_summary_handles_hostile_text(doc):
    for bad in HOSTILE:
        d = copy.deepcopy(doc)
        d["agent"] = {"id": bad}
        text = terminal_summary(d, True)  # must not raise
        assert isinstance(text, str)


def test_html_has_strict_csp_and_no_external_refs(doc):
    page = build_html(doc, True)
    assert "Content-Security-Policy" in page and "default-src 'none'" in page
    assert "http://" not in page and "https://" not in page  # no external resource
    assert "<script" not in page.lower()  # no script at all


# --------------------------------------------------------------------------- serve


def test_serve_allowlist_and_traversal():
    from cyberarena.rc.serve import ALLOW, Handler

    class FakeHandler(Handler):
        def __init__(self, path):  # bypass socket setup
            self.path = path
            self.sent = {}
            self.headers_sent = []
            self.wfile = io.BytesIO()

        def send_response(self, code):
            self.sent["code"] = code

        def send_error(self, code, msg=None):
            self.sent["code"] = code

        def send_header(self, k, v):
            self.headers_sent.append((k, v))

        def end_headers(self):
            pass

    for bad in [
        "/../pyproject.toml",
        "/..%2f..%2fetc/passwd",
        "/js/../../serve.py",
        "/data/../../../world.json",
        "/nope.html",
        "/etc/passwd",
    ]:
        h = FakeHandler(bad)
        h.do_GET()
        assert h.sent.get("code") == 404, bad
    # A real allowlisted path serves 200 with the strict CSP header.
    h = FakeHandler("/js/viewer.js")
    h.do_GET()
    assert h.sent.get("code") == 200
    csp = dict(h.headers_sent).get("Content-Security-Policy", "")
    assert "default-src 'none'" in csp
    assert "/" in ALLOW and ALLOW["/"] == "viewer.html"
    assert "/index.html" not in ALLOW


# --------------------------------------------------------------------------- loader / verify


def test_verify_rejects_garbage():
    assert verify({"schema": "not-ours"})
    assert verify("a string")
    assert verify([1, 2, 3])
    assert verify({"schema": "flagwake-rc-report-1"})  # missing everything


def test_forged_report_cannot_pass(doc):
    # Keep the numbers but swap in commands that would have scored differently: verify must fail.
    d = copy.deepcopy(doc)
    for inc in d["incidents"]:
        inc["commands"] = ["look", 'report {"compromised": []}']
    assert verify(d)


def test_hostile_agent_output_never_becomes_markup():
    """Everything an agent controls (commands, report text, usage keys) stays inert text."""
    from cyberarena.rc.protocol import clean_usage
    from cyberarena.rc.runner import run_pack, text_driver

    bad = "<script>alert(1)</script><img src=x onerror=alert(1)>"
    cmds = iter([bad, "logs " + bad, "report " + '{"summary": "' + bad + '"}'])
    res = run_pack(
        lambda: text_driver(lambda _obs: next(cmds, None)), build_pack("practice", 1)[:1]
    )
    res["transcripts"][0]["usage"] = clean_usage({bad: 1, "calls": 2})
    d = build_report(res, {"id": bad})
    page = build_html(d, True)
    assert "<script" not in page.lower() and "<img" not in page.lower()
    assert "&lt;script&gt;" in page  # the usage key and agent id are shown, escaped
    terminal_summary(d, True).encode("ascii")  # plain text, never raises


def test_shipped_programs_are_labelled_as_scripted(doc):
    d = copy.deepcopy(doc)
    d["agent"] = {"id": "baseline:careful"}
    assert "a scripted example program shipped with the tool" in build_html(d, True)
    assert "(scripted example program)" in terminal_summary(d, True)
