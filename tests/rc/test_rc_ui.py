"""The local page's server: detection, estimates, progress, one job at a time, and its defences
(Host, token, Origin, JSON only, size limits, no CORS, commands off by default, keys never
written)."""

from __future__ import annotations

import http.client
import json
import sys
import threading
import time

import pytest
from uikit import FakeServer

from cyberarena.rc import ui
from cyberarena.rc.runner import baseline_driver, run_pack
from cyberarena.rc.ui_text import headline, plain_checks

KEY = "sk-test-SECRET-7f3a9c"  # hygiene-ok: fake key, must never reach a page or file


@pytest.fixture
def page(tmp_path):
    """A running page (no browser) and a helper to call it."""
    fake = FakeServer(models=("tiny-model", "<script>alert(1)</script>"), key=KEY)
    app = ui.App(tmp_path / "flagwake.yaml", detect_ports=(fake.port,))
    server = ui.make_server(app, 0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def call(method, path, body=None, headers=None, token=True, origin=True, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        h = {"Host": host or f"127.0.0.1:{port}"}
        if token:
            h[ui.TOKEN_HEADER] = app.token
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        if origin and method == "POST":
            h["Origin"] = f"http://127.0.0.1:{port}"
        h.update(headers or {})
        conn.request(method, path, body=data, headers=h)
        r = conn.getresponse()
        raw = r.read()
        conn.close()
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = raw
        return r.status, payload, dict(r.getheaders())

    def wait_job():
        for _ in range(600):
            job = call("GET", "/api/state")[1]["job"]
            if job and job["status"] != "running":
                return job
            time.sleep(0.1)
        raise AssertionError("the job did not finish")

    call.port = port
    yield app, call, wait_job, fake, tmp_path
    server.shutdown()
    server.server_close()
    fake.close()


# --------------------------------------------------------------------------- logic


def test_detection_lists_models_of_a_local_server_and_nothing_when_none():
    fake = FakeServer(models=("b-model", "a-model"))
    try:
        found = ui.detect((fake.port,))
        assert found == [{"base_url": fake.url, "models": ["a-model", "b-model"]}]
    finally:
        fake.close()
    assert ui.detect((fake.port,), timeout=0.2) == []  # closed now


def test_time_estimates_and_remaining_time():
    assert ui.estimate_seconds(None, 12) is None
    assert ui.estimate_seconds(10.0, 12) == round(10 * 12 * 1.15 + 2, 1)
    assert ui.remaining(30.0, 3, 12, None) == 90.0  # the pace so far
    assert ui.remaining(5.0, 0, 12, 10.0) == 115.0  # the probe, before the first incident
    assert ui.remaining(5.0, 0, 12, None) is None
    assert ui.remaining(50.0, 12, 12, 1.0) == 0.0


def test_run_pack_reports_progress_and_stops_between_incidents():
    from cyberarena.rc.packs import build_pack

    seen = []
    specs = build_pack("practice", per_family=1)
    res = run_pack(
        lambda: baseline_driver("careful"),
        specs,
        progress=lambda d, t: seen.append((d, t)),
        stop=lambda: len(seen) >= 3,
    )
    assert seen == [(1, 12), (2, 12), (3, 12)]
    assert res["stopped"] is True and len(res["outcomes"]) == 3


def test_plain_words():
    checks = plain_checks({"status": "failed", "checks": [
        {"id": "valid_commands", "name": "x", "passed": False, "detail": "2 of 9"},
        {"id": "protocol", "name": "y", "passed": False, "detail": "could not be run: refused"},
    ]})  # fmt: skip
    assert "follows instructions better" in checks[0]["text"]
    assert "could not be reached" in checks[1]["text"]
    doc = {"metrics": {"incidents": 12, "damage_index": {"mean_clipped": 101.0}}}
    assert "about the same as doing nothing" in headline(doc)


# --------------------------------------------------------------------------- defences


def test_wrong_host_is_refused(page):
    _app, call, *_ = page
    assert call("GET", "/", host="evil.example")[0] == 421
    assert call("GET", "/api/state", host="attacker.test:80")[0] == 421


def test_missing_or_wrong_token_is_refused(page):
    _app, call, *_ = page
    assert call("GET", "/api/state", token=False)[0] == 403
    assert call("GET", "/api/state", headers={ui.TOKEN_HEADER: "guess"})[0] == 403
    assert call("GET", "/")[0] == 200  # the page itself needs no token


def test_an_absolute_request_target_cannot_skip_the_token(page):
    app, call, *_ = page
    base = f"http://127.0.0.1:{call.port}"
    assert call("GET", base + "/api/state", token=False)[0] == 400
    body = {"name": "x1", "kind": "http", "url": "http://127.0.0.1:9/act"}
    assert call("POST", base + "/api/defenders", body, token=False)[0] == 400
    assert "x1" not in (app.path.read_text() if app.path.exists() else "")


def test_a_request_from_another_site_cannot_change_anything(page):
    app, call, *_ = page
    body = {"name": "x", "kind": "http", "url": "http://127.0.0.1:9/act"}
    assert call("POST", "/api/defenders", body, headers={"Origin": "http://evil.example"})[0] == 403
    assert call("POST", "/api/defenders", body, origin=False)[0] == 403
    status = call("POST", "/api/defenders", b"name=x", headers={"Content-Type": "text/plain"})[0]
    assert status == 415
    assert call("POST", "/api/defenders", b"x" * (ui.MAX_BODY + 1))[0] == 413
    assert not (app.path).exists()  # nothing was written
    status, _p, headers = call("OPTIONS", "/api/defenders")
    assert status >= 400 and not any(k.lower().startswith("access-control") for k in headers)


def test_static_files_are_an_allow_list_with_a_strict_policy(page):
    _app, call, *_ = page
    status, _p, headers = call("GET", "/")
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    for bad in ("/../flagwake.yaml", "/js/../../ui.py", "/viewer.html", "/%2e%2e/x"):
        assert call("GET", bad)[0] == 404


def test_commands_are_off_unless_allowed_and_confirmed(page):
    app, call, *_ = page
    cmd = {"name": "prog", "kind": "command", "command": f'"{sys.executable}" agent.py'}
    status, payload, _h = call("POST", "/api/defenders", cmd)
    assert status == 403 and "command line" in payload["error"]
    app.allow_commands = True
    assert call("POST", "/api/defenders", cmd)[0] == 403  # still needs the confirmation
    assert call("POST", "/api/defenders", {**cmd, "confirm_runs_code": True})[0] == 200
    assert call("POST", "/api/check", {"name": "prog"})[0] == 403


def test_bad_fields_get_plain_errors(page):
    _app, call, *_ = page
    s, p, _h = call("POST", "/api/defenders", {"name": "Bad Name!", "kind": "http",
                                                "url": "http://127.0.0.1:9/act"})  # fmt: skip
    assert s == 400 and "small letters" in p["error"]
    s, p, _h = call("POST", "/api/defenders", {"name": "svc", "kind": "http",
                                                "url": "http://10.0.0.5/act"})  # fmt: skip
    assert s == 400 and "127.0.0.1" in p["error"]


def test_a_key_is_used_but_never_written_anywhere(page, capsys):
    app, call, wait_job, fake, tmp = page
    body = {"name": "online", "kind": "model-endpoint", "base_url": fake.url,
            "model": "tiny-model", "key": KEY}  # fmt: skip
    assert call("POST", "/api/defenders", body)[0] == 200
    assert call("POST", "/api/check", {"name": "online"})[0] == 200
    assert wait_job()["status"] == "done"
    assert (
        call("POST", "/api/run", {"name": "online", "size": "quick", "pack": "practice"})[0] == 200
    )
    job = wait_job()
    assert job["status"] == "done" and job["result_id"]
    assert f"Bearer {KEY}" in fake.auth  # the key reached the model...
    leaked = [p for p in tmp.rglob("*") if p.is_file() and KEY.encode() in p.read_bytes()]
    assert leaked == []  # ...and no file holds it: registry, reports, logs, conformance
    out = capsys.readouterr()
    assert KEY not in out.out + out.err
    state = call("GET", "/api/state")[1]
    assert KEY not in json.dumps(state) and state["defenders"][0]["has_key"]
    result = call("GET", f"/api/result?id={job['result_id']}")[1]
    assert result["plain"]["headline"].startswith("On 20 incidents")  # 20 families, 1 seed each
    s, raw, headers = call("GET", f"/api/download?id={job['result_id']}&file=report.json")
    assert s == 200 and "attachment" in headers["Content-Disposition"]
    from cyberarena.rc.verify import verify

    assert verify(raw) == []


def test_one_job_at_a_time_and_stop(page):
    app, call, wait_job, fake, _tmp = page
    body = {"name": "local", "kind": "model-endpoint", "base_url": fake.url, "model": "tiny-model",
            "key": KEY}  # fmt: skip
    call("POST", "/api/defenders", body)
    assert call("POST", "/api/run", {"name": "local", "size": "standard"})[0] == 200
    s, p, _h = call("POST", "/api/run", {"name": "local", "size": "quick"})
    assert s == 409 and "already running" in p["error"]
    assert call("POST", "/api/stop", {})[0] == 200
    job = wait_job()
    assert job["status"] == "stopped" and job["done"] < 60


def test_the_size_choices_show_the_real_number_of_incidents(page):
    """The tiles count incidents in the defender's own company, never a fixed 12/60/120."""
    from pathlib import Path

    from cyberarena.rc import rules

    _app, call, _wait, fake, _tmp = page
    body = {"name": "ref", "kind": "model-endpoint", "base_url": fake.url, "model": "tiny-model"}
    assert call("POST", "/api/defenders", body)[0] == 200
    entry = next(
        d for d in call("GET", "/api/state")[1]["defenders"] if d["entry"]["name"] == "ref"
    )
    fams = len(rules.families(rules.default_world()))
    assert entry["incidents"] == {s: fams * n for s, n in ui.SIZES.items()}
    html = (Path(ui.__file__).parent / "web" / "ui.html").read_text(encoding="utf-8")
    for fixed in ("<em>12</em>", "<em>60</em>", "<em>120</em>"):
        assert fixed not in html


def test_the_page_will_not_keep_a_key_for_plain_http_to_another_machine(page):
    _app, call, *_ = page
    body = {"name": "far", "kind": "model-endpoint", "base_url": "http://192.168.1.5:8080/v1",
            "model": "m", "key": KEY}  # fmt: skip
    s, p, _h = call("POST", "/api/defenders", body)
    assert s == 400 and "https" in p["error"]
    del body["key"]  # with no key there is nothing to protect
    assert call("POST", "/api/defenders", body)[0] == 200


def test_unknown_results_and_files_are_refused(page):
    _app, call, *_ = page
    assert call("GET", "/api/result?id=../../etc")[0] == 404
    assert call("GET", "/api/download?id=x&file=../flagwake.yaml")[0] == 404


def test_every_number_on_the_result_page_comes_from_the_report():
    """The short words and the bars repeat the report's own numbers, which verify re-derives."""
    from cyberarena.rc.packs import build_pack
    from cyberarena.rc.report import build_report
    from cyberarena.rc.ui_text import plain_result

    doc = build_report(run_pack(lambda: baseline_driver("rule-bot"),
                                build_pack("practice", per_family=2)), {"id": "x"})  # fmt: skip
    p = plain_result(doc)
    tax = doc["profile"]["taxonomy"]
    row = doc["profile"]["behaviour_vs_baselines"][0]
    assert p["numbers"]["damage"] == doc["metrics"]["damage_index"]["mean_clipped"]
    assert p["bars"]["you"] == row["value"] and p["bars"]["you_range"] == row["ci95"]
    assert [o["value"] for o in p["bars"]["others"]] == [v["value"] for v in row["vs"].values()]
    shown = {c["short"]: c["count"] for c in p["bad"]}
    assert shown["Left the intruder in"] == tax["missed_intruder"]["events"]
    assert shown["Skipped approval"] == tax["skipped_approval"]["events"]
    assert all(c["count"] > 0 for c in p["bad"])  # nothing shown that did not happen
    assert p["verdict"] == "A little better than doing nothing" and p["tone"] == "poor"


def test_the_live_view_watches_without_changing_the_run():
    """The page's live snapshot wraps the driver; the run, and so the report, is identical."""
    from cyberarena.rc.packs import build_pack
    from cyberarena.rc.report import build_report, report_hash

    specs = build_pack("practice", per_family=1)
    job = ui.Job("run", "x", len(specs), None)
    key = "1ee7" * 8  # the same run key for both runs: only the watching differs
    plain = build_report(run_pack(lambda: baseline_driver("careful"), specs, key=key), {"id": "x"})
    seen = []

    def factory():
        return baseline_driver("careful")

    watched = ui.watched(factory, job, len(specs))

    def spy_factory():
        d = watched()
        seen.append(d)
        return d

    spied = build_report(run_pack(spy_factory, specs, key=key), {"id": "x"})
    assert report_hash(spied) == report_hash(plain)
    live = job.live
    assert live["number"] == 12 and live["total"] == 12 and len(live["hosts"]) == 18
    assert live["feed"] and live["feed"][-1]["cmd"].startswith("report")
    assert set(live["hosts"].values()) <= {"clean", "held", "cut", "held-cut", "down"}
    assert ui.world_layout()["hosts"][0].keys() == {"name", "zone", "crit"}


def test_the_live_view_is_served_to_the_page_only(page):
    _app, call, *_ = page
    status, data, _h = call("GET", "/api/world")
    assert status == 200 and len(data["hosts"]) == 18
    assert call("GET", "/api/world", token=False)[0] == 403


def test_the_page_saves_a_company_and_rejects_a_bad_company_file(page):
    app, call, *_ = page
    body = {"name": "big", "kind": "http", "url": "http://127.0.0.1:9/act", "world": "fenwick-brae"}
    assert call("POST", "/api/defenders", body)[0] == 200
    saved = [e for e in call("GET", "/api/state")[1]["defenders"] if e["entry"]["name"] == "big"]
    assert saved[0]["entry"]["world"] == "fenwick-brae"
    (app.folder / "co.yaml").write_text("schema: flagwake-company-1\nname: x\n", encoding="utf-8")
    s, p, _h = call("POST", "/api/defenders", {**body, "name": "bad", "world": "co.yaml"})
    assert s == 400 and "company file is not valid" in p["error"]


def test_the_page_checks_and_runs_a_tools_defender_on_a_custom_company(page, tmp_path):
    app, call, wait_job, *_ = page
    app.allow_commands = True
    from cyberarena.rc.world_cli import TEMPLATE

    (app.folder / "company.yaml").write_text(TEMPLATE, encoding="utf-8")
    prog = app.folder / "tool_defender.py"
    prog.write_text(
        "import json, os, urllib.request\n"
        "api, tok = os.environ['FLAGWAKE_API_URL'], os.environ['FLAGWAKE_TOOLS_TOKEN']\n"
        "def call(n, a=None):\n"
        "    r = urllib.request.Request(f'{api}/tools/{n}', data=json.dumps(a or {}).encode(),\n"
        "        headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + tok})\n"
        "    return json.loads(urllib.request.urlopen(r, timeout=30).read())\n"
        "while True:\n"
        "    r = call('get_alerts')\n"
        "    if not r['result'].get('ticket'):\n"
        "        break\n"
        "    call('list_hosts')\n"
        "    call('close_ticket', {'compromised': []})\n",
        encoding="utf-8",
    )
    body = {"name": "tooly", "kind": "command", "command": f'"{sys.executable}" tool_defender.py',
            "confirm_runs_code": True, "mode": "tools", "world": "company.yaml"}  # fmt: skip
    assert call("POST", "/api/defenders", body)[0] == 200
    assert call("POST", "/api/check", {"name": "tooly", "confirm_runs_code": True})[0] == 200
    assert wait_job()["status"] == "done"
    assert call("GET", "/api/checks?name=tooly")[1]["passed"]
    run = {"name": "tooly", "size": "quick", "pack": "practice", "confirm_runs_code": True}
    assert call("POST", "/api/run", run)[0] == 200
    job = wait_job()
    assert job["status"] == "done", job
    s, raw, _h = call("GET", f"/api/download?id={job['result_id']}&file=report.json")
    from cyberarena.rc.verify import verify

    assert raw["integration"]["mode"] == "environment as tools" and raw["world"]["custom"]
    assert verify(raw, app.folder / "company.yaml") == []


def test_the_demo_saves_a_result_that_verifies_and_a_tampered_copy_is_caught(page):
    app, call, _wait, _fake, tmp_path = page
    status, demo, _h = call("POST", "/api/demo", {})
    assert status == 200 and demo["id"] == f"example-{ui.DEMO}/runs/demo-practice"
    assert any(r["id"] == demo["id"] for r in call("GET", "/api/runs")[1]["runs"])
    status, res, _h = call("GET", "/api/result?id=" + demo["id"])
    costs = res["costs"]
    assert status == 200 and costs["items"] and all(i["value"] > 0 for i in costs["items"])
    assert sum(i["value"] for i in costs["items"]) == costs["total"] > costs["best"]
    assert 99 <= sum(i["share"] for i in costs["items"]) <= 101 and costs["nothing"] > 0
    status, v, _h = call("POST", "/api/verify", {"id": demo["id"]})
    assert status == 200 and v["ok"] and v["problems"] == [] and v["incidents"] == 20
    report = tmp_path / "flagwake-runs" / demo["id"] / "report.json"
    before = report.read_bytes()
    status, t, _h = call("POST", "/api/tamper", {"id": demo["id"]})
    assert status == 200 and t["caught"] and "damage_index" in t["message"]
    assert t["after"] == round(max(0.0, t["before"] - 20.0), 1)
    assert report.read_bytes() == before  # the copy is edited in memory only
    assert call("POST", "/api/demo", {})[1]["id"] == demo["id"]  # the demo reuses its folder


def test_the_demo_shows_two_defenders_on_the_same_incidents(page):
    """The demo's point is the contrast: a careful and a gullible example on the same incidents."""
    _app, call, *_ = page
    status, demo, _h = call("POST", "/api/demo", {})
    assert status == 200
    pair = demo["pair"]
    assert [p["name"] for p in pair] == ["example-careful", "example-gullible"]
    assert pair[0]["score"] < pair[1]["score"] and pair[1]["tone"] == "bad"
    for row in pair:
        status, res, _h = call("GET", "/api/result?id=" + row["id"])
        assert status == 200 and res["pair"] == pair
        assert res["plain"]["numbers"]["damage"] == row["score"]
        assert res["plain"]["verdict"] == row["verdict"]
    docs = [call("GET", f"/api/download?id={r['id']}&file=report.json")[1] for r in pair]
    same = [[(i["family"], i["seed"]) for i in d["incidents"]] for d in docs]
    assert same[0] == same[1] and len(same[0]) == 20


def test_a_result_that_is_not_an_example_has_no_pair(page):
    app, call, wait_job, fake, _tmp = page
    body = {"name": "local", "kind": "model-endpoint", "base_url": fake.url, "model": "tiny-model"}
    call("POST", "/api/defenders", body)
    assert (
        call("POST", "/api/run", {"name": "local", "size": "quick", "pack": "practice"})[0] == 200
    )
    job = wait_job()
    res = call("GET", "/api/result?id=" + job["result_id"])[1]
    assert res["pair"] == []


def test_verify_and_tamper_refuse_unknown_results(page):
    _app, call, _wait, _fake, _tmp = page
    for path in ("/api/verify", "/api/tamper"):
        status, body, _h = call("POST", path, {"id": "../../etc"})
        assert status == 404 and "No such result" in body["error"]
    assert call("POST", "/api/demo", {}, token=False)[0] == 403


def test_the_example_on_the_home_page_shows_the_real_demo_numbers():
    """The home page prints an example; every figure in it is what the demo really produces."""
    import functools
    import re
    from pathlib import Path

    from cyberarena.rc.demo import EXAMPLES, kpi_items
    from cyberarena.rc.report import build_report
    from cyberarena.rc.runner import pack_specs
    from cyberarena.rc.world import shipped_world

    html = (Path(ui.__file__).parent / "web" / "ui.html").read_text(encoding="utf-8")
    shown = dict(re.findall(r'data-demo="([a-z]+\.[a-z0-9]+)">([^<]+)<', html))
    world = shipped_world()
    specs = pack_specs("practice", 1, world=world)
    assert f"the same {len(specs)} incidents" in html
    want = {}
    for name in EXAMPLES:
        result = run_pack(functools.partial(baseline_driver, name), specs, world=world)
        doc = build_report(result, {"id": name}, "practice", world=world)
        want[f"{name}.score"] = str(round(doc["metrics"]["damage_index"]["mean_clipped"]))
        for i, item in enumerate(kpi_items(doc)):
            want[f"{name}.{i}"] = item["value"]
    assert shown == want
