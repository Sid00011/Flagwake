"""Browser tests of the local page (flagwake ui): the whole flow on a phone and a desktop size.

A fake local model server answers /v1/models (one model name is hostile markup) and chat
requests; the page finds it, saves the defender, checks the connection, runs the quick pack,
shows the result and downloads a report that verifies. Any script dialog (hostile text run as
code), page error or request to another host fails the test. With CA_UI_SHOTS set to a folder,
screenshots of each step are saved there.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import pytest
from uikit import FakeServer

from cyberarena.rc import ui
from cyberarena.rc.verify import verify

HOSTILE = '<img src=x onerror="alert(1)">'
SIZES = {"phone": (390, 844), "desktop": (1280, 800)}


@pytest.fixture(scope="module")
def local_page(tmp_path_factory):
    fake = FakeServer(models=("tiny-model", HOSTILE))
    work = tmp_path_factory.mktemp("ui")
    app = ui.App(work / "flagwake.yaml", detect_ports=(fake.port,))
    server = ui.make_server(app, 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}/#t={app.token}"
    yield url, app
    server.shutdown()
    server.server_close()
    fake.close()


def _page(browser, url, size):
    ctx = browser.new_context(viewport={"width": size[0], "height": size[1]}, accept_downloads=True)
    page = ctx.new_page()
    problems: list[str] = []
    page.on("dialog", lambda d: (problems.append("dialog: " + d.message), d.dismiss()))
    page.on("pageerror", lambda e: problems.append(f"page error: {e}"))
    page.on("console", lambda m: m.type == "error" and problems.append("console: " + m.text))

    def only_local(route):
        if route.request.url.startswith("http://127.0.0.1:"):
            route.continue_()
        else:
            problems.append("outside request: " + route.request.url)
            route.abort()

    page.route("**/*", only_local)
    page.goto(url)
    return ctx, page, problems


def _shot(page, name):
    folder = os.environ.get("CA_UI_SHOTS")
    if folder:
        Path(folder).mkdir(parents=True, exist_ok=True)
        page.wait_for_timeout(800)  # let the heading finish decoding
        page.screenshot(path=str(Path(folder) / f"{name}.png"), full_page=True)


@pytest.mark.parametrize("label", list(SIZES))
def test_add_check_run_read_download(browser, local_page, label, tmp_path):
    url, _app = local_page
    ctx, page, problems = _page(browser, url, SIZES[label])
    try:
        _shot(page, f"{label}-0-start")
        page.locator("#add").click()
        page.get_by_text("On this computer", exact=True).click()
        page.get_by_text("Pick a model").wait_for()
        assert page.get_by_text(HOSTILE, exact=True).count() == 1  # shown as text, not markup
        page.get_by_text("tiny-model", exact=True).click()
        page.locator("#name").fill(f"tiny-{label}")
        _shot(page, f"{label}-1-what")
        page.locator("#save").click()
        page.locator("#check").click()
        page.locator("#s2-status", has_text="Connected").wait_for(timeout=60_000)
        assert page.locator("#pips i.ok").count() == 7
        _shot(page, f"{label}-2-check")
        page.locator("#to-s3").click()
        assert "≈" in page.locator(".est").first.inner_text()  # an estimate is shown
        _shot(page, f"{label}-3-size")
        page.locator("#start").click()
        page.locator("#s5:not([hidden])").wait_for(timeout=120_000)
        assert page.locator("#map .node").count() == 18  # the live room drew the company
        # 20 families on the default company, one seed each
        assert page.locator("#r-long").text_content().startswith("On 20 incidents")
        assert "not yet compared with expert judgement" in page.locator("#r-scope").text_content()
        assert page.locator("#r-headline").text_content() == "About the same as doing nothing"
        assert page.locator("#r-compare li").count() == 3
        assert page.locator("#r-score").inner_text() == "100"
        _shot(page, f"{label}-5-result")
        with page.expect_download() as dl:
            page.get_by_role("button", name="report.json").click()
        path = tmp_path / "report.json"
        dl.value.save_as(path)
        assert verify(json.loads(path.read_text(encoding="utf-8"))) == []
        page.get_by_role("button", name="Back to start").click()
        assert page.locator("#runs li").count() >= 1
        _shot(page, f"{label}-6-home")
    finally:
        ctx.close()
    assert problems == []


def test_the_wizard_works_from_the_keyboard(browser, local_page):
    url, _app = local_page
    ctx, page, problems = _page(browser, url, SIZES["desktop"])
    try:
        page.locator("#home .q").first.focus()
        assert page.locator("#home .q .tip").first.is_visible()  # a tooltip opens on focus
        page.locator("#add").focus()
        page.keyboard.press("Enter")
        assert page.locator("#s1 h1").evaluate("e => document.activeElement === e")
        page.keyboard.press("Tab")
        page.keyboard.press("Space")  # the first tile: a model on this computer
        page.get_by_text("Pick a model").wait_for()
        page.keyboard.press("Escape")
        assert page.locator("#home").is_visible()
    finally:
        ctx.close()
    assert problems == []


def test_without_the_token_the_page_says_how_to_open_it(browser, local_page):
    url, _app = local_page
    ctx, page, problems = _page(browser, url.split("#")[0], SIZES["phone"])
    try:
        assert "address printed" in page.locator("#notice").inner_text()
    finally:
        ctx.close()
    assert problems == []
