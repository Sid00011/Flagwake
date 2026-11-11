"""Browser tests of the report viewer in web/rc/.

Playwright (Python, sync API, Chromium only). Install with ``pip install -e ".[dev,e2e]"`` and
``python -m playwright install chromium``. Without playwright (or without Chromium) the folder is
skipped, so a plain ``pytest -q`` stays green; with ``CA_E2E=1`` (set by CI) a missing playwright
or browser is an error instead.

A session fixture serves web/ on 127.0.0.1 with the standard library. Every page opened through
the ``tab`` / ``open_tab`` fixtures records console errors, page errors and every request; any
console error or page error fails the test (unless the test declared it as expected), and every
request to another origin is blocked by a route and fails the test too.
"""

from __future__ import annotations

import functools
import http.server
import os
import re
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from sitekit import READY_JS, WEB

REQUIRED = os.environ.get("CA_E2E") == "1"
HERE = Path(__file__).resolve().parent

try:
    from playwright.sync_api import Browser, BrowserContext, Page, Playwright, sync_playwright
    from playwright.sync_api import Error as PlaywrightError

    MISSING: str | None = None
except ImportError as exc:  # pragma: no cover - depends on the environment
    if REQUIRED:
        raise RuntimeError(
            "CA_E2E=1 but playwright cannot be imported; run "
            '`pip install -e ".[dev,e2e]"` and `python -m playwright install chromium`'
        ) from exc
    MISSING = f"playwright is not installed ({exc}); set CA_E2E=1 to make this an error"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Without playwright (and without CA_E2E=1) every test of this folder is skipped."""
    if MISSING is None:
        return
    skip = pytest.mark.skip(reason=MISSING)
    for item in items:
        if HERE in Path(str(item.path)).resolve().parents:
            item.add_marker(skip)


DEFAULT_VIEWPORT = {"width": 1280, "height": 900}


# ----------------------------------------------------------------------------- static server
class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    """Serves web/ with explicit MIME types (the Windows registry can map .js oddly)."""

    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".html": "text/html; charset=utf-8",
        ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".json": "application/json",
        ".svg": "image/svg+xml",
        ".webmanifest": "application/manifest+json",
        ".png": "image/png",
    }

    def log_message(self, format: str, *args: Any) -> None:
        pass


class _QuietServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    # The default listen backlog (5) overflows when a page loads its emblems and data files at
    # once; Windows then refuses connections (ERR_CONNECTION_REFUSED). Real hosts never do.
    request_queue_size = 128

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass  # a browser closing a connection early is not a test failure


@dataclass(frozen=True)
class Site:
    """The served site: ``origin`` is http://127.0.0.1:<port>."""

    origin: str

    def url(self, path: str = "") -> str:
        return f"{self.origin}/{path}"


@pytest.fixture(scope="session")
def site() -> Iterator[Site]:
    handler = functools.partial(_QuietHandler, directory=str(WEB))
    server = _QuietServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, name="e2e-http", daemon=True)
    thread.start()
    try:
        yield Site(f"http://127.0.0.1:{port}")
    finally:
        server.shutdown()
        server.server_close()


# ----------------------------------------------------------------------------- browser
@pytest.fixture(scope="session")
def playwright_driver() -> Iterator[Playwright]:
    with sync_playwright() as p:
        yield p


@pytest.fixture(scope="session")
def browser(playwright_driver: Playwright) -> Iterator[Browser]:
    try:
        b = playwright_driver.chromium.launch()
    except PlaywrightError as exc:  # pragma: no cover - depends on the environment
        first = str(exc).strip().splitlines()[0] if str(exc).strip() else repr(exc)
        msg = (
            f"Chromium for Playwright does not start ({first}); "
            "run: python -m playwright install chromium"
        )
        if REQUIRED:
            pytest.fail(msg, pytrace=False)
        pytest.skip(msg)
    yield b
    b.close()


class Probe:
    """Records what a page did: console errors, uncaught page errors, requests, blocked requests."""

    def __init__(self, page: Page) -> None:
        self.page = page
        self.console_errors: list[str] = []
        self.page_errors: list[str] = []
        self.requests: list[str] = []
        self.blocked: list[str] = []
        self._expected: list[re.Pattern[str]] = []
        page.on("console", self._on_console)
        page.on("pageerror", lambda err: self.page_errors.append(str(err)))
        page.on("request", lambda req: self.requests.append(req.url))

    def _on_console(self, msg: Any) -> None:
        if msg.type == "error":
            self.console_errors.append(msg.text)

    def expect_console_error(self, pattern: str) -> None:
        """Declare console errors matching ``pattern`` (regex) as expected by this test."""
        self._expected.append(re.compile(pattern))

    def reset(self) -> None:
        """Forget everything recorded so far (for a page reused across tests)."""
        self.flush()
        self.console_errors.clear()
        self.page_errors.clear()
        self.requests.clear()
        self.blocked.clear()
        self._expected.clear()

    def flush(self) -> None:
        """Let queued page events reach the listeners."""
        if not self.page.is_closed():
            try:
                self.page.evaluate("0")
            except PlaywrightError:
                pass

    def problems(self) -> list[str]:
        self.flush()
        out = [f"uncaught page error: {e}" for e in self.page_errors]
        out += [
            f"console error: {t}"
            for t in self.console_errors
            if not any(p.search(t) for p in self._expected)
        ]
        out += [f"request to another origin (blocked): {u}" for u in self.blocked]
        return out


class Tab:
    """A page plus its probe; ``open`` navigates and waits until the data is rendered."""

    def __init__(self, page: Page, probe: Probe, site: Site) -> None:
        self.page = page
        self.probe = probe
        self.site = site

    def open(self, path: str, *, ready: bool = True) -> Page:
        self.page.goto(self.site.url(path))
        if ready:
            self.wait_ready()
        return self.page

    def wait_ready(self) -> None:
        self.page.wait_for_function(READY_JS)


def attach_probe(node: Any, probe: Probe) -> None:
    """Make the call-phase hook below check ``probe`` for this test item."""
    node.ca_probes = [*getattr(node, "ca_probes", []), probe]


def new_tab(
    browser: Browser, site: Site, *, block_external: bool = True, **context_kwargs: Any
) -> tuple[BrowserContext, Tab]:
    """A fresh context (no shared cache or storage) with one page and its probe.

    The offline service worker is blocked unless a test asks for it (``service_workers="allow"``):
    with it, the worker's own cache fills fetch in the background and request routing cannot see
    what it serves."""
    kwargs: dict[str, Any] = {
        "viewport": DEFAULT_VIEWPORT,
        "service_workers": "block",
        **context_kwargs,
    }
    ctx = browser.new_context(**kwargs)
    ctx.set_default_timeout(15_000)
    page = ctx.new_page()
    probe = Probe(page)
    if block_external:
        prefix = site.origin + "/"

        def other_origin(url: str) -> bool:
            return not url.startswith(prefix)

        def block(route: Any) -> None:
            probe.blocked.append(route.request.url)
            route.abort("blockedbyclient")

        ctx.route(other_origin, block)
    return ctx, Tab(page, probe, site)


@pytest.fixture
def open_tab(
    browser: Browser, site: Site, request: pytest.FixtureRequest
) -> Iterator[Callable[..., Tab]]:
    """Factory: ``open_tab(**context options)`` -> a checked Tab, closed after the test."""
    contexts: list[BrowserContext] = []

    def make(**kwargs: Any) -> Tab:
        ctx, tab = new_tab(browser, site, **kwargs)
        contexts.append(ctx)
        attach_probe(request.node, tab.probe)
        return tab

    yield make
    for ctx in contexts:
        ctx.close()


@pytest.fixture
def tab(open_tab: Callable[..., Tab]) -> Tab:
    """A checked page at the default desktop size."""
    return open_tab()


@pytest.fixture(scope="module")
def module_tab(browser: Browser, site: Site) -> Iterator[Tab]:
    """One page kept for a whole module (fast loops such as every replay)."""
    ctx, tab = new_tab(browser, site)
    yield tab
    ctx.close()


@pytest.fixture
def shared_tab(module_tab: Tab, request: pytest.FixtureRequest) -> Tab:
    """The module's page, with its record cleared and checked for this test only."""
    module_tab.probe.reset()
    attach_probe(request.node, module_tab.probe)
    return module_tab


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item: pytest.Item) -> Iterator[None]:
    """After a passing test body: fail on any console error, page error or blocked request."""
    result = yield
    problems = [p for probe in getattr(item, "ca_probes", []) for p in probe.problems()]
    if problems:
        pytest.fail("the page reported problems:\n  " + "\n  ".join(problems), pytrace=False)
    return result
