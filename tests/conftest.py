"""Shared pytest set-up: a per-test time limit, so a hung test fails the run.

A hung test must fail the run, not block it for hours. Before each test a fault-handler timer is
armed: when a test runs past its limit, the stacks of every thread are printed (so the hang can be
diagnosed) and the process exits with an error. Limits: 30 s for tests/unit, 120 s for the rest
(browser and statistical tests). FLAGWAKE_TEST_TIMEOUT overrides both (0 = off).
"""

import faulthandler
import os
import sys
import threading

import pytest

UNIT_LIMIT = 30.0
OTHER_LIMIT = 120.0


def _limit(item: pytest.Item) -> float:
    override = os.environ.get("FLAGWAKE_TEST_TIMEOUT")
    if override is not None:
        return float(override)
    marker = item.get_closest_marker("time_limit")
    if marker is not None:
        return float(marker.args[0])
    parts = item.path.parts
    return (
        UNIT_LIMIT
        if "unit" in parts[parts.index("tests") + 1 : parts.index("tests") + 2]
        else (OTHER_LIMIT)
    )


def _expire(item: pytest.Item, limit: float) -> None:
    """Runs in a timer thread when a test is over its limit: show where it hangs, then stop."""
    capture = item.config.pluginmanager.getplugin("capturemanager")
    if capture is not None:
        capture.suspend_global_capture(in_=False)  # back to the real terminal
    sys.stderr.write(f"\nTIME LIMIT: {item.nodeid} ran past {limit:.0f} s; stacks follow\n")
    sys.stderr.flush()
    faulthandler.dump_traceback(file=sys.stderr, all_threads=True)
    sys.stderr.flush()
    os._exit(3)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item: pytest.Item, nextitem: pytest.Item | None):
    limit = _limit(item)
    if limit <= 0:
        yield
        return
    timer = threading.Timer(limit, _expire, (item, limit))
    timer.daemon = True
    timer.start()
    # Fallback if the timer thread cannot run (a test holding the interpreter lock in C code).
    faulthandler.dump_traceback_later(limit + 15, exit=True)
    try:
        yield
    finally:
        faulthandler.cancel_dump_traceback_later()
        timer.cancel()
