"""Shared, browser-free helpers for the browser tests: the folder served and the ready check.

This module must not import playwright: the conftest decides whether the folder runs.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"

# Ready when the document has loaded (the report viewer renders only after a file is chosen).
READY_JS = "() => document.readyState === 'complete'"
