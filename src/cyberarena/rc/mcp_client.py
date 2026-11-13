"""Run a defender that is a stdio MCP server: the harness is the MCP client.

The defender's server is started from its registry ``command`` and must offer one tool (``act``
unless the entry names another) that takes ``{"message": <harness message>}``, where the message
is exactly what the JSON-lines protocol sends (``start``, ``obs`` or ``end``, see
docs/PROTOCOL.md), and returns the next command as text: either a bare command line
(``logs web-01``) or the same JSON reply a JSON-lines agent sends (``{"cmd": "logs web-01"}``,
``{"stop": true}``, with optional ``usage``). The harness speaks the subset of MCP this needs
(``initialize``, ``notifications/initialized``, ``tools/list``, ``tools/call``) with the same
time limits, line caps and failure handling as a JSON-lines child; one server process per
incident. The defender never sees anything but the messages; it cannot call the harness.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from cyberarena.rc.engine import Shift
from cyberarena.rc.protocol import (
    DEFAULT_STEP_TIMEOUT,
    DEFAULT_WALL_TIMEOUT,
    INVALID_REPLY,
    MAX_BAD_LINES,
    MAX_LINE,
    ProtocolError,
    SubprocessAgent,
    _obs_message,
    _start_message,
    parse_reply,
)

PROTOCOL_VERSION = "2024-11-05"
CLIENT_INFO = {"name": "flagwake-harness", "version": "1"}
SKIP_LINES = 50  # notifications or log lines tolerated before the answer to one request


class McpAgent(SubprocessAgent):
    """One incident's MCP server process, driven through its ``act`` tool."""

    def __init__(self, argv: list[str], tool: str = "act", *args: Any, **kwargs: Any) -> None:
        super().__init__(argv, *args, **kwargs)
        self.tool = tool
        self._next_id = 0
        self._ready = False

    def _rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any] | None:
        """Send one request; the matching response, or None when the server failed."""
        self._next_id += 1
        rid = self._next_id
        if not self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}):
            return None
        for _ in range(SKIP_LINES):
            line = self._readline()
            if line is None:
                return None
            if line == "":
                self._exited()
                return None
            if len(line) > MAX_LINE:
                continue
            try:
                msg = json.loads(line)
            except (ValueError, RecursionError):
                continue
            if isinstance(msg, dict) and msg.get("id") == rid:
                return msg
        self._stop(f"no answer to {method} among {SKIP_LINES} lines")
        return None

    def _handshake(self) -> bool:
        init = self._rpc(
            "initialize",
            {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO},
        )
        if init is None or "result" not in init:
            return self._failed("the MCP server did not answer initialize")
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        listed = self._rpc("tools/list", {})
        tools = ((listed or {}).get("result") or {}).get("tools") or []
        names = [t.get("name") for t in tools if isinstance(t, dict)]
        if self.tool not in names:
            return self._failed(f"the MCP server has no tool named {self.tool!r}")
        self._ready = True
        return True

    def _failed(self, why: str) -> bool:
        if self.first and self.notes.answered == 0:
            self._stop(why, kill=True)
            raise ProtocolError(why)
        self._stop(why, kill=True)
        return False

    def __call__(self, shift: Shift) -> str | None:
        if self._closed:
            return None
        if not self._ready and not self._handshake():
            return None
        msg = _start_message(shift, self.step_timeout) if not self._started else _obs_message(shift)
        self._started = True
        resp = self._rpc("tools/call", {"name": self.tool, "arguments": {"message": msg}})
        if resp is None:
            return None
        kind, cmd, usage = reply_from_result(resp)
        if usage is not None:
            self.notes.usage = usage
        if kind == "stop":
            self._stop("")
            return None
        if kind == "bad":
            self.notes.invalid += 1
            if self.notes.invalid > MAX_BAD_LINES:
                self._stop(f"more than {MAX_BAD_LINES} invalid replies")
                return None
            return INVALID_REPLY
        self.notes.answered += 1
        return cmd

    def end(self, summary: dict[str, Any]) -> None:
        if not self._closed and self._ready and self.proc.poll() is None:
            self._rpc(
                "tools/call",
                {"name": self.tool, "arguments": {"message": {"type": "end", "summary": summary}}},
            )
        self._stop("")


def reply_from_result(resp: dict[str, Any]) -> tuple[str, str | None, dict[str, Any] | None]:
    """Classify a tools/call response like a JSON-lines reply (see ``protocol.parse_reply``)."""
    result = resp.get("result")
    if not isinstance(result, dict) or result.get("isError"):
        return "bad", None, None
    parts = result.get("content")
    if not isinstance(parts, list):
        return "bad", None, None
    text = "".join(
        p.get("text", "") for p in parts if isinstance(p, dict) and isinstance(p.get("text"), str)
    ).strip()
    if not text or len(text) > MAX_LINE:
        return "bad", None, None
    if text.startswith("{"):
        return parse_reply(text)
    return "cmd", text.splitlines()[0][:4000], None


def mcp_driver_factory(
    argv: list[str],
    tool: str = "act",
    step_timeout: float = DEFAULT_STEP_TIMEOUT,
    stderr_path: str | None = None,
    wall_timeout: float = DEFAULT_WALL_TIMEOUT,
    cwd: str | None = None,
) -> Callable[[], McpAgent]:
    """A factory the runner calls per incident; each incident gets a fresh server process."""
    state = {"first": True}

    def make() -> McpAgent:
        first, state["first"] = state["first"], False
        return McpAgent(argv, tool, step_timeout, stderr_path, wall_timeout, first, cwd)

    return make
