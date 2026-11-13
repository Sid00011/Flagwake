"""Serving the company as tools and running a defender that brings its own loop.

A :class:`TicketDesk` serves the incidents of a pack one ticket at a time: the defender reads the
open ticket and its alerts, investigates and acts with the tools, and closes the ticket; the next
ticket opens at once. The desk is reachable three ways, all on this machine only:

- MCP over HTTP: JSON-RPC 2.0 posted to ``/mcp`` (initialize, tools/list, tools/call, ping);
- a REST API: ``POST /v1/tools/<name>`` with the arguments as a JSON object, ``GET /v1/alerts`` to
  poll, ``POST /v1/webhooks`` to register a callback URL on this machine, and the OpenAPI document
  at ``/openapi.json``;
- MCP over stdio (``flagwake tools serve --stdio``) for clients that start their servers.

Every HTTP request needs the bearer token the harness prints or passes to the defender. Nothing
here runs code the defender sends; arguments are data, checked against the tool schemas.
"""

from __future__ import annotations

import hmac
import http.server
import json
import queue
import secrets
import socketserver
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cyberarena import __version__
from cyberarena.rc import rules
from cyberarena.rc.engine import MAX_COMMANDS, digits, parse_command
from cyberarena.rc.protocol import incident_label, new_run_key
from cyberarena.rc.provenance import child_env
from cyberarena.rc.report import TOOLS as TOOLS_MODE
from cyberarena.rc.runner import start_shift
from cyberarena.rc.scoring import score_shift
from cyberarena.rc.toolsapi import TOOL_NAMES, TOOLS, ToolIncident
from cyberarena.rc.world import World

MAX_BODY = 65536
IDLE_TIMEOUT = 900.0  # seconds without a call before the open ticket is closed unfinished
MCP_VERSION = "2025-06-18"
DONE = {"ticket": None, "message": "No open tickets: the run is complete."}


class TicketDesk:
    """The pack as a queue of tickets; thread-safe; scores each incident when it closes."""

    def __init__(
        self,
        specs: list[dict[str, Any]],
        world: World | None = None,
        repeat: int = 1,
        idle_timeout: float = IDLE_TIMEOUT,
        progress: Callable[[int, int], None] | None = None,
        key: str | None = None,
        max_commands: int = MAX_COMMANDS,
    ) -> None:
        self.world = world or rules.default_world()
        self.max_commands = max_commands  # the same per-incident cap the native modes enforce
        self.key = key or new_run_key()  # names every ticket; the report records it at the end
        self.queue = [(s, r) for s in specs for r in range(repeat)]
        self.total = len(self.queue)
        self.repeat = repeat
        self.idle_timeout = idle_timeout
        self.progress = progress
        self.lock = threading.RLock()
        self.complete = threading.Event()
        self.transcripts: list[dict[str, Any]] = []
        self.outcomes: list[dict[str, Any]] = []
        self.listeners: list[Callable[[dict[str, Any]], None]] = []
        self.current: ToolIncident | None = None
        self.spec: dict[str, Any] = {}
        self.rep = 0
        self.last = time.monotonic()
        self._open_next()

    # -------------------------------------------------------------------- tickets
    def _open_next(self) -> None:
        if not self.queue:
            self.current = None
            self.complete.set()
            self._emit({"event": "run.complete"})
            return
        self.spec, self.rep = self.queue.pop(0)
        shift = start_shift(self.spec, self.world)
        label = incident_label(self.spec["family"], self.spec["seed"], self.spec["difficulty"],
                               key=self.key)  # fmt: skip
        if self.repeat > 1:
            label += f"-r{self.rep}"
        self.current = ToolIncident(shift, label)
        self.last = time.monotonic()
        self._emit(self.current.opening)

    def _close(self, harness_error: str | None = None) -> None:
        inc = self.current
        assert inc is not None
        inc.finish()
        sh = inc.shift
        tr: dict[str, Any] = {
            "family": self.spec["family"],
            "seed": self.spec["seed"],
            "difficulty": self.spec["difficulty"],
            "commands": inc.commands,
            "obs_hashes": inc.obs_hashes,
            "end_reason": sh.end_reason,
            "calls": inc.calls,
            "sent_hashes": inc.sent_hashes,
        }
        outcome = score_shift(sh)
        if self.repeat > 1:
            tr["repeat"] = self.rep
            outcome = {**outcome, "repeat": self.rep}
        if harness_error:
            tr["harness"] = {"error": harness_error}
        self.transcripts.append(tr)
        self.outcomes.append(outcome)
        self._emit({"event": "ticket.closed", "ticket": inc.label, "reason": sh.end_reason})
        if self.progress:
            self.progress(len(self.outcomes), self.total)
        self._open_next()

    def call(self, tool: Any, args: Any) -> dict[str, Any]:
        """One tool call from the defender; the response it gets."""
        with self.lock:
            if self.current is None:
                return {"ok": True, "result": dict(DONE), "ticket_open": False}
            seen = len(self.current.shift.alerts)
            resp = self.current.call(tool, args)
            self.last = time.monotonic()
            for a in self.current.shift.alerts[seen:]:
                self._emit({"event": "alert", "ticket": self.current.label, "alert_id": a["id"]})
            if self.current.done:
                self._close()
            elif len(self.current.commands) >= self.max_commands:
                resp = {
                    **resp,
                    "ticket_open": False,
                    "note": f"command cap ({self.max_commands}) reached: the ticket is closed",
                }
                self._close()  # fmt: skip
            return resp

    def expire(self, reason: str) -> None:
        """Close the open ticket as unfinished (the defender went quiet or stopped)."""
        with self.lock:
            if self.current is not None:
                self._close(reason)

    def idle(self) -> bool:
        return self.current is not None and time.monotonic() - self.last > self.idle_timeout

    def stop_all(self, reason: str) -> None:
        """End the run: every ticket not yet closed is closed unfinished with ``reason``."""
        with self.lock:
            while self.current is not None:
                self._close(reason)

    def result(self) -> dict[str, Any]:
        return {"transcripts": list(self.transcripts), "outcomes": list(self.outcomes),
                "world": rules.world_ref(self.world), "run_key": self.key}  # fmt: skip

    # -------------------------------------------------------------------- events
    def _emit(self, event: dict[str, Any]) -> None:
        for fn in list(self.listeners):
            fn(event)


# ------------------------------------------------------------------------ webhooks


class Webhooks:
    """Posts desk events to callback URLs on this machine, in order, from one worker thread."""

    def __init__(self, token: str) -> None:
        self.urls: list[str] = []
        self.token = token
        self.q: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self.thread = threading.Thread(target=self._work, daemon=True)
        self.thread.start()

    def add(self, url: str) -> str | None:
        """Register a URL; returns a plain error, or None."""
        u = urllib.parse.urlsplit(url)
        if u.scheme != "http" or u.hostname not in ("127.0.0.1", "localhost", "::1"):
            return "the webhook must be an http:// URL on this machine (127.0.0.1 or localhost)"
        if len(self.urls) >= 4 or url in self.urls:
            return "at most 4 different webhooks"
        self.urls.append(url)
        return None

    def __call__(self, event: dict[str, Any]) -> None:
        if self.urls:
            self.q.put(event)

    def _work(self) -> None:
        while True:
            ev = self.q.get()
            if ev is None:
                return
            body = json.dumps(ev, sort_keys=True).encode("utf-8")
            for url in list(self.urls):
                req = urllib.request.Request(
                    url,
                    data=body,
                    method="POST",
                    headers={"Content-Type": "application/json", "X-Flagwake-Token": self.token},
                )
                try:
                    urllib.request.urlopen(req, timeout=2).close()  # noqa: S310 (local only)
                except OSError:
                    pass  # a callback that is down misses the event; polling still works

    def close(self) -> None:
        self.q.put(None)


# ------------------------------------------------------------------------ MCP (JSON-RPC)


def mcp_handle(desk: TicketDesk, msg: Any) -> dict[str, Any] | None:
    """Answer one JSON-RPC message (None for a notification)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return _rpc_error(None, -32600, "not a JSON-RPC 2.0 message")
    mid, method = msg.get("id"), msg.get("method")
    if mid is None:
        return None  # notifications (initialized, cancelled) need no answer
    raw = msg.get("params")
    params: dict[str, Any] = raw if isinstance(raw, dict) else {}
    if method == "initialize":
        return _rpc(
            mid,
            {
                "protocolVersion": MCP_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "flagwake-company", "version": __version__},
            },
        )
    if method == "ping":
        return _rpc(mid, {})
    if method == "tools/list":
        return _rpc(mid, {"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name")
        if name not in TOOL_NAMES:
            return _rpc_error(mid, -32602, f"unknown tool {str(name)[:40]!r}")
        resp = desk.call(name, params.get("arguments", {}))
        return _rpc(mid, {"content": [{"type": "text", "text": json.dumps(resp, sort_keys=True)}],
                          "isError": not resp.get("ok", False)})  # fmt: skip
    return _rpc_error(mid, -32601, f"method not found: {str(method)[:40]}")


def _rpc(mid: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _rpc_error(mid: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def serve_stdio(desk: TicketDesk, stdin: Any = None, stdout: Any = None) -> None:
    """MCP over stdio: one JSON-RPC message per line until stdin closes or the run is complete."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line[:MAX_BODY])
        except (ValueError, RecursionError):
            out: dict[str, Any] | None = _rpc_error(None, -32700, "not JSON")
        else:
            out = mcp_handle(desk, msg)
        if out is not None:
            stdout.write(json.dumps(out, sort_keys=True) + "\n")
            stdout.flush()


# ------------------------------------------------------------------------ OpenAPI


def openapi() -> dict[str, Any]:
    """The OpenAPI 3.0 document of the REST API (one POST per tool, plus the alert poll)."""
    paths: dict[str, Any] = {
        "/v1/alerts": {"get": {"summary": "the same as get_alerts", "operationId": "poll_alerts",
                               "responses": {"200": {"description": "tool response"}}}},
        "/v1/webhooks": {"post": {
            "summary": "register a callback URL on this machine for ticket and alert events",
            "operationId": "register_webhook",
            "requestBody": {"required": True, "content": {"application/json": {"schema": {
                "type": "object", "properties": {"url": {"type": "string"}},
                "required": ["url"]}}}},
            "responses": {"200": {"description": "registered"}}}},
    }  # fmt: skip
    for t in TOOLS:
        paths[f"/v1/tools/{t['name']}"] = {"post": {
            "summary": t["description"], "operationId": t["name"],
            "requestBody": {"required": False,
                            "content": {"application/json": {"schema": t["inputSchema"]}}},
            "responses": {"200": {"description": "tool response: ok, result or error, time, "
                                                 "ticket_open, events"}}}}  # fmt: skip
    return {
        "openapi": "3.0.3",
        "info": {"title": "Flagwake simulated company", "version": __version__},
        "servers": [{"url": "/"}],
        "components": {"securitySchemes": {"token": {"type": "http", "scheme": "bearer"}}},
        "security": [{"token": []}],
        "paths": paths,
    }


# ------------------------------------------------------------------------ HTTP server


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def handle_error(self, request: Any, client_address: Any) -> None:
        """A defender that hangs up (it was stopped, or closed a kept-alive connection) is normal
        at the end of a run; anything else is still printed."""
        if isinstance(sys.exc_info()[1], ConnectionError):
            return
        super().handle_error(request, client_address)


class ToolsServer:
    """REST + MCP over HTTP on 127.0.0.1 for one desk."""

    def __init__(self, desk: TicketDesk, port: int = 0, token: str | None = None) -> None:
        self.desk = desk
        self.token = token or secrets.token_urlsafe(24)
        self.hooks = Webhooks(self.token)
        desk.listeners.append(self.hooks)
        handler = _make_handler(self)
        self.httpd = _Server(("127.0.0.1", port), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def addresses(self) -> dict[str, str]:
        return {"mcp": self.base + "/mcp", "api": self.base + "/v1",
                "openapi": self.base + "/openapi.json", "token": self.token}  # fmt: skip

    def env(self) -> dict[str, str]:
        a = self.addresses()
        return {
            "FLAGWAKE_MCP_URL": a["mcp"],
            "FLAGWAKE_API_URL": a["api"],
            "FLAGWAKE_OPENAPI_URL": a["openapi"],
            "FLAGWAKE_TOOLS_TOKEN": a["token"],
        }

    def start(self) -> ToolsServer:
        self.thread.start()
        return self

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.hooks.close()


class _Handler(http.server.BaseHTTPRequestHandler):
    """One request to the tools server; ``tools`` is set per server (see below)."""

    tools: ToolsServer
    server_version = "flagwake-tools"
    sys_version = ""

    def log_message(self, *a: Any) -> None:  # quiet
        return

    def _send(self, code: int, obj: Any) -> None:
        body = json.dumps(obj, sort_keys=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _drain(self) -> None:
        """Read a small unread body before closing, so the refusal reaches the sender."""
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if 0 < n <= 16 * MAX_BODY:
            self.rfile.read(n)
        self.close_connection = True

    def _authed(self) -> bool:
        got = self.headers.get("Authorization", "")
        want = "Bearer " + self.tools.token
        if hmac.compare_digest(got.encode("utf-8", "replace"), want.encode("utf-8")):
            return True
        if self.command == "POST":
            self._drain()
        self._send(401, {"ok": False, "error": "missing or wrong bearer token"})
        return False

    def _body(self) -> Any:
        if self.headers.get_content_type() != "application/json":
            self._drain()
            self._send(415, {"ok": False, "error": "send application/json"})
            return ...
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if not 0 <= n <= MAX_BODY:
            if 0 < n <= 16 * MAX_BODY:  # read it first, so the refusal reaches the sender
                self.rfile.read(n)
            self.close_connection = True
            self._send(413, {"ok": False, "error": f"body larger than {MAX_BODY} bytes"})
            return ...
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError, RecursionError):
            self._send(400, {"ok": False, "error": "the body is not JSON"})
            return ...

    def do_GET(self) -> None:  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        if path == "/openapi.json":
            return self._send(200, openapi())
        if not self._authed():
            return None
        if path == "/v1/alerts":
            return self._send(200, self.tools.desk.call("get_alerts", {}))
        if path == "/v1/tools":
            return self._send(200, {"tools": TOOLS})
        return self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        if not self._authed():
            return None
        body = self._body()
        if body is ...:
            return None
        if path == "/mcp":
            out = mcp_handle(self.tools.desk, body)
            if out is None:
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None
            return self._send(200, out)
        if path == "/v1/webhooks":
            err = self.tools.hooks.add(str(body.get("url", "")) if isinstance(body, dict) else "")
            return self._send(400 if err else 200, {"ok": not err, "error": err} if err
                              else {"ok": True})  # fmt: skip
        if path.startswith("/v1/tools/"):
            name = path[len("/v1/tools/") :]
            if name not in TOOL_NAMES:
                return self._send(404, {"ok": False, "error": f"no tool {name[:40]!r}"})
            return self._send(200, self.tools.desk.call(name, body))
        return self._send(404, {"ok": False, "error": "not found"})

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send(405, {"ok": False, "error": "not allowed"})


def _make_handler(server: ToolsServer) -> type[http.server.BaseHTTPRequestHandler]:
    """The request handler class bound to one server (its desk, token and webhooks)."""
    return type("Handler", (_Handler,), {"tools": server})


# ------------------------------------------------------------------------ running defenders


def native_to_call(line: str, sources: frozenset[str] = frozenset()) -> tuple[str, dict[str, Any]]:
    """The tool call that does what a native command does (used to drive the shipped programs
    through the tool layer, so the two modes can be compared on the same decisions)."""
    verb, args, rest = parse_command(line)
    one = args[0] if args else ""
    if verb == "look":
        return "get_alerts", {}
    if verb == "hosts":
        return "list_hosts", {}
    if verb == "logs" and args:
        out: dict[str, Any] = {"source" if one in sources else "host": one}
        if len(args) > 1 and digits(args[1]):
            out["minutes"] = int(args[1])
        return "search_logs", out
    if verb == "who":
        return "get_user", {"account": one}
    if verb == "ask" and len(args) > 1:
        return "contact_user", {"account": one, "topic": args[1]}
    simple = {"isolate": ("isolate_host", "host"), "release": ("release_host", "host"),
              "reset": ("reset_credentials", "account"), "restore": ("restore_host", "host"),
              "patch": ("patch_host", "host"), "pause": ("pause_flow", "flow"),
              "resume": ("resume_flow", "flow")}  # fmt: skip
    if verb in simple and args:
        tool, key = simple[verb]
        out = {key: one}
        if verb == "isolate" and len(args) > 1 and digits(args[1]):
            out["minutes"] = int(args[1])
        return tool, out
    if verb == "block" and args:
        from cyberarena.rc.engine import looks_like_ip

        return ("block_address", {"address": one}) if looks_like_ip(one) else (
            "disable_account", {"account": one})  # fmt: skip
    if verb == "escalate":
        v2, a2, _ = parse_command(rest)
        action = {"isolate": "isolate_host", "restore": "restore_host", "block": "disable_account",
                  "reset": "reset_credentials", "pause": "pause_flow",
                  "resume": "resume_flow"}.get(v2, v2)  # fmt: skip
        return "request_approval", {"action": action, "target": a2[0] if a2 else ""}
    if verb == "notify":
        role, _, text = rest.partition(" ")
        return "notify_role", {"role": role, "message": text or "-"}
    if verb == "wait" and args and digits(args[0]):
        return "wait", {"minutes": int(args[0])}
    if verb == "report":
        try:
            body = json.loads(rest) if rest.startswith("{") else {"summary": rest}
        except (ValueError, RecursionError):
            body = {"summary": rest}
        keep = {k: body[k] for k in ("summary", "compromised", "confidence", "suspicious_text")
                if k in body}  # fmt: skip
        return "close_ticket", keep
    return verb or "unknown", {"line": line[:200]}


def run_program_as_tools(name: str, desk: TicketDesk) -> None:
    """Drive a shipped program through the tool layer until the run is complete."""
    from cyberarena.rc.baselines import ALL_AGENTS

    sources = frozenset(s["source"] for s in desk.world.log_sources) - set(desk.world.host)
    while desk.current is not None:
        agent = ALL_AGENTS[name]()
        inc = desk.current
        while desk.current is inc and not inc.done:
            line = agent.next_command(inc.shift)
            if line is None:
                desk.expire("the program stopped without closing the ticket")
                break
            tool, args = native_to_call(line, sources)
            desk.call(tool, args)


def run_command_as_tools(argv: list[str], desk: TicketDesk, folder: Path, out: Path,
                         wall_timeout: float) -> None:  # fmt: skip
    """Start a defender with the tool addresses in its environment; wait for the run to end."""
    server = ToolsServer(desk).start()
    out.mkdir(parents=True, exist_ok=True)
    env = {**child_env(), **server.env()}  # never the job's signing tokens
    with open(out / "agent-stderr.log", "ab") as err:
        proc = subprocess.Popen(argv, cwd=str(folder), env=env, stdin=subprocess.DEVNULL,
                                stdout=err, stderr=err)  # fmt: skip
        t0 = time.monotonic()
        try:
            while not desk.complete.wait(0.2):
                if proc.poll() is not None:
                    desk.stop_all("the defender exited before closing every ticket")
                    break
                if desk.idle():
                    desk.expire(f"no tool call within {desk.idle_timeout:.0f} s")
                if time.monotonic() - t0 > wall_timeout:
                    desk.stop_all("the run reached its time limit")
                    break
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            server.close()


def run_tools_entry(
    entry: dict[str, Any],
    folder: Path,
    out: Path,
    specs: list[dict[str, Any]],
    repeat: int,
    world: World,
    key: str | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """``flagwake run`` for an entry with ``mode: tools``: (run result, fidelity disclosure)."""
    from cyberarena.rc.registry import caps_of

    caps = caps_of(entry)
    desk = TicketDesk(specs, world, repeat, idle_timeout=float(caps["incident_timeout"]), key=key,
                      max_commands=int(caps["max_commands"]))  # fmt: skip
    if entry["kind"] == "baseline":
        run_program_as_tools(entry["baseline"], desk)
        adapter = "built-in program (environment as tools)"
    else:
        from cyberarena.rc.cli import split_command

        wall = float(caps["incident_timeout"]) * max(1, desk.total)
        run_command_as_tools(split_command(entry["command"]), desk, folder, out, wall)
        adapter = "command (environment as tools)"
    return desk.result(), {"mode": TOOLS_MODE, "adapter": adapter, "instruction_text": "none"}
