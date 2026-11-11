"""A small stdio MCP server for the Responder Check (JSON-RPC 2.0 over stdin/stdout, stdlib only).

Tools:
  start_incident(family, seed, difficulty)  -> the opening observation
  run_command(command)                       -> the observation after the command
  incident_status()                          -> clock, commands used, whether it is closed
  finish_incident()                          -> ends the incident and writes a transcript file

The transcript is written under a chosen directory; ``flagwake report --mcp-log <dir>`` scores it
into the standard report. Only these four tools exist and they change only in-memory incident
state; the server runs no other code. It speaks the subset of MCP that a scripted client needs
(``initialize``, ``tools/list``, ``tools/call``); it is tested in CI with such a client.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

from cyberarena.rc import rules
from cyberarena.rc.engine import Shift
from cyberarena.rc.gen2 import DIFFICULTIES
from cyberarena.rc.runner import obs_hash
from cyberarena.rc.world import World

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "flagwake-rc", "version": "1"}


def tool_list(world: World) -> list[dict[str, Any]]:
    """The four tools; ``start_incident`` offers the families that can run in ``world``."""
    start = {
        "name": "start_incident",
        "description": "Start a Responder Check incident and return the opening observation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "family": {"type": "string", "enum": list(rules.families(world))},
                "seed": {"type": "integer"},
                "difficulty": {"type": "string", "enum": list(DIFFICULTIES)},
            },
            "required": ["family", "seed"],
        },
    }
    return [start, *OTHER_TOOLS]


OTHER_TOOLS: list[dict[str, Any]] = [
    {
        "name": "run_command",
        "description": "Run one command in the current incident and return the observation.",
        "inputSchema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
    {
        "name": "incident_status",
        "description": "The current clock, commands used and whether the incident is closed.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "finish_incident",
        "description": "End the incident and write a transcript file for flagwake report.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


class Server:
    """Holds one incident at a time and writes a transcript when it finishes."""

    def __init__(self, log_dir: str | None = None, world: World | None = None) -> None:
        self.world = world or rules.default_world()
        self.shift: Shift | None = None
        self.hashes: list[str] = []
        self.commands: list[str] = []
        self.spec: dict[str, Any] | None = None
        self.log_dir = Path(log_dir) if log_dir else Path("rc-mcp-log")

    def _tool_result(self, text: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
        if data is not None:
            out["structuredContent"] = data
        return out

    def start_incident(self, args: dict[str, Any]) -> dict[str, Any]:
        family = args.get("family")
        seed = args.get("seed", 0)
        if not isinstance(seed, int) or isinstance(seed, bool):
            raise ValueError("seed must be a whole number")
        difficulty = args.get("difficulty", "standard")
        if not isinstance(family, str) or family not in rules.families(self.world):
            raise ValueError(f"unknown family {family!r}")
        if not isinstance(difficulty, str) or difficulty not in DIFFICULTIES:
            raise ValueError(f"unknown difficulty {difficulty!r}")
        inc = rules.generate(self.world, family, seed, difficulty)
        self.spec = {"family": family, "seed": seed, "difficulty": difficulty}
        self.shift = Shift(inc, self.world)
        first = self.shift.reset()
        self.hashes = [obs_hash(first["text"])]
        self.commands = []
        return self._tool_result(first["text"], {"t": first["t"], "done": False})

    def run_command(self, args: dict[str, Any]) -> dict[str, Any]:
        if self.shift is None:
            raise ValueError("no incident is running; call start_incident first")
        if self.shift.done:
            raise ValueError("the incident is closed; call finish_incident")
        cmd = str(args.get("command", ""))[:4000]
        obs, info = self.shift.step(cmd)
        self.commands.append(cmd)
        self.hashes.append(obs_hash(obs["text"]))
        return self._tool_result(obs["text"], {"t": obs["t"], "done": obs["done"]})

    def incident_status(self, args: dict[str, Any]) -> dict[str, Any]:
        if self.shift is None:
            return self._tool_result("No incident is running.", {"running": False})
        s = self.shift
        data = {
            "running": True,
            "t": s.now,
            "commands": len(s.commands),
            "done": s.done,
            "incident": f"{self.spec['family']}:{self.spec['seed']}" if self.spec else None,
        }
        return self._tool_result(json.dumps(data), data)

    def finish_incident(self, args: dict[str, Any]) -> dict[str, Any]:
        if self.shift is None:
            raise ValueError("no incident to finish")
        self.shift.finish()
        self.log_dir.mkdir(parents=True, exist_ok=True)
        assert self.spec is not None
        transcript = {
            "schema": "flagwake-rc-transcript-1",
            "rules": self.world.rules,
            "world": self.world.summary(),
            "family": self.spec["family"],
            "seed": self.spec["seed"],
            "difficulty": self.spec["difficulty"],
            "commands": self.commands,
            "obs_hashes": self.hashes,
            "end_reason": self.shift.end_reason,
        }
        stem = f"{self.spec['family']}-{self.spec['seed']}-{int(time.time())}"
        path = self.log_dir / f"{stem}.json"
        n = 1
        while path.exists():  # two finishes in one second must not overwrite each other
            n += 1
            path = self.log_dir / f"{stem}-{n}.json"
        path.write_text(
            json.dumps(transcript, sort_keys=True, indent=1) + "\n", encoding="utf-8", newline="\n"
        )
        data = {"written": str(path), "commands": len(self.commands), "done": True}
        self.shift = None
        return self._tool_result(f"Incident closed; transcript written to {path}.", data)

    # ----------------------------------------------------------------- JSON-RPC
    def handle(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        method = msg.get("method")
        mid = msg.get("id")
        if method == "initialize":
            return _ok(
                mid,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": SERVER_INFO,
                },
            )
        if method in ("notifications/initialized", "initialized"):
            return None
        if method == "tools/list":
            return _ok(mid, {"tools": tool_list(self.world)})
        if method == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name")
            args = params.get("arguments") or {}
            fn = {
                "start_incident": self.start_incident,
                "run_command": self.run_command,
                "incident_status": self.incident_status,
                "finish_incident": self.finish_incident,
            }.get(name if isinstance(name, str) else "")
            if fn is None:
                return _err(mid, -32601, f"unknown tool {name!r}")
            try:
                return _ok(mid, fn(args))
            except Exception as exc:  # report tool errors as content, not transport errors
                return _ok(
                    mid,
                    {
                        "content": [{"type": "text", "text": f"error: {exc}"}],
                        "isError": True,
                    },
                )
        if mid is not None:
            return _err(mid, -32601, f"unknown method {method!r}")
        return None


def _ok(mid: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def serve(
    stdin: Any = None, stdout: Any = None, log_dir: str | None = None, world: World | None = None
) -> int:
    """Read JSON-RPC messages line by line from stdin; write responses to stdout."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    server = Server(log_dir, world)
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            stdout.write(json.dumps(_err(None, -32700, "parse error")) + "\n")
            stdout.flush()
            continue
        if not isinstance(msg, dict):
            stdout.write(json.dumps(_err(None, -32600, "invalid request")) + "\n")
            stdout.flush()
            continue
        resp = server.handle(msg)
        if resp is not None:
            stdout.write(json.dumps(resp, ensure_ascii=True) + "\n")
            stdout.flush()
    return 0
