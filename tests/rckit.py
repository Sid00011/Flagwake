"""A local fake chat-completions server for the model-agent and doctor tests (no real model).

It answers each request from a script of behaviours, cycling: ("ok", text), ("http", status),
("raw", bytes), ("slow", seconds) and ("other", x) for a JSON body without choices.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeModel:
    """A chat-completions server on 127.0.0.1 that replays a script of behaviours, cycling."""

    def __init__(self, script: list[tuple[str, object]]) -> None:
        self.script = script
        self.i = 0
        self.requests: list[dict] = []
        self.lock = threading.Lock()
        model = self

        class H(BaseHTTPRequestHandler):
            def handle(self):
                try:
                    super().handle()
                except ConnectionError:  # the client gave up on a slow reply
                    pass

            def do_POST(self):  # noqa: N802 (http.server API)
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                with model.lock:
                    kind, arg = model.script[model.i % len(model.script)]
                    model.i += 1
                    model.requests.append(
                        {"auth": self.headers.get("Authorization"), "body": body, "path": self.path}
                    )
                if kind == "slow":
                    time.sleep(float(arg))
                    kind, arg = "ok", "look"
                if kind == "http":
                    self.send_response(int(arg))
                    self.end_headers()
                    return
                if kind == "rate":  # rate limited: try again after arg seconds
                    self.send_response(429)
                    self.send_header("Retry-After", str(arg))
                    self.end_headers()
                    return
                if kind == "raw":
                    data = bytes(arg)
                else:
                    reply = {
                        "choices": [{"message": {"role": "assistant", "content": arg}}],
                        "usage": {"prompt_tokens": 100, "completion_tokens": 7},
                        "model": "fake-model-2026-01",  # the id the server says answered
                    }
                    data = json.dumps(reply if kind == "ok" else {"unexpected": arg}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/v1"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()
