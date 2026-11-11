"""A fake local model server for the page's tests: GET /v1/models and POST /v1/chat/completions.

Each conversation gets "look" first and a JSON report after; model names and the required key
are configurable, and every Authorization header it receives is recorded.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeServer:
    def __init__(self, models=("tiny-model",), key: str | None = None) -> None:
        self.models = list(models)
        self.key = key
        self.auth: list[str] = []
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *_a):
                pass

            def _send(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802
                if self.path == "/v1/models":
                    self._send(200, {"data": [{"id": m} for m in fake.models]})
                else:
                    self._send(404, {})

            def do_POST(self):  # noqa: N802
                auth = self.headers.get("Authorization", "")
                fake.auth.append(auth)
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if fake.key and auth != f"Bearer {fake.key}":
                    self._send(401, {"error": "bad key"})
                    return
                said = sum(1 for m in body["messages"] if m["role"] not in ("system", "user"))
                text = (
                    "look"
                    if said == 0
                    else ('report {"compromised": [], "confidence": {}, "summary": "checked"}')
                )
                self._send(
                    200,
                    {
                        "choices": [{"message": {"content": text}}],
                        "usage": {"prompt_tokens": 10, "completion_tokens": 2},
                    },
                )

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}/v1"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
