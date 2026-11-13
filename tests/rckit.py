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


GITHUB_ISSUER = "https://token.actions.githubusercontent.com"


class FakeRekor:
    """A public log in memory that answers like Sigstore's: digest -> entries. Each entry carries a
    "certificate" that is just its facts as JSON; ``trusted`` says whether Sigstore issued it."""

    def __init__(self) -> None:
        self.by_digest: dict[str, list[str]] = {}
        self.entries: dict[str, dict] = {}

    def add(
        self,
        digest: str,
        repo_id: str,
        run: int = 1,
        attempt: int = 1,
        issuer: str = GITHUB_ISSUER,
        trusted: bool = True,
        when: int = 50,
    ) -> int:
        import base64

        facts = {
            "issuer": issuer,
            "repository_id": repo_id,
            "run_uri": f"https://github.com/example-org/defender/actions/runs/{run}/attempts/{attempt}",
            "trusted": trusted,
        }
        verifier = base64.b64encode(json.dumps(facts).encode()).decode()
        body = {"kind": "dsse", "spec": {"signatures": [{"verifier": verifier}]}}
        uuid = f"u{len(self.entries)}"
        index = 1000 + len(self.entries)
        encoded = base64.b64encode(json.dumps(body).encode()).decode()
        self.entries[uuid] = {"body": encoded, "logIndex": index, "integratedTime": when}
        self.by_digest.setdefault(digest, []).append(uuid)
        return index

    def fetch(self, url: str, body: bytes | None):
        if url.endswith("/index/retrieve"):
            return self.by_digest.get(json.loads(body)["hash"].removeprefix("sha256:"), [])
        uuid = url.rsplit("/", 1)[1]
        return {uuid: self.entries[uuid]}

    def log(self):
        from cyberarena.rc.attempt import Log

        def facts(pem: bytes, _when: int):
            said = json.loads(pem)
            return {k: v for k, v in said.items() if k != "trusted"} if said["trusted"] else None

        return Log(fetch=self.fetch, facts=facts)
