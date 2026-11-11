"""``flagwake serve`` and ``flagwake view``: a localhost-only static server for the report viewer.

It binds 127.0.0.1 only, serves a fixed set of files from the packaged ``web/rc`` copy (no
directory listing, no path traversal, no range of routes beyond the allowlist), and makes no
outbound request. ``flagwake view`` adds exactly one more route, ``/report.json``, which returns
the one report file it was given, and opens the viewer on it. Nothing outside the packaged
folder and that one file is ever served.
"""

from __future__ import annotations

import http.server
import socketserver
import webbrowser
from pathlib import Path

WEB = Path(__file__).resolve().parent / "web"
ALLOW = {
    "/": "viewer.html",
    "/viewer.html": "viewer.html",
    "/css/rc.css": "css/rc.css",
    "/js/viewer.js": "js/viewer.js",
}
TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "flagwake-rc"
    report: Path | None = None  # set on a subclass by flagwake view

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        path = self.path.split("?", 1)[0]
        if path == "/report.json" and self.report is not None:
            self._send(self.report.read_bytes(), TYPES[".json"])
            return
        rel = ALLOW.get(path)
        if rel is None:
            self.send_error(404, "not found")
            return
        target = (WEB / rel).resolve()
        if not str(target).startswith(str(WEB.resolve())) or not target.is_file():
            self.send_error(404, "not found")
            return
        self._send(target.read_bytes(), TYPES.get(target.suffix, "application/octet-stream"))

    def _send(self, body: bytes, ctype: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; connect-src 'self'; "
            "style-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:  # keep the console quiet
        pass


def make_server(port: int = 8077, report: Path | None = None) -> socketserver.TCPServer:
    """A server bound to 127.0.0.1; with ``report``, it also serves that file as /report.json."""
    handler = type("ViewHandler", (Handler,), {"report": report}) if report else Handler
    return socketserver.TCPServer(("127.0.0.1", port), handler)


def serve(port: int = 8077, report: Path | None = None, open_browser: bool = False) -> int:
    try:
        httpd = make_server(port, report)
    except OSError as exc:
        print(f"error: cannot listen on 127.0.0.1:{port} ({exc}); try --port", flush=True)
        return 2
    url = f"http://127.0.0.1:{httpd.server_address[1]}/" + ("?report=latest" if report else "")
    with httpd:
        print(f"Responder Check report viewer on {url} (Ctrl+C to stop)")
        if report:
            print(f"showing {report}")
        print("Local only; nothing is sent anywhere.")
        if open_browser:
            webbrowser.open(url)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
    return 0
