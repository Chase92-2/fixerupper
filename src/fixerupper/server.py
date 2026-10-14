"""Minimal local web server: serves the UI and a /api/analyze endpoint."""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from importlib import resources

from .analyzer import analyze
from .parser import ParseError, parse_events

DEFAULT_MAX_BYTES = 20 * 1024 * 1024


def make_handler(max_bytes):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                html = resources.files("fixerupper").joinpath("static/index.html").read_bytes()
                self._send(200, html, "text/html; charset=utf-8")
            elif self.path == "/healthz":
                self._send(200, {"status": "ok"})
            else:
                self._send(404, {"error": "Not found"})

        def do_POST(self):
            if self.path != "/api/analyze":
                return self._send(404, {"error": "Not found"})
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return self._send(411, {"error": "Content-Length required"})
            if length > max_bytes:
                return self._send(413, {"error": "File too large (limit %d bytes)" % max_bytes})
            body = self.rfile.read(length)
            try:
                self._send(200, analyze(parse_events(body)))
            except ParseError as exc:
                self._send(400, {"error": str(exc)})

        def log_message(self, fmt, *args):
            pass

    return Handler


def serve(host=None, port=None, max_bytes=None):
    host = host or os.environ.get("FIXERUPPER_HOST", "127.0.0.1")
    port = int(port if port is not None else os.environ.get("FIXERUPPER_PORT", 8765))
    max_bytes = int(max_bytes or os.environ.get("FIXERUPPER_MAX_BYTES", DEFAULT_MAX_BYTES))
    httpd = ThreadingHTTPServer((host, port), make_handler(max_bytes))
    print("FixerUpper running at http://%s:%d (Ctrl+C to stop)" % (host, httpd.server_address[1]))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
