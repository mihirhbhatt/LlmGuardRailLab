"""Small standard-library web UI backend for the guarded pipeline."""

from __future__ import annotations

import json
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import config
from audit import result_to_record

ROOT = Path(__file__).parent


class GuardHandler(SimpleHTTPRequestHandler):
    pipeline = None
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT / "static"), **kwargs)

    def log_message(self, format, *args):
        return

    def _send_json(self, payload: dict, status: int = 200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/stats":
            self._send_json(self.pipeline.adaptive_guard.stats())
            return
        if path == "/api/audit":
            self._send_json({"events": self.pipeline.audit.tail(50)})
            return
        if path == "/":
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            if path == "/api/chat":
                prompt = self._read_json().get("prompt", "").strip()
                if not prompt:
                    self._send_json({"error": "Prompt is required."}, 400)
                    return
                with self.lock:
                    record = result_to_record(self.pipeline.run(prompt))
                self._send_json(record)
                return
            if path == "/api/flag":
                with self.lock:
                    report = self.pipeline.flag_last()
                self._send_json({"report": report})
                return
            if path == "/api/reset":
                with self.lock:
                    self.pipeline.adaptive_guard.reset()
                self._send_json({"ok": True})
                return
            self._send_json({"error": "Not found."}, 404)
        except (json.JSONDecodeError, ValueError) as exc:
            self._send_json({"error": f"Invalid request: {exc}"}, 400)
        except Exception as exc:
            self._send_json({"error": str(exc)}, 500)


def serve(pipeline):
    GuardHandler.pipeline = pipeline
    server = ThreadingHTTPServer((config.WEB_HOST, config.WEB_PORT), GuardHandler)
    print(f"AI Guard web UI: http://127.0.0.1:{config.WEB_PORT}")
    print("Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping web UI.")
    finally:
        server.server_close()