"""Minimal BlueAir provisioning backend.

The device calls its `api_url`/`auth_url` before it connects to the broker.
Serving the captured valid responses lets provisioning finish without the
BlueAir cloud. Plain HTTP is fine; the device accepts an `http://` URL.

Paths:
    POST .../authenticate           -> auth_resp.json
    POST .../register-device-hash   -> register_resp.json
    anything else                   -> {"message": "ok"} / {"ok": true}
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .util import info

DATA = Path(__file__).resolve().parent / "data" / "fake_backend"


def _load(name: str, default: dict) -> dict:
    try:
        return json.loads((DATA / name).read_text())
    except (OSError, json.JSONDecodeError):
        return default


class _Handler(BaseHTTPRequestHandler):
    server_version = "BlueAirFakeApi/1.0"

    def _send(self, obj: dict, code: int = 200) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        info(f"fake API POST {self.path} ({len(body)} B)")
        if "authenticate" in self.path:
            self.server.auth_seen.set()  # type: ignore[attr-defined]
            self._send(self.server.auth_resp)  # type: ignore[attr-defined]
        elif "register-device-hash" in self.path:
            self.server.register_seen.set()  # type: ignore[attr-defined]
            self._send(self.server.register_resp)  # type: ignore[attr-defined]
        else:
            self._send({"message": "ok"})

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        info(f"fake API GET {self.path}")
        self._send({"ok": True})

    def log_message(self, *args) -> None:
        pass


class FakeApiServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8000, data_dir: Path | None = None) -> None:
        global DATA
        if data_dir is not None:
            DATA = data_dir
        self.httpd = ThreadingHTTPServer((host, port), _Handler)
        self.httpd.daemon_threads = True
        self.httpd.auth_seen = threading.Event()  # type: ignore[attr-defined]
        self.httpd.register_seen = threading.Event()  # type: ignore[attr-defined]
        self.httpd.auth_resp = _load("auth_resp.json", {})  # type: ignore[attr-defined]
        self.httpd.register_resp = _load(  # type: ignore[attr-defined]
            "register_resp.json", {"message": "The request was successfully Activated."}
        )
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return int(self.httpd.server_address[1])

    def start(self) -> FakeApiServer:
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def reset(self) -> None:
        """Clear the seen flags before a second provisioning run."""
        self.httpd.auth_seen.clear()  # type: ignore[attr-defined]
        self.httpd.register_seen.clear()  # type: ignore[attr-defined]

    def urls(self, gateway: str) -> tuple[str, str]:
        base = f"http://{gateway}:{self.port}/prod"
        return base, f"{base}/c/authenticate"

    def wait_for_provisioning(self, timeout: float = 60.0) -> bool:
        """Wait until the device has called both provisioning endpoints."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.provisioning_complete:
                return True
            time.sleep(0.2)
        return self.provisioning_complete

    @property
    def provisioning_complete(self) -> bool:
        return bool(  # type: ignore[attr-defined]
            self.httpd.auth_seen.is_set() and self.httpd.register_seen.is_set()
        )

    def __enter__(self) -> FakeApiServer:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
