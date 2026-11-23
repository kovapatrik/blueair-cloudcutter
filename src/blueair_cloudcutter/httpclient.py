"""HTTPS client for the device's factory-mode server.

The device presents a self-signed certificate and expects the caller to present
a JWT, not a client certificate. Certificate validation is therefore disabled;
the only thing that matters is that the peer is the device on the LAN.
"""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import time
from dataclasses import dataclass

from .errors import DeviceError, TransportError


def _context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# The factory handler returns -1 without writing a response on the MCU-size
# bail path, so the socket is closed after a complete request. The same shape
# appears when the signature check rejects the image. Both are expected.
_PEER_CLOSE_ERRORS = (
    ConnectionResetError,
    BrokenPipeError,
    ssl.SSLEOFError,
    http.client.RemoteDisconnected,
    http.client.BadStatusLine,
)


def _peer_closed(exc: BaseException) -> bool:
    return isinstance(exc, _PEER_CLOSE_ERRORS)


@dataclass
class Response:
    status: int | None
    reason: str
    body: str
    elapsed: float
    peer_closed: bool = False

    @property
    def ok(self) -> bool:
        return self.status == 200

    @property
    def json(self):
        try:
            return json.loads(self.body)
        except (TypeError, json.JSONDecodeError):
            return None

    def __str__(self) -> str:
        return f"HTTP {self.status} {self.reason} ({self.elapsed:.1f}s) {self.body[:300]!r}"


class DeviceHTTP:
    def __init__(
        self,
        host: str,
        port: int = 443,
        timeout: float = 30.0,
        bind: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.bind = bind

    def _connect(self, timeout: float | None = None) -> http.client.HTTPSConnection:
        src = (self.bind, 0) if self.bind else None
        return http.client.HTTPSConnection(
            self.host,
            self.port,
            context=_context(),
            timeout=timeout or self.timeout,
            source_address=src,
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
        declared_length: int | None = None,
        attempts: int = 3,
        allow_early_close: bool = False,
        timeout: float | None = None,
    ) -> Response:
        """Send a request, retrying only connection setup failures.

        `declared_length` lets the caller advertise more bytes than are sent.
        That is the MCU-stage bail trigger; see `firmware/multipart.py`.
        """
        hdrs = dict(headers or {})
        hdrs.setdefault("Content-Length", str(declared_length if declared_length is not None else len(body)))

        last: Exception | None = None
        for attempt in range(1, attempts + 1):
            conn = self._connect(timeout)
            t0 = time.time()
            peer_closed = False
            try:
                conn.request(method, path, body=body, headers=hdrs)
            except (BrokenPipeError, ssl.SSLEOFError, ConnectionResetError) as exc:
                peer_closed = True
                last = exc
                if not allow_early_close:
                    conn.close()
                    raise TransportError(
                        f"peer closed while sending to {self.host}:{self.port}: {exc}"
                    ) from exc
            except OSError as exc:
                last = exc
                conn.close()
                if attempt < attempts:
                    time.sleep(1.5)
                    continue
                raise TransportError(f"cannot connect to {self.host}:{self.port}: {exc}") from exc
            try:
                resp = conn.getresponse()
                text = resp.read().decode("utf-8", "replace")
                return Response(resp.status, resp.reason, text, time.time() - t0, peer_closed)
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                last = exc
                conn.close()
                if allow_early_close and (peer_closed or _peer_closed(exc)):
                    return Response(None, "", "", time.time() - t0, peer_closed=True)
                if attempt < attempts:
                    time.sleep(1.5)
                    continue
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

        raise TransportError(f"request to {self.host}:{self.port}{path} failed: {last}")

    # -- convenience -------------------------------------------------------

    def post_json(self, path: str, obj, token: str, **kw) -> Response:
        body = json.dumps(obj).encode()
        return self.request(
            "POST",
            path,
            body=body,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            **kw,
        )

    def get(self, path: str, token: str, **kw) -> Response:
        return self.request("GET", path, headers={"Authorization": f"Bearer {token}"}, **kw)

    def alive(self, timeout: float = 4.0) -> bool:
        """TCP probe. Used to tell 'handler bailed out' from 'device rebooted'."""
        s = socket.socket()
        s.settimeout(timeout)
        try:
            if self.bind:
                s.bind((self.bind, 0))
            s.connect((self.host, self.port))
            return True
        except OSError:
            return False
        finally:
            try:
                s.close()
            except OSError:
                pass

    def wait_alive(self, timeout: float = 120.0, down_first: bool = True) -> bool:
        if down_first:
            time.sleep(3)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.alive(2.0):
                return True
            time.sleep(2)
        return False

    def require_ok(self, resp: Response, what: str) -> Response:
        if not resp.ok:
            raise DeviceError(f"{what} failed: {resp}")
        return resp
