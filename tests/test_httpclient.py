from __future__ import annotations

import http.client

import pytest

from blueair_cloudcutter.errors import TransportError
from blueair_cloudcutter.httpclient import DeviceHTTP


class _NoResponse:
    """Accept the request, then close without an HTTP response."""

    def __init__(self) -> None:
        self.closed = False

    def request(self, *args, **kwargs) -> None:
        pass

    def getresponse(self):
        raise http.client.RemoteDisconnected("Remote end closed connection without response")

    def close(self) -> None:
        self.closed = True


def _device(monkeypatch, conn) -> DeviceHTTP:
    http = DeviceHTTP("192.0.2.1")
    monkeypatch.setattr(http, "_connect", lambda timeout=None: conn)
    return http


def test_early_close_is_a_response_when_allowed(monkeypatch):
    conn = _NoResponse()
    http = _device(monkeypatch, conn)

    resp = http.request("POST", "/d/x/provision/image", body=b"body", allow_early_close=True)

    assert resp.status is None
    assert resp.peer_closed
    assert conn.closed


def test_early_close_still_raises_without_the_flag(monkeypatch):
    conn = _NoResponse()
    http = _device(monkeypatch, conn)

    with pytest.raises(TransportError):
        http.request("POST", "/d/x/provision/image", body=b"body", attempts=1)
