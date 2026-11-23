from __future__ import annotations

from blueair_cloudcutter.errors import TransportError
from blueair_cloudcutter.firmware import chain


class _HTTP:
    def __init__(self, exc: Exception | None = None) -> None:
        self.exc = exc
        self.kwargs: dict = {}

    def get(self, path, token, **kwargs):
        self.kwargs = kwargs
        if self.exc:
            raise self.exc
        return "reply"


def test_reset_does_not_wait_for_the_image_timeout():
    http = _HTTP()

    chain.reset(http, "did", "token")  # type: ignore[arg-type]

    assert http.kwargs["timeout"] <= 30
    assert http.kwargs["attempts"] == 1
    assert http.kwargs["allow_early_close"]


def test_reset_tolerates_a_missing_response():
    http = _HTTP(TransportError("timed out"))

    assert chain.reset(http, "did", "token") is None  # type: ignore[arg-type]


class _PostHTTP:
    timeout = 0.0

    def __init__(self) -> None:
        self.body = b""

    def request(self, method, path, *, body=b"", headers=None, **kwargs):
        self.body = body
        return chain.Response(400, "Bad Request", "OTA end failed", 0.0)


def test_swap_uses_the_requested_image_name():
    http = _PostHTTP()

    chain.swap(  # type: ignore[arg-type]
        http,
        "did",
        "token",
        b"\xe9" + b"\x00" * 99,
        version="1.0.9",
        settle=0,
        image_name="ba_gp_wifi.bin",
    )

    assert b'"image": "ba_gp_wifi.bin"' in http.body
    assert b'filename="ba_gp_wifi.bin"' in http.body
