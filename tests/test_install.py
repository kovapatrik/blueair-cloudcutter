"""Restoring the official image: a normal OTA upload, no STM32 entry."""

from __future__ import annotations

from blueair_cloudcutter.context import Context
from blueair_cloudcutter.firmware import install


def test_restore_official_uses_the_plain_upload(tmp_path, monkeypatch):
    ctx = Context(output=tmp_path)
    ctx.ip = "192.0.2.1"
    ctx.did = "device-id"
    calls = {}

    def upload(http, did, token, official, **kwargs):
        calls.update(did=did, official=official, **kwargs)

    def arm(*args, **kwargs):
        raise AssertionError("restore must not use the STM32 arm")

    monkeypatch.setattr(install.chain, "upload_official", upload)
    monkeypatch.setattr(install.chain, "arm", arm)
    monkeypatch.setattr(install.chain, "reset", lambda *args, **kwargs: None)

    assert install.restore_official(ctx, official=b"\xe9" + b"\x00" * 9) == 0

    assert calls["did"] == "device-id"
    assert calls["official"].startswith(b"\xe9")
    assert calls["version"] == "1.0.9"
