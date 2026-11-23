"""The flash helper can restore the official image without a custom one."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from blueair_cloudcutter.context import Context
from blueair_cloudcutter.errors import CutterError
from blueair_cloudcutter.helpers import flash


def _args(**overrides):
    values = {
        "custom": None,
        "official": None,
        "dry_run": False,
        "version": "1.0.6",
        "image_name": None,
        "pad": 123,
        "settle": 2.0,
        "no_reset": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_official_only_restores_the_passive_slot(tmp_path, monkeypatch):
    image = tmp_path / "official.bin"
    image.write_bytes(b"\xe9" + b"\x00" * 99)
    ctx = Context(output=tmp_path / "out")
    calls = []
    monkeypatch.setattr(flash.install, "restore_official", lambda ctx, **kw: calls.append(kw) or 0)

    assert flash.run(ctx, _args(official=image)) == 0

    assert calls[0]["official"] == b"\xe9" + b"\x00" * 99
    assert calls[0]["version"] == "1.0.6"


def test_flash_needs_custom_or_official(tmp_path):
    ctx = Context(output=tmp_path / "out")

    with pytest.raises(CutterError, match="--custom"):
        flash.run(ctx, _args())
