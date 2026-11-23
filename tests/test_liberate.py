"""Restoring the stock trust anchor."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from blueair_cloudcutter import liberate
from blueair_cloudcutter.context import Context
from blueair_cloudcutter.errors import CutterError


def test_restore_roots_writes_the_stock_root_and_clears_the_marker(tmp_path, monkeypatch):
    ctx = Context(output=tmp_path)
    ctx.did = "device-id"
    ctx.state.mark("liberate", broker="broker.local")
    calls = []
    monkeypatch.setattr(liberate, "plant_cert_mqtt", lambda **kwargs: calls.append(kwargs))

    args = SimpleNamespace(
        transport="mqtt",
        broker="broker.local",
        broker_port=8883,
        ca=None,
        cert=None,
        key=None,
        insecure=False,
    )

    assert liberate.restore_roots(ctx, args) == 0

    assert calls[0]["slot"] == "c-r"
    assert calls[0]["host"] == "broker.local"
    assert calls[0]["what"] == "stock root"
    assert "BEGIN CERTIFICATE" in calls[0]["cert_text"]
    assert "liberate" not in ctx.state.steps


def test_restore_roots_requires_a_broker_for_mqtt(tmp_path):
    ctx = Context(output=tmp_path)
    ctx.did = "device-id"
    args = SimpleNamespace(
        transport="mqtt",
        broker=None,
        broker_port=8883,
        ca=None,
        cert=None,
        key=None,
        insecure=False,
    )

    with pytest.raises(CutterError, match="--broker"):
        liberate.restore_roots(ctx, args)
