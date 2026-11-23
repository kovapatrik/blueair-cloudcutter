"""listen() should stop as soon as the wanted message arrives."""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

import blueair_cloudcutter.mqttclient as mqttclient
from blueair_cloudcutter.mqttclient import MQTT


def test_listen_stops_on_match(monkeypatch):
    mqtt = MQTT.__new__(MQTT)
    mqtt._messages = []

    def subscribe(*args, **kwargs):
        mqtt._messages.append(("d/1cd9a74c-209c-436a-9ead-a81784ca265e/s/event", "{}"))

    mqtt._client = SimpleNamespace(subscribe=subscribe)

    monkeypatch.setattr(mqttclient.time, "sleep", lambda _seconds: None)

    started = time.monotonic()
    messages = mqtt.listen(
        "#",
        wait=30,
        stop_when=lambda topic, payload: "1cd9a74c" in topic,
    )
    elapsed = time.monotonic() - started

    assert messages
    assert elapsed < 5


def test_listen_waits_when_no_match(monkeypatch):
    mqtt = MQTT.__new__(MQTT)
    mqtt._messages = []
    mqtt._client = SimpleNamespace(subscribe=lambda *a, **k: None)

    calls = {"n": 0}

    def fake_sleep(_seconds):
        calls["n"] += 1
        if calls["n"] > 100:
            raise TimeoutError

    monkeypatch.setattr(mqttclient.time, "sleep", fake_sleep)
    monkeypatch.setattr(mqttclient.time, "time", lambda: 0)

    with pytest.raises(TimeoutError):
        mqtt.listen("#", wait=10, stop_when=lambda topic, payload: False)
