from __future__ import annotations

from types import SimpleNamespace

import pytest

import blueair_cloudcutter.mqttclient as mqttclient
from blueair_cloudcutter.mqttclient import MQTT

DID = "1cd9a74c-209c-436a-9ead-a81784ca265e"


def test_wait_for_device_uses_a_device_publication(monkeypatch):
    mqtt = MQTT.__new__(MQTT)
    mqtt._messages = []

    def subscribe(topic, qos=1):
        mqtt._messages.append((f"d/{DID}/s/event", "{}"))
        return (0, 1)

    mqtt._client = SimpleNamespace(subscribe=subscribe)
    monkeypatch.setattr(mqttclient.time, "sleep", lambda _seconds: None)

    assert mqtt.wait_for_device(DID, timeout=1.0)


def test_wait_for_device_times_out(monkeypatch):
    mqtt = MQTT.__new__(MQTT)
    mqtt._messages = []
    mqtt._client = SimpleNamespace(subscribe=lambda *a, **k: (0, 1))

    def stop(_seconds):
        raise TimeoutError

    monkeypatch.setattr(mqttclient.time, "sleep", stop)
    monkeypatch.setattr(mqttclient.time, "time", lambda: 0)

    with pytest.raises(TimeoutError):
        mqtt.wait_for_device(DID, timeout=1.0)
