"""Small paho-mqtt wrapper: one request, one reply topic, no retained state."""

from __future__ import annotations

import json
import os
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .errors import TransportError
from .util import info, warn


@dataclass
class MQTTConfig:
    host: str
    port: int = 8883
    ca: Path | None = None
    cert: Path | None = None
    key: Path | None = None
    insecure: bool = False
    client_id: str = ""

    def __post_init__(self) -> None:
        if not self.client_id:
            self.client_id = "blueair-cloudcutter-" + os.urandom(4).hex()


class MQTT:
    def __init__(self, cfg: MQTTConfig, timeout: float = 60.0) -> None:
        import paho.mqtt.client as mqtt

        self.cfg = cfg
        self.timeout = timeout
        self._messages: list[tuple[str, str]] = []
        self._client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=cfg.client_id,
            protocol=mqtt.MQTTv311,
        )
        if cfg.ca or cfg.cert:
            self._client.tls_set(
                ca_certs=str(cfg.ca) if cfg.ca else None,
                certfile=str(cfg.cert) if cfg.cert else None,
                keyfile=str(cfg.key) if cfg.key else None,
                tls_version=ssl.PROTOCOL_TLSv1_2,
            )
            self._client.tls_insecure_set(cfg.insecure)
        self._client.on_message = self._on_message
        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._connected = False

    def _on_connect(self, client, userdata, flags, reason_code, properties=None) -> None:
        if reason_code == 0:
            self._connected = True
            info(f"MQTT connected to {self.cfg.host}:{self.cfg.port}")
        else:
            info(f"MQTT connect failed: {reason_code}")

    def _on_disconnect(self, client, userdata, flags, reason_code, properties=None) -> None:
        if reason_code != 0:
            info(f"MQTT disconnected: {reason_code}")

    def _on_message(self, client, userdata, msg) -> None:
        self._messages.append((msg.topic, msg.payload.decode("utf-8", "replace")))

    def __enter__(self) -> MQTT:
        try:
            self._client.connect(self.cfg.host, self.cfg.port, 60)
        except OSError as exc:
            raise TransportError(f"cannot connect to {self.cfg.host}:{self.cfg.port}: {exc}") from exc
        self._client.loop_start()
        deadline = time.time() + 10
        while time.time() < deadline and not self._connected:
            time.sleep(0.1)
        if not self._connected:
            self._client.loop_stop()
            raise TransportError("MQTT connection was not established")
        return self

    def __exit__(self, *exc) -> None:
        try:
            self._client.disconnect()
            self._client.loop_stop()
        except Exception:
            pass

    def _publish(self, topic: str, body: str) -> None:
        info(f"MQTT publish {topic}")
        result = self._client.publish(topic, body, qos=1)
        if result.rc != 0:
            raise TransportError(f"publish to {topic} failed: {result.rc}")
        result.wait_for_publish(timeout=5)
        if not result.is_published():
            raise TransportError(f"publish to {topic} was not acknowledged")

    def wait_for_device(self, did: str, timeout: float = 10.0) -> bool:
        """Wait for a device publication after it connects, on AWS or a local broker."""
        prefixes = (
            f"d/{did}/",
            f"$aws/things/{did}/",
            f"$aws/events/presence/connected/{did}",
        )
        self._messages.clear()
        result, _ = self._client.subscribe("#", qos=1)
        if result != 0:
            warn(f"cannot subscribe to device activity: {result}")
            return False
        time.sleep(0.5)
        deadline = time.time() + timeout
        while time.time() < deadline:
            for topic, _payload in list(self._messages):
                if any(topic.startswith(prefix) for prefix in prefixes):
                    info(f"device is active on {topic}")
                    return True
            time.sleep(0.2)
        warn(f"no device activity on {did} within {timeout:.0f}s")
        return False

    def request(self, topic: str, payload, reply_topic: str, *, wait: float | None = None) -> str:
        wait = wait if wait is not None else self.timeout
        self._messages.clear()
        result, _ = self._client.subscribe(reply_topic, qos=1)
        if result != 0:
            raise TransportError(f"subscribe to {reply_topic} failed: {result}")
        time.sleep(0.5)
        body = payload if isinstance(payload, str) else json.dumps(payload)
        self._publish(topic, body)
        deadline = time.time() + wait
        while time.time() < deadline:
            for t, msg in list(self._messages):
                if t == reply_topic:
                    return msg
            time.sleep(0.15)
        return ""

    def publish(self, topic: str, payload) -> None:
        body = payload if isinstance(payload, str) else json.dumps(payload)
        self._publish(topic, body)

    def listen(
        self,
        topic: str,
        wait: float = 30.0,
        stop_when: Callable[[str, str], bool] | None = None,
    ) -> list[tuple[str, str]]:
        """Subscribe and collect messages for up to `wait` seconds.

        `stop_when(topic, payload)` ends the wait as soon as a relevant message
        arrives, so discovery does not sit out the whole timeout.
        """
        self._messages.clear()
        self._client.subscribe(topic, qos=1)
        time.sleep(0.5)
        deadline = time.time() + wait
        while time.time() < deadline:
            if stop_when is not None:
                for topic_name, payload in list(self._messages):
                    if stop_when(topic_name, payload):
                        return list(self._messages)
            time.sleep(0.2)
        return list(self._messages)
