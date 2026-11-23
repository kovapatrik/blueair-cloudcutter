"""BlueAir BLE provisioning service.

The flow is:

    connect -> proto-ver -> Security 1 session 0 -> session 1 -> start
            -> config / factory / events / filters / WiFi

All request and response payloads after the session handshake go through one
AES-256-CTR keystream, in both directions, in order.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any

from ..errors import CutterError
from ..util import info
from . import messages as m
from . import protobuf as pb
from .crypto import SessionCrypto, derive_shared_secret, generate_keypair, public_bytes
from .transport import Transport

WIFI_SCAN_CHUNK = 4
WIFI_CONNECT_TIMEOUT = 45.0
WIFI_SCAN_POLLS = 10


@dataclass
class Configuration:
    """The six values sent by `ConfigCmd`. Empty strings are skipped unless full=True."""

    api_url: str = ""
    auth_url: str = ""
    broker_url: str = ""
    region: str = ""
    random_text: str = ""
    secure_random: str = ""

    def items(self) -> dict[str, str]:
        return {
            "api_url": self.api_url,
            "auth_url": self.auth_url,
            "broker_url": self.broker_url,
            "region": self.region,
            "random_text": self.random_text,
            "secure_random": self.secure_random,
        }


@dataclass
class FactoryConfiguration:
    url: str
    ssid: str
    pwd: str
    token: str


@dataclass
class Event:
    json: Any
    number_of_events: int
    raw: str = ""


class BlueAirBLE:
    def __init__(self, transport: Transport) -> None:
        self.transport = transport
        self.crypto: SessionCrypto | None = None
        self.client_public_key: bytes | None = None
        self.device_public_key: bytes | None = None
        self.is_configured = False

    # -- session -----------------------------------------------------------

    async def connect(self) -> None:
        await self.transport.connect()
        try:
            await self.get_proto_ver()
            await self.step_session0()
            await self.step_session1()
            await self.start()
        except Exception:
            await self.transport.disconnect()
            raise

    async def disconnect(self) -> None:
        await self.transport.disconnect()

    async def get_proto_ver(self) -> bytes:
        await self.transport.write("proto-ver", b"ESP")
        return await self.transport.read("proto-ver")

    async def _encrypted_exchange(self, characteristic: str, payload: bytes) -> bytes:
        if self.crypto is None:
            raise CutterError("session is not established")
        await self.transport.write(characteristic, self.crypto.apply(payload))
        response = await self.transport.read(characteristic)
        return self.crypto.apply(response)

    async def step_session0(self) -> None:
        private_key = generate_keypair()
        self.client_public_key = public_bytes(private_key)
        payload = m.encode_session_command0(self.client_public_key)
        await self.transport.write("prov-session", payload)
        response = await self.transport.read("prov-session")
        decoded = m.decode_session_response0(response)
        self._check_esp(decoded.status, "session 0")

        shared = derive_shared_secret(private_key, decoded.device_pubkey)
        self.crypto = SessionCrypto(shared, decoded.device_random)
        self.device_public_key = decoded.device_pubkey

    async def step_session1(self) -> None:
        if self.crypto is None or self.client_public_key is None or self.device_public_key is None:
            raise CutterError("session 1 requested before session 0")
        verify = self.crypto.apply(self.device_public_key)
        payload = m.encode_session_command1(verify)
        await self.transport.write("prov-session", payload)
        response = await self.transport.read("prov-session")
        decoded = m.decode_session_response1(response)
        self._check_esp(decoded.status, "session 1")

        expected = self.crypto.apply(decoded.device_verify_data)
        if expected != self.client_public_key:
            raise CutterError("device did not prove possession of the session key")

    # -- custom commands ---------------------------------------------------

    async def _command(self, payload: bytes, expected_wrapper_field: int) -> list:
        response = await self._encrypted_exchange("custom-endpoint", payload)
        number, sub = m.decode_command_wrapper(response)
        if number != expected_wrapper_field:
            raise CutterError(
                f"unexpected BLE response: wrapper field {number}, expected {expected_wrapper_field}"
            )
        return sub

    async def start(self) -> None:
        sub = await self._command(m.encode_start_cmd(), m.WRAPPER_START_RESP)
        self._check_custom(_varint(sub, 1), "start")

    async def stop(self) -> None:
        sub = await self._command(m.encode_stop_cmd(), m.WRAPPER_STOP_RESP)
        self._check_custom(_varint(sub, 1), "stop")

    async def get_event(self) -> Event:
        for _ in range(3):
            response = await self._encrypted_exchange("custom-endpoint", m.encode_event_cmd())
            number, sub = m.decode_command_wrapper(response)
            if number == m.WRAPPER_EVENT_RESP:
                raw = _string(sub, 1)
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError:
                    parsed = None
                return Event(
                    json=parsed,
                    number_of_events=_int32(sub, 2),
                    raw=raw,
                )
            # The device can answer with a ConfigResp between events; ignore it
            # and ask again rather than failing the whole event drain.
            info(f"ignoring non-event BLE response (wrapper field {number})")
        raise CutterError("device did not return an event response")

    async def wait_for_connection(self, timeout: float = 15.0) -> tuple[bool | None, Event | None]:
        """Stop at the first live connection/onboarding event.

        The queue can contain old events; drain it before provisioning and use
        this after WiFi. OnboardEvent means the device is on WiFi and talking to
        its cloud (the TLS handshake is happening), so the capture can proceed.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            try:
                event = await self.get_event()
            except CutterError:
                await asyncio.sleep(0.5)
                continue
            if not event.raw:
                await asyncio.sleep(0.5)
                continue
            data = event.json if isinstance(event.json, dict) else {}
            kind = data.get("ot")
            state = data.get("et") or ""
            message = str(data.get("m") or "").lower()
            if kind == "ConnectionEvent":
                if state == "Connected" or ("connected" in message and "disconnected" not in message):
                    return True, event
                if state == "NotConnected" or "disconnect" in message:
                    return False, event
            elif kind == "OnboardEvent" and "authenticat" in message:
                return True, event
            await asyncio.sleep(0.5)
        return None, None

    async def get_all_events(self, max_events: int = 100) -> list[Event]:
        events: list[Event] = []
        while len(events) < max_events:
            event = await self.get_event()
            events.append(event)
            if event.number_of_events <= 0:
                break
        if len(events) >= max_events:
            info(f"stopped after {max_events} events (safety limit)")
        return events

    async def set_configuration(self, config: Configuration, *, full: bool = False) -> None:
        values = config.items()
        if full:
            targets = values
        else:
            targets = {k: v for k, v in values.items() if v}
        if not targets:
            raise CutterError("nothing to configure: pass at least one config value")

        for name, value in targets.items():
            sub = await self._command(m.encode_config_cmd(name, value), m.WRAPPER_CONFIG_RESP)
            self._check_custom(_varint(sub, 1), f"config {name}")
            info(f"config {name} accepted")

        self.is_configured = True

    async def set_factory(self, config: FactoryConfiguration) -> None:
        payload = m.encode_factory_cmd(config.url, config.ssid, config.pwd, config.token)
        try:
            sub = await self._command(payload, m.WRAPPER_FACTORY_RESP)
            self._check_custom(_varint(sub, 1), "factory")
        except CutterError as exc:
            # FactoryCmd can reboot the device before the acknowledgement is
            # readable. Treat a transport failure as "probably applied".
            if "BLE read" in str(exc) or "not available" in str(exc):
                info("no factory acknowledgement: the device may have rebooted into factory mode")
                return
            raise

    async def read_address(self) -> str:
        response = await self._encrypted_exchange("custom-endpoint", m.encode_address_cmd())
        number, sub = m.decode_command_wrapper(response)
        if number != m.WRAPPER_ADDRESS_RESP:
            raise CutterError(f"unexpected address response (wrapper field {number})")
        return _string(sub, 1)

    async def read_filter(self, filter_type: str) -> int:
        response = await self._encrypted_exchange("custom-endpoint", m.encode_filter_read_cmd(filter_type))
        number, sub = m.decode_command_wrapper(response)
        if number != m.WRAPPER_FILTER_READ_RESP:
            raise CutterError(f"unexpected filter read response (wrapper field {number})")
        return _varint(sub, 1)

    async def write_filter(self, value: str) -> None:
        sub = await self._command(m.encode_filter_set_cmd(value), m.WRAPPER_FILTER_SET_RESP)
        self._check_custom(_varint(sub, 1), "filter write")

    # -- WiFi --------------------------------------------------------------

    async def wifi_connect(self, ssid: str, password: str, timeout: float = WIFI_CONNECT_TIMEOUT) -> None:
        if self.crypto is None:
            raise CutterError("session is not established")

        set_config = await self._encrypted_exchange("prov-config", m.encode_wifi_set_config(ssid, password))
        status = m.decode_wifi_set_config_response(set_config)
        self._check_esp(status, "WiFi set config")

        apply_config = await self._encrypted_exchange("prov-config", m.encode_wifi_apply_config())
        status = m.decode_wifi_apply_config_response(apply_config)
        self._check_esp(status, "WiFi apply config")

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            response = await self._encrypted_exchange("prov-config", m.encode_wifi_get_status())
            decoded = m.decode_wifi_status_response(response)
            self._check_esp(decoded.status, "WiFi get status")

            if decoded.fail_reason is not None and decoded.sta_state != m.WifiStationState.Connecting:
                raise CutterError(
                    f"WiFi connection failed: {decoded.fail_reason.name} (state {decoded.sta_state.name})"
                )
            if decoded.sta_state == m.WifiStationState.Connected:
                ip = decoded.connected.ip4_addr if decoded.connected else "?"
                info(f"device joined WiFi, IP {ip}")
                return
            await asyncio.sleep(0.5)

        raise CutterError(f"WiFi connection timed out after {timeout:.0f}s")

    async def wifi_scan(self) -> list[m.WifiNetwork]:
        if self.crypto is None:
            raise CutterError("session is not established")

        start = await self._encrypted_exchange("prov-scan", m.encode_scan_start())
        # RespScanStart is empty; parse it so a malformed reply is caught.
        pb.decode_fields(start)

        finished = False
        result_count = 0
        for _ in range(WIFI_SCAN_POLLS):
            response = await self._encrypted_exchange("prov-scan", m.encode_scan_status())
            status = m.decode_scan_status(response)
            self._check_esp(status.status, "WiFi scan status")
            finished = status.scan_finished
            result_count = status.result_count
            if finished:
                break
            await asyncio.sleep(0.5)

        if not finished:
            raise CutterError("WiFi scan did not finish in time")

        networks: list[m.WifiNetwork] = []
        start_index = 0
        while start_index < result_count:
            count = min(result_count - start_index, WIFI_SCAN_CHUNK)
            response = await self._encrypted_exchange("prov-scan", m.encode_scan_result(start_index, count))
            networks.extend(m.decode_scan_results(response))
            start_index += count
        return networks

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _check_esp(status: m.EspStatus, what: str) -> None:
        if status != m.EspStatus.Success:
            raise CutterError(f"{what} failed: {status.name}")

    @staticmethod
    def _check_custom(status: int, what: str) -> None:
        try:
            value = m.CustomStatus(status)
        except ValueError as exc:
            raise CutterError(f"{what} failed: unknown status {status}") from exc
        if value != m.CustomStatus.Success:
            raise CutterError(f"{what} failed: {value.name}")


def _varint(fields: list, number: int, default: int = 0) -> int:
    return pb.get_varint(fields, number, default)


def _string(fields: list, number: int, default: str = "") -> str:
    return pb.get_string(fields, number, default)


def _int32(fields: list, number: int, default: int = 0) -> int:
    return pb.to_int32(pb.get_varint(fields, number, default))
