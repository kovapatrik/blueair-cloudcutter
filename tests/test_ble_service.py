from __future__ import annotations

import asyncio
import json

from blueair_cloudcutter.ble import messages as m
from blueair_cloudcutter.ble import protobuf as pb
from blueair_cloudcutter.ble.crypto import (
    SessionCrypto,
    derive_shared_secret,
    generate_keypair,
    public_bytes,
)
from blueair_cloudcutter.ble.service import (
    BlueAirBLE,
    Configuration,
    FactoryConfiguration,
)


class FakeTransport:
    """A device simulator: same crypto, same request/response shapes."""

    def __init__(self) -> None:
        self.device_key = generate_keypair()
        self.device_pub = public_bytes(self.device_key)
        self.device_random = bytes(range(16))
        self.crypto: SessionCrypto | None = None
        self.client_pub: bytes | None = None
        self.pending = b""
        self.connected = False
        self.config_updates: dict[int, str] = {}
        self.ssid = ""
        self.password = ""
        self.applied = False
        self.factory: dict[str, str] = {}
        self.writes: list[tuple[str, bytes]] = []

    async def connect(self) -> None:
        self.connected = True

    async def disconnect(self) -> None:
        self.connected = False

    async def write(self, name: str, data: bytes) -> None:
        self.writes.append((name, data))
        if name == "proto-ver":
            self.pending = b"ESP"
        elif name == "prov-session":
            self._session(data)
        else:
            if self.crypto is None:
                raise AssertionError("encrypted write before session")
            plain = self.crypto.apply(data)
            response = self._handle(name, plain)
            self.pending = self.crypto.apply(response)

    async def read(self, name: str) -> bytes:
        return self.pending

    # -- session -----------------------------------------------------------

    def _session(self, data: bytes) -> None:
        outer = pb.decode_fields(data)
        sec1 = pb.get_message(outer, 11)
        msg = pb.get_varint(sec1, 1)
        if msg == 0:
            cmd0 = pb.get_message(sec1, 20)
            self.client_pub = pb.get_bytes(cmd0, 1)
            shared = derive_shared_secret(self.device_key, self.client_pub)
            self.crypto = SessionCrypto(shared, self.device_random)
            self.pending = m.encode_session_response0(0, self.device_pub, self.device_random)
        elif msg == 2:
            cmd1 = pb.get_message(sec1, 22)
            verify = pb.get_bytes(cmd1, 2)
            expected = self.crypto.apply(self.device_pub)
            assert verify == expected
            device_verify = self.crypto.apply(self.client_pub)
            self.pending = m.encode_session_response1(0, device_verify)
        else:
            raise AssertionError(f"unexpected session message {msg}")

    # -- custom commands ---------------------------------------------------

    def _handle(self, name: str, plain: bytes) -> bytes:
        if name == "custom-endpoint":
            return self._custom(plain)
        if name == "prov-config":
            return self._wifi_config(plain)
        if name == "prov-scan":
            return self._wifi_scan(plain)
        raise AssertionError(f"unexpected characteristic {name}")

    def _custom(self, plain: bytes) -> bytes:
        fields = pb.decode_fields(plain)
        start = pb.get_message(fields, m.WRAPPER_START_CMD)
        if start is not None:
            return pb.field_message(m.WRAPPER_START_RESP, pb.field_varint(1, 0))

        config = pb.get_message(fields, m.WRAPPER_CONFIG_CMD)
        if config is not None:
            for number in range(1, 7):
                if pb.find(config, number):
                    self.config_updates[number] = pb.get_string(config, number)
            return pb.field_message(m.WRAPPER_CONFIG_RESP, pb.field_varint(1, 0))

        event = pb.get_message(fields, m.WRAPPER_EVENT_CMD)
        if event is not None:
            body = pb.field_string(1, json.dumps({"x": 1})) + pb.field_varint(2, 0)
            return pb.field_message(m.WRAPPER_EVENT_RESP, body)

        address = pb.get_message(fields, m.WRAPPER_ADDRESS_CMD)
        if address is not None:
            return pb.field_message(m.WRAPPER_ADDRESS_RESP, pb.field_string(1, "aa:bb:cc:dd:ee:ff"))

        stop = pb.get_message(fields, m.WRAPPER_STOP_CMD)
        if stop is not None:
            return pb.field_message(m.WRAPPER_STOP_RESP, pb.field_varint(1, 0))

        factory = pb.get_message(fields, m.WRAPPER_FACTORY_CMD)
        if factory is not None:
            self.factory = {
                "url": pb.get_string(factory, 1),
                "ssid": pb.get_string(factory, 2),
                "pwd": pb.get_string(factory, 3),
                "token": pb.get_string(factory, 4),
            }
            return pb.field_message(m.WRAPPER_FACTORY_RESP, pb.field_varint(1, 0))

        filter_read = pb.get_message(fields, m.WRAPPER_FILTER_READ_CMD)
        if filter_read is not None:
            return pb.field_message(m.WRAPPER_FILTER_READ_RESP, pb.field_varint(1, 123))

        filter_set = pb.get_message(fields, m.WRAPPER_FILTER_SET_CMD)
        if filter_set is not None:
            return pb.field_message(m.WRAPPER_FILTER_SET_RESP, pb.field_varint(1, 0))

        raise AssertionError(f"unhandled custom command: {[f.number for f in fields]}")

    def _wifi_config(self, plain: bytes) -> bytes:
        fields = pb.decode_fields(plain)
        msg = pb.get_varint(fields, 1)
        if msg == m.WifiConfigMsgType.CmdSetConfig:
            sub = pb.get_message(fields, 12)
            self.ssid = pb.get_bytes(sub, 1).decode()
            self.password = pb.get_bytes(sub, 2).decode()
            return pb.field_varint(1, m.WifiConfigMsgType.RespSetConfig) + pb.field_message(
                13, pb.field_varint(1, 0)
            )
        if msg == m.WifiConfigMsgType.CmdApplyConfig:
            self.applied = True
            return pb.field_varint(1, m.WifiConfigMsgType.RespApplyConfig) + pb.field_message(
                15, pb.field_varint(1, 0)
            )
        if msg == m.WifiConfigMsgType.CmdGetStatus:
            connected = (
                pb.field_string(1, "192.168.1.50")
                + pb.field_varint(2, 3)
                + pb.field_bytes(3, b"wifi")
                + pb.field_bytes(4, bytes.fromhex("aabbccddeeff"))
                + pb.field_varint(5, 6)
            )
            body = pb.field_varint(1, 0) + pb.field_varint(2, 0) + pb.field_message(11, connected)
            return pb.field_varint(1, m.WifiConfigMsgType.RespGetStatus) + pb.field_message(11, body)
        raise AssertionError(f"unexpected WiFi config msg {msg}")

    def _wifi_scan(self, plain: bytes) -> bytes:
        fields = pb.decode_fields(plain)
        msg = pb.get_varint(fields, 1)
        if msg == m.WifiScanMsgType.CmdScanStart:
            return pb.field_varint(1, m.WifiScanMsgType.RespScanStart) + pb.field_message(11, b"")
        if msg == m.WifiScanMsgType.CmdScanStatus:
            body = pb.field_bool(1, True) + pb.field_varint(2, 1)
            return (
                pb.field_varint(1, m.WifiScanMsgType.RespScanStatus)
                + pb.field_varint(2, 0)
                + pb.field_message(13, body)
            )
        if msg == m.WifiScanMsgType.CmdScanResult:
            entry = (
                pb.field_bytes(1, b"wifi")
                + pb.field_varint(2, 6)
                + pb.field_varint(3, -50)
                + pb.field_bytes(4, bytes.fromhex("aabbccddeeff"))
                + pb.field_varint(5, 3)
            )
            return (
                pb.field_varint(1, m.WifiScanMsgType.RespScanResult)
                + pb.field_varint(2, 0)
                + pb.field_message(15, pb.field_bytes(1, entry))
            )
        raise AssertionError(f"unexpected scan msg {msg}")


def _run(coro):
    return asyncio.run(coro)


def test_full_service_flow():
    async def scenario():
        transport = FakeTransport()
        service = BlueAirBLE(transport)
        await service.connect()
        assert service.crypto is not None
        assert transport.connected

        await service.set_configuration(Configuration(broker_url="192.168.1.10", region="eu-west-1"))
        assert transport.config_updates[3] == "192.168.1.10"
        assert transport.config_updates[4] == "eu-west-1"

        assert await service.read_address() == "aa:bb:cc:dd:ee:ff"
        assert await service.read_filter("hepa") == 123
        await service.write_filter("42")

        events = await service.get_all_events()
        assert len(events) == 1
        assert events[0].json == {"x": 1}

        await service.wifi_connect("wifi", "password")
        assert transport.ssid == "wifi"
        assert transport.password == "password"
        assert transport.applied

        networks = await service.wifi_scan()
        assert len(networks) == 1
        assert networks[0].ssid == "wifi"
        assert networks[0].rssi == -50
        assert networks[0].bssid == "aabbccddeeff"

        await service.set_factory(
            FactoryConfiguration(
                url="http://192.168.1.10:8080",
                ssid="BAFactory",
                pwd="secret",
                token="token",
            )
        )
        assert transport.factory["url"] == "http://192.168.1.10:8080"
        assert transport.factory["token"] == "token"

        assert await service.read_filter("") == 123
        await service.stop()
        await service.disconnect()

    _run(scenario())


def test_config_is_skipped_when_empty():
    async def scenario():
        transport = FakeTransport()
        service = BlueAirBLE(transport)
        await service.connect()
        await service.set_configuration(Configuration(broker_url="broker"))
        assert transport.config_updates == {3: "broker"}

    _run(scenario())


def test_full_config_sends_all_six_fields():
    async def scenario():
        transport = FakeTransport()
        service = BlueAirBLE(transport)
        await service.connect()
        await service.set_configuration(
            Configuration(api_url="a", auth_url="b", broker_url="c", region="d"),
            full=True,
        )
        assert transport.config_updates == {1: "a", 2: "b", 3: "c", 4: "d", 5: "", 6: ""}

    _run(scenario())
