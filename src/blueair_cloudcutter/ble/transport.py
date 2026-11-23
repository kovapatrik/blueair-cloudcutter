"""BLE transport abstraction and the bleak-backed implementation."""

from __future__ import annotations

from typing import Any, Protocol

from ..errors import CutterError

# Service advertised by the device.
SERVICE_UUID = "4772911e-d07c-4617-8241-f4d10948d6ae"

# Characteristic UUIDs. The names line up with ESP-IDF's protocomm endpoints.
CHAR_UUIDS = {
    "prov-scan": "4772ff50-d07c-4617-8241-f4d10948d6ae",
    "prov-session": "4772ff51-d07c-4617-8241-f4d10948d6ae",
    "prov-config": "4772ff52-d07c-4617-8241-f4d10948d6ae",
    "proto-ver": "4772ff53-d07c-4617-8241-f4d10948d6ae",
    "custom-endpoint": "4772ff54-d07c-4617-8241-f4d10948d6ae",
}

UUID_TO_NAME = {uuid.lower(): name for name, uuid in CHAR_UUIDS.items()}
USER_DESCRIPTION_UUID = "00002901-0000-1000-8000-00805f9b34fb"


class Transport(Protocol):
    async def connect(self) -> None: ...
    async def disconnect(self) -> None: ...
    async def write(self, name: str, data: bytes) -> None: ...
    async def read(self, name: str) -> bytes: ...


class BleakTransport:
    """bleak-backed transport.

    bleak is imported lazily so the rest of the tool (and the unit tests) work
    without a Bluetooth stack.
    """

    def __init__(
        self,
        *,
        address: str | None = None,
        device: Any | None = None,
        timeout: float = 20.0,
        settle: float = 0.0,
    ) -> None:
        if not address and device is None:
            raise CutterError("either a BLE address or a scanned device is required")
        self.address = address
        self.device = device
        self.timeout = timeout
        self.settle = settle
        self.client: Any | None = None
        self._by_name: dict[str, Any] = {}

    async def connect(self) -> None:
        try:
            from bleak import BleakClient
        except ImportError as exc:  # pragma: no cover - dependency is declared
            raise CutterError("bleak is not installed; `pip install bleak`") from exc

        target = self.device if self.device is not None else self.address
        last: Exception | None = None
        for attempt in range(1, 4):
            client = BleakClient(target, timeout=self.timeout)
            try:
                await client.connect()
                self.client = client
                break
            except Exception as exc:  # noqa: BLE001 - bleak has many error types
                last = exc
                try:
                    await client.disconnect()
                except Exception:  # noqa: BLE001
                    pass
                if attempt < 3:
                    import asyncio

                    await asyncio.sleep(1.5)
        if self.client is None:
            detail = f"{type(last).__name__}: {last!r}" if last is not None else "unknown error"
            raise CutterError(
                f"BLE connection to {target} failed after 3 attempts ({detail}).\n"
                "Move the purifier closer (a weak RSSI makes connects fail), and make sure "
                "no phone/app is connected to it. The Pi's Wi-Fi AP and BLE share one 2.4 GHz "
                "radio; stop the AP for the BLE step, or use a USB Bluetooth/Wi-Fi adapter."
            )

        self._by_name = await self._discover_characteristics()
        missing = set(CHAR_UUIDS) - set(self._by_name)
        if missing:
            raise CutterError(
                "connected, but these characteristics are missing: "
                + ", ".join(sorted(missing))
                + ". Is this a BlueAir provisioning interface?"
            )

    async def _discover_characteristics(self) -> dict[str, Any]:
        found: dict[str, Any] = {}
        assert self.client is not None
        services = getattr(self.client, "services", None)
        if services is None:
            raise CutterError("BLE connected but the service list is empty")

        for service in services:
            for char in service.characteristics:
                uuid = str(char.uuid).lower()
                name = UUID_TO_NAME.get(uuid)
                if name:
                    found[name] = char
                for desc in getattr(char, "descriptors", []):
                    if str(desc.uuid).lower() != USER_DESCRIPTION_UUID:
                        continue
                    try:
                        value = await self.client.read_gatt_descriptor(desc.handle)
                        label = value.decode("utf-8", "replace").strip()
                    except Exception:
                        continue
                    if label:
                        found.setdefault(label, char)
        return found

    async def disconnect(self) -> None:
        if self.client is not None:
            try:
                await self.client.disconnect()
            except Exception:
                pass
            self.client = None

    def _char(self, name: str):
        if name in self._by_name:
            return self._by_name[name]
        uuid = CHAR_UUIDS.get(name)
        if uuid:
            for _, char in self._by_name.items():
                if str(char.uuid).lower() == uuid.lower():
                    return char
        raise CutterError(f"characteristic {name!r} not available")

    async def write(self, name: str, data: bytes) -> None:
        assert self.client is not None
        char = self._char(name)
        try:
            await self.client.write_gatt_char(char, data, response=True)
        except Exception as exc:
            raise CutterError(f"BLE write to {name} failed: {exc}") from exc
        if self.settle:
            import asyncio

            await asyncio.sleep(self.settle)

    async def read(self, name: str) -> bytes:
        assert self.client is not None
        char = self._char(name)
        try:
            return bytes(await self.client.read_gatt_char(char))
        except Exception as exc:
            raise CutterError(f"BLE read from {name} failed: {exc}") from exc
