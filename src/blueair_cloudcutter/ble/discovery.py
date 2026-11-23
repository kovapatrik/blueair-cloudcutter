"""BLE discovery and device selection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..errors import CutterError
from .transport import SERVICE_UUID


@dataclass
class DiscoveredDevice:
    name: str
    address: str
    rssi: int
    service_match: bool
    device: Any | None = None

    @property
    def label(self) -> str:
        return self.name or "(unnamed)"


def _normalise(result) -> list[DiscoveredDevice]:
    devices: list[DiscoveredDevice] = []
    if isinstance(result, dict):
        iterable = result.values()
    else:
        iterable = [(item, None) for item in result]

    for item in iterable:
        if isinstance(item, tuple):
            device, adv = item
        else:
            device, adv = item, None
        name = (getattr(device, "name", None) or "") or ""
        if adv is not None and getattr(adv, "local_name", None):
            name = adv.local_name
        rssi = int(getattr(adv, "rssi", 0) or 0) if adv is not None else 0
        uuids = {str(u).lower() for u in (getattr(adv, "service_uuids", None) or [])}
        # Some devices (and BlueZ versions) expose the provisioning UUID only in
        # the service-data map rather than the advertised UUID list.
        uuids.update(str(u).lower() for u in (getattr(adv, "service_data", None) or {}))
        devices.append(
            DiscoveredDevice(
                name=name,
                address=str(getattr(device, "address", "")),
                rssi=rssi,
                service_match=SERVICE_UUID in uuids,
                device=device,
            )
        )
    devices.sort(key=lambda d: (not d.service_match, -d.rssi, d.label.lower()))
    return devices


async def scan(timeout: float = 10.0, *, include_all: bool = True) -> list[DiscoveredDevice]:
    try:
        from bleak import BleakScanner
    except ImportError as exc:  # pragma: no cover
        raise CutterError("bleak is not installed; `pip install bleak`") from exc

    try:
        result = await BleakScanner.discover(timeout=timeout, return_adv=True)
    except TypeError:
        # Older bleak: no return_adv. Discovery still works; service UUIDs are
        # not available, so everything is returned and the user picks.
        result = await BleakScanner.discover(timeout=timeout)

    devices = _normalise(result)
    matches = [d for d in devices if d.service_match]
    if include_all:
        return matches + [d for d in devices if not d.service_match]
    return matches


def select_device(
    devices: list[DiscoveredDevice],
    *,
    address: str | None = None,
    name: str | None = None,
) -> DiscoveredDevice:
    if address:
        for device in devices:
            if device.address.lower() == address.lower():
                return device
        for device in devices:
            if device.address.lower().startswith(address.lower()):
                return device
        # bleak can often connect by address even when it was not in the scan.
        return DiscoveredDevice(name="", address=address, rssi=0, service_match=False)

    if name:
        needle = name.lower()
        found = [d for d in devices if needle in d.label.lower()]
        if not found:
            raise CutterError(f"no BLE device matching {name!r}; run `blueair-cloudcutter helpers ble scan`")
        if len(found) > 1:
            listing = "\n".join(f"  {d.label}  {d.address}" for d in found)
            raise CutterError(f"multiple devices match {name!r}:\n{listing}\npass --address")
        return found[0]

    matches = [d for d in devices if d.service_match]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        listing = "\n".join(f"  {d.label}  {d.address}" for d in matches)
        raise CutterError(f"multiple BlueAir devices found:\n{listing}\npass --address")
    if len(devices) == 1:
        return devices[0]
    if not devices:
        raise CutterError(
            "no BLE devices found; make sure the purifier is in normal mode (factory mode has no BLE)"
        )
    listing = "\n".join(f"  {d.label}  {d.address}" for d in devices)
    raise CutterError(f"could not identify the purifier:\n{listing}\npass --address or --name")


def format_table(devices: list[DiscoveredDevice]) -> str:
    lines = [f"{'':2} {'Name':28} {'Address':40} RSSI"]
    for device in devices:
        mark = "*" if device.service_match else " "
        lines.append(f"{mark:2} {device.label[:28]:28} {device.address[:40]:40} {device.rssi:4}")
    return "\n".join(lines)
