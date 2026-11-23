"""High-level BLE session and provisioning flow.

Both the exploit and `helpers ble` use this; the command wrapper only parses
arguments and prints events.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from ..errors import CutterError
from ..util import info, step, warn
from .discovery import DiscoveredDevice
from .service import BlueAirBLE, Configuration, Event
from .transport import BleakTransport


@dataclass
class ProvisionResult:
    connected: bool | None = None
    event: Event | None = None


async def connect(device: DiscoveredDevice, *, timeout: float = 20.0, settle: float = 0.0) -> BlueAirBLE:
    transport = BleakTransport(
        device=device.device,
        address=device.address,
        timeout=timeout,
        settle=settle,
    )
    service = BlueAirBLE(transport)
    await service.connect()
    return service


def _random_text() -> str:
    return secrets.token_hex(8)


async def provision(
    service: BlueAirBLE,
    *,
    broker: str,
    api: str = "",
    auth: str = "",
    region: str = "",
    ssid: str | None = None,
    password: str | None = None,
    open_network: bool = False,
    random_text: str | None = None,
    secure_random: str | None = None,
    full_config: bool = False,
    wifi_hook=None,
    wait_events: bool = False,
) -> ProvisionResult:
    """Send ConfigCmd, join WiFi, and optionally wait for a connection event."""
    try:
        stale = await service.get_all_events()
        stale = [event for event in stale if event.raw]
        if stale:
            info(f"drained {len(stale)} stale event(s)")
    except CutterError:
        pass

    config = Configuration(
        api_url=api,
        auth_url=auth,
        broker_url=broker,
        region=region,
        random_text=random_text or _random_text(),
        secure_random=secure_random or _random_text(),
    )
    step(1, 3, "Send ConfigCmd")
    await service.set_configuration(config, full=full_config)

    step(2, 3, "Configure WiFi")
    if ssid:
        if password is None and not open_network:
            raise CutterError("a WiFi password is required with an SSID (or pass --open-network)")
        if wifi_hook is not None:
            wifi_hook()
        try:
            await service.wifi_connect(ssid, password or "")
        except CutterError as exc:
            raise CutterError(
                f"{exc}\n"
                "Check output/logs/hostapd.log and dnsmasq.log. If the device says "
                "InternalError, power-cycle it before retrying; that state does not "
                "clear by re-sending the WiFi config."
            ) from exc
    else:
        info("no SSID; WiFi configuration left unchanged")

    if not wait_events:
        step(3, 3, "Disconnect BLE so the device can finish onboarding")
        info("WiFi is connected; freeing the 2.4 GHz radio for the cloud connection")
        return ProvisionResult()

    step(3, 3, "Wait for a live connection event")
    connected, event = await service.wait_for_connection()
    if connected is False:
        warn(
            "the device reported STA disconnected; the certificate capture may time out. "
            "Check hostapd/dnsmasq and power-cycle the purifier before retrying."
        )
    return ProvisionResult(connected=connected, event=event)
