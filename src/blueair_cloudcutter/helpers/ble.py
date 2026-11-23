"""BLE helper commands: scan, provision, factory mode, events and WiFi."""

from __future__ import annotations

import asyncio
import json

from .. import aws
from ..ble import (
    BlueAirBLE,
    FactoryConfiguration,
    connect,
    discovery,
    provision,
)
from ..constants import FACTORY_PSK, FACTORY_SSID
from ..context import Context
from ..errors import CutterError
from ..fakeapi import FakeApiServer
from ..util import info, local_ip, ok, read_json, step, warn


def _print_events(events) -> None:
    for index, event in enumerate(events, 1):
        remaining = event.number_of_events
        if event.json is not None:
            info(f"event {index} (remaining {remaining}):")
            print(json.dumps(event.json, indent=2))
        else:
            info(f"event {index} (remaining {remaining}): {event.raw!r}")


async def _scan(args) -> int:
    devices = await discovery.scan(args.timeout, include_all=True)
    matches = [d for d in devices if d.service_match]

    if not devices:
        info("no BLE devices found; make sure the purifier is in normal mode (factory mode has no BLE)")
        return 1

    if args.blueair_only and not matches:
        print(discovery.format_table(devices))
        info("no device advertised the BlueAir provisioning service")
        info("check that the purifier is in normal mode; otherwise pick a MAC with --address")
        return 1

    if matches and not (args.all or args.blueair_only):
        hidden = len(devices) - len(matches)
        devices = matches
        if hidden:
            info(f"{hidden} other BLE device(s) hidden; pass --all to list everything")
    elif not matches:
        info("no device advertised the BlueAir service; showing all devices")
        info("pick the purifier's MAC and pass it with --address")

    print(discovery.format_table(devices))
    if matches:
        info(f"* = advertises the BlueAir provisioning service ({discovery.SERVICE_UUID})")
    return 0


async def _connect(args) -> BlueAirBLE:
    if args.address and not args.name:
        # Prefer the scanned BLEDevice object: it carries the address type and
        # adapter path, and refreshes a stale advertisement.
        devices = await discovery.scan(min(max(args.timeout, 1.0), 3.0), include_all=True)
        match = next((d for d in devices if d.address.lower() == args.address.lower()), None)
        chosen = match or discovery.DiscoveredDevice(
            name="", address=args.address, rssi=0, service_match=False
        )
        if match is None:
            info(f"{args.address} not seen in the short scan; connecting by address")
    else:
        devices = await discovery.scan(args.timeout, include_all=True)
        chosen = discovery.select_device(devices, address=args.address, name=args.name)

    info(f"connecting to {chosen.label or 'device'} {chosen.address}")
    service = await connect(chosen, timeout=args.ble_timeout, settle=args.ble_settle)
    ok("BLE session established (Security 1)")
    return service


async def _run(ctx: Context, args) -> int:
    service = None
    try:
        service = await _connect(args)

        if args.action == "provision":
            result = await provision(
                service,
                broker=args.broker,
                api=args.api or "",
                auth=args.auth or "",
                region=args.region or "",
                ssid=args.ssid,
                password=args.password,
                open_network=args.open_network,
                random_text=args.random_text,
                secure_random=args.secure_random,
                full_config=args.full_config,
                wifi_hook=getattr(args, "wifi_hook", None),
                wait_events=getattr(args, "wifi_events", False),
            )
            if result.event is not None:
                _print_events([result.event])

        elif args.action == "factory":
            saved = read_json(ctx.output / "ap.json", default={}) or {}
            gateway = saved.get("gateway")
            default_url = f"https://{gateway or local_ip() or '192.168.1.10'}:8443"
            url = args.factory_url or default_url
            ssid = args.factory_ssid or saved.get("ssid") or FACTORY_SSID
            pwd = args.factory_password or saved.get("psk") or FACTORY_PSK
            token = args.factory_token or ctx.token()
            step(1, 1, "Send FactoryCmd")
            info(f"factory url: {url}")
            info(f"factory AP:  {ssid}")
            await service.set_factory(FactoryConfiguration(url=url, ssid=ssid, pwd=pwd, token=token))
            ok("factory command sent; the device should reboot into factory mode")

        elif args.action == "events":
            step(1, 1, "Read pending events")
            _print_events(await service.get_all_events())

        elif args.action == "info":
            step(1, 2, "Read MAC address")
            print(f"MAC: {await service.read_address()}")
            step(2, 2, "Read filter")
            filter_type = args.filter_type or ""
            try:
                print(f"filter({filter_type!r}): {await service.read_filter(filter_type)}")
            except CutterError as exc:
                info(f"filter read failed: {exc}")

        elif args.action == "wifi-scan":
            step(1, 1, "Scan for WiFi networks")
            networks = await service.wifi_scan()
            print(f"{'SSID':32} {'BSSID':18} {'CH':>3} {'RSSI':>5}  AUTH")
            for network in networks:
                print(
                    f"{network.ssid[:32]:32} {network.bssid:18} {network.channel:3} "
                    f"{network.rssi:5}  {network.security.name}"
                )

        elif args.action == "filter":
            if args.filter_value is not None:
                step(1, 1, "Write filter value")
                await service.write_filter(args.filter_value)
                ok("filter value written")
            else:
                step(1, 1, "Read filter value")
                print(await service.read_filter(args.filter_type or ""))

        else:
            raise CutterError(f"unknown BLE action {args.action!r}")

        return 0
    finally:
        if service is not None:
            await service.disconnect()


def run(ctx: Context, args) -> int:
    if args.action == "provision":
        if not args.broker:
            raise CutterError("ble provision needs --broker <broker host or endpoint>")
        cfg = aws.load_default(ctx.output)
        if cfg and not args.region:
            args.region = cfg.region

        api = getattr(args, "api", None)
        auth = getattr(args, "auth", None)
        if bool(api) != bool(auth):
            raise CutterError("pass both --api and --auth to override the fake API")

    if args.action == "scan":
        return asyncio.run(_scan(args))

    fake: FakeApiServer | None = None
    if (
        args.action == "provision"
        and not getattr(args, "no_fake_api", False)
        and not (args.api and args.auth)
    ):
        try:
            fake = FakeApiServer(port=getattr(args, "fake_api_port", 8000)).start()
        except OSError as exc:
            raise CutterError(
                f"cannot start the fake provisioning API on :{getattr(args, 'fake_api_port', 8000)}: {exc}"
            ) from exc
        host = getattr(args, "fake_api_host", None) or local_ip() or "192.168.50.1"
        args.api, args.auth = fake.urls(host)
        ok(f"fake API on :{fake.port} (api_url={args.api})")

    try:
        status = asyncio.run(_run(ctx, args))
        if fake is not None and status == 0:
            info("waiting for authenticate and register-device-hash ...")
            if not fake.wait_for_provisioning(getattr(args, "fake_api_wait", 60.0)):
                warn("the device did not call both provisioning endpoints")
        return status
    finally:
        if fake is not None:
            fake.stop()
