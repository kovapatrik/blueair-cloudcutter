"""Plant a broker CA and move the device to your broker.

Two transports:

* `--transport factory` (recommended): the device is in factory mode, so the
  config is written over HTTPS. No AWS account and no broker are needed to
  plant the CA. Then `provision/ssid` points the device at your WiFi and broker
  and takes it out of factory mode.
* `--transport mqtt`: the device is already connected to a broker you can
  publish on (typically your own AWS IoT). Plant the CA there.
"""

from __future__ import annotations

from pathlib import Path

from .. import aws
from ..configapi import set_fields_http
from ..constants import BROKER_CA_SLOTS
from ..context import Context
from ..errors import CutterError
from ..liberate import broker_ca_text, plant_ca_mqtt, prepare_bundle, restore_roots
from ..util import confirm, info, local_ip, ok, step


def _local_broker(args) -> str | None:
    explicit = getattr(args, "local_broker", None)
    if explicit:
        return explicit
    if getattr(args, "transport", "factory") == "mqtt":
        # --broker is the broker the device is on now (your AWS); the local
        # target is this machine unless explicitly overridden.
        return local_ip()
    return getattr(args, "broker", None)


def _write_bundle(ctx: Context, args) -> Path:
    sans = list(args.san or [])
    local = _local_broker(args)
    if local:
        sans.append(local.split("://")[-1].split(":")[0])
    return prepare_bundle(ctx, sans, port=args.broker_port)


def _provision_ssid(ctx: Context, args) -> None:
    if not (args.ssid and args.wifi_password):
        info("WiFi credentials not supplied; the device stays in factory mode")
        info("run `liberate` again with --ssid/--wifi-password, or send provision/ssid yourself")
        return
    payload = {
        "bssid": (args.bssid or "00:00:00:00:00:00").lower(),
        "ssid": args.ssid,
        "password": args.wifi_password,
        "rand": "x",
        "text": "x",
    }
    if args.broker:
        payload["broker"] = (
            args.broker if "://" in args.broker else f"mqtts://{args.broker}:{args.broker_port}"
        )
    if getattr(args, "api", None):
        payload["api"] = args.api
    if getattr(args, "auth", None):
        payload["auth"] = args.auth
    http = ctx.http()
    token = ctx.token()
    step(1, 1, "Exit factory mode and point the device at your WiFi/broker")
    resp = http.post_json(f"/d/{ctx.did}/provision/ssid", payload, token, timeout=30)
    print(resp)
    if not resp.ok:
        raise CutterError(f"provision/ssid failed: {resp}")
    ok("credentials accepted (fc.mode=0 persisted). Reboot to leave factory mode.")
    if args.reset and confirm("reboot now?", default=True):
        try:
            http.get(f"/d/{ctx.did}/management/reset", token, allow_early_close=True)
        except Exception:
            pass
        info("waiting for the device to come back ...")
        http.wait_alive(args.wait, down_first=True)


def run(ctx: Context, args) -> int:
    if args.transport == "mqtt":
        aws.apply_defaults(ctx.output, args)
        if args.ca is None and args.broker:
            cfg = aws.load_default(ctx.output)
            if cfg and args.broker != cfg.endpoint and ctx.materials.ca_cert.exists():
                args.ca = ctx.materials.ca_cert
        if not ctx.did and getattr(args, "did", None):
            ctx.did = args.did
    if not ctx.did:
        if args.transport == "factory" and ctx.ip:
            ctx.discover()
        else:
            raise CutterError("device ID unknown; pass --did")

    if args.restore_roots:
        return restore_roots(ctx, args)

    slot = args.slot or BROKER_CA_SLOTS[0]
    ca_text = broker_ca_text(ctx, None)

    if args.transport == "factory":
        step(1, 3, f"Plant your CA into db.{slot}")
        set_fields_http(ctx.http(), ctx.did, ctx.token(), {"db": {slot: ca_text}})
        ok(f"db.{slot} written")

        step(2, 3, "Broker certificate")
        _write_bundle(ctx, args)

        step(3, 3, "Move the device to your broker")
        _provision_ssid(ctx, args)
    else:
        if not args.broker:
            raise CutterError("--transport mqtt needs --broker")
        step(1, 2, f"Plant your CA into db.{slot} (over MQTT)")
        plant_ca_mqtt(
            ctx,
            did=ctx.did,
            ca_text=ca_text,
            host=args.broker,
            port=args.broker_port,
            ca=args.ca,
            cert=args.cert,
            key=args.key,
            insecure=args.insecure,
            slot=slot,
        )
        step(2, 2, "Broker certificate")
        _write_bundle(ctx, args)
        info("now point the device at the broker: either via BLE ConfigCmd, or by")
        info("putting it in factory mode and running this command with --transport factory")

    ctx.state.mark("liberate", slot=slot, broker=args.broker)
    ctx.save()

    print()
    print("Next:")
    print(f"  1. start the broker:  (cd {ctx.output / 'mqtt'} && ./start.sh)")
    print(f"  2. make the device dial {_local_broker(args) or '<your broker>'}:{args.broker_port}")
    print("  3. if you used an IP, no DNS is needed. If you used a hostname, add a DNS")
    print("     rewrite for it to this machine.")
    print(
        "  4. control it:  blueair-cloudcutter helpers mqtt control "
        "--broker ... --did ... --actuator fsp0 --value 3"
    )
    return 0
