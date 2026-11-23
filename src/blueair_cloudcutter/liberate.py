"""Replace the device broker trust anchor.

The write is a `Diff` to `db.c-r`. It is atomic: no ack means nothing changed.
`c-r` is the active trust anchor on this firmware; `c-r2` is a rotation slot
with no effect.
"""

from __future__ import annotations

from pathlib import Path

from .certs import load_cert_text
from .configapi import find_version, read_mqtt, set_fields_http, write_mqtt
from .constants import AP_SSID, BROKER_CA_SLOTS
from .context import Context
from .errors import CutterError
from .mqttclient import MQTT, MQTTConfig
from .network import write_mqtt_bundle
from .util import info, ok, warn


def broker_ca_text(ctx: Context, path: Path | None) -> str:
    """The CA to plant: the user's broker CA, or our generated one."""
    if path is not None:
        if not path.exists():
            raise CutterError(f"broker CA not found: {path}")
        return load_cert_text(path)
    ctx.materials.ensure_ca()
    return load_cert_text(ctx.materials.ca_cert)


def prepare_bundle(ctx: Context, sans: str | list[str], *, port: int = 8883) -> Path:
    """Write a self-contained mosquitto folder for the given SANs."""
    names = [sans] if isinstance(sans, str) else list(sans)
    path = write_mqtt_bundle(ctx.materials, ctx.output / "mqtt", port=port, sans=names or ["localhost"])
    ok(f"broker bundle -> {path.parent}")
    info(f"  start it with: (cd {path.parent} && ./start.sh)")
    return path


def plant_cert_mqtt(
    *,
    did: str,
    slot: str,
    cert_text: str,
    host: str,
    port: int = 8883,
    ca: Path | None = None,
    cert: Path | None = None,
    key: Path | None = None,
    insecure: bool = False,
    what: str | None = None,
) -> None:
    """Write one `db.<slot>` value over MQTT, waiting for the ack."""
    with MQTT(MQTTConfig(host=host, port=port, ca=ca, cert=cert, key=key, insecure=insecure)) as mqtt:
        text = read_mqtt(mqtt, did, wait_for_device=True)
        if not text:
            raise CutterError(
                f"no config reply from {did} on {host}:{port}. The device is not connected "
                "to this broker, or it is in factory mode. If it is still on the temporary "
                f"{AP_SSID} AP, rerun without --skip-wifi-setup."
            )
        cas = find_version(text)
        if cas is None:
            raise CutterError(
                f"the config reply from {did} has no _v field. The device may be in factory "
                "mode, or the DID is wrong."
            )
        result = write_mqtt(mqtt, did, {"db": {slot: cert_text}}, cas=cas)
        print(result[:800])
        if '"ack"' not in result and '"c":200' not in result:
            raise CutterError("write was not acknowledged; nothing changed")
    ok(f"db.{slot} written" + (f" ({what})" if what else ""))


def plant_ca_mqtt(
    ctx: Context,
    *,
    did: str,
    ca_text: str,
    host: str,
    port: int = 8883,
    ca: Path | None = None,
    cert: Path | None = None,
    key: Path | None = None,
    insecure: bool = False,
    slot: str = BROKER_CA_SLOTS[0],
) -> None:
    plant_cert_mqtt(
        did=did,
        slot=slot,
        cert_text=ca_text,
        host=host,
        port=port,
        ca=ca,
        cert=cert,
        key=key,
        insecure=insecure,
        what="broker CA",
    )


def plant_kjwt_mqtt(
    ctx: Context,
    *,
    did: str,
    host: str,
    port: int = 8883,
    ca: Path | None = None,
    cert: Path | None = None,
    key: Path | None = None,
    insecure: bool = False,
) -> None:
    ctx.materials.ensure_kjwt()
    plant_cert_mqtt(
        did=did,
        slot="k-jwt",
        cert_text=load_cert_text(ctx.materials.p("kjwt.pem")),
        host=host,
        port=port,
        ca=ca,
        cert=cert,
        key=key,
        insecure=insecure,
        what="factory JWT",
    )


def restore_roots(ctx: Context, args) -> int:
    roots = Path(__file__).resolve().parent / "data" / "roots"
    slots = {"c-r": roots / "amazon_root_ca1.pem"}
    for slot, path in slots.items():
        if not path.exists():
            warn(f"missing stock root {path}; skipping {slot}")
            continue
        cert_text = load_cert_text(path)
        if args.transport == "factory":
            set_fields_http(ctx.http(), ctx.did, ctx.token(), {"db": {slot: cert_text}})
        else:
            if not args.broker:
                raise CutterError("--transport mqtt needs --broker")
            plant_cert_mqtt(
                did=ctx.did,
                slot=slot,
                cert_text=cert_text,
                host=args.broker,
                port=args.broker_port,
                ca=args.ca,
                cert=args.cert,
                key=args.key,
                insecure=args.insecure,
                what="stock root",
            )
        ok(f"db.{slot} restored")

    # The marker means "c-r holds our CA, skip the AWS write". It does not
    # describe the device any more.
    if ctx.state.steps.pop("liberate", None) is not None:
        ctx.save()
        info("cleared the local-control marker in output/state.json")
    return 0
