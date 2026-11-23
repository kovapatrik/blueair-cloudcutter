"""MQTT and factory-HTTPS operations: read, write, plant a CA and control.

`read` and `write` work over both transports. `--transport factory` is the old
`config` command; the device must be in factory mode.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .. import aws
from ..certs import load_cert_text
from ..configapi import (
    find_version,
    read_http,
    read_mqtt,
    set_fields_http,
    write_mqtt,
)
from ..context import Context
from ..errors import CutterError
from ..liberate import plant_cert_mqtt
from ..mqttclient import MQTT, MQTTConfig
from ..util import info, ok, step, warn


def _client(args) -> MQTT:
    return MQTT(
        MQTTConfig(
            host=args.broker,
            port=args.broker_port,
            ca=args.ca,
            cert=args.cert,
            key=args.key,
            insecure=args.insecure,
        )
    )


def _payload(args) -> dict:
    payload: dict = {}
    for pair in getattr(args, "set", None) or []:
        if "=" not in pair:
            raise CutterError(f"bad --set {pair!r}: expected section.key=value")
        lhs, value = pair.split("=", 1)
        if "." not in lhs:
            raise CutterError(f"bad --set {pair!r}: expected section.key=value")
        section, key = lhs.split(".", 1)
        payload.setdefault(section, {})[key] = value
    if args.json:
        try:
            extra = json.loads(args.json)
        except json.JSONDecodeError as exc:
            raise CutterError(f"bad --json: {exc}") from exc
        if not isinstance(extra, dict):
            raise CutterError("--json must be an object")
        for section, body in extra.items():
            if isinstance(body, dict):
                payload.setdefault(section, {}).update(body)
            else:
                payload[section] = body
    return payload


def _did(ctx: Context, args) -> str:
    did = args.did or ctx.did
    if not did:
        raise CutterError("device ID unknown; pass --did")
    return did


def _read_factory(ctx: Context, args, did: str) -> int:
    step(1, 1, f"Read configuration ({args.type})")
    resp = read_http(ctx.http(), did, ctx.token(), args.type, v=args.read_v)
    print(resp.body[:8000])
    if not resp.ok:
        raise CutterError(str(resp))
    info(f"_v={find_version(resp.body)}")
    if args.save:
        args.save.write_text(resp.body)
        ok(f"saved -> {args.save}")
    return 0


def _write_factory(ctx: Context, args, did: str) -> int:
    payload = _payload(args)
    if not payload:
        raise CutterError("write needs --set or --json")
    step(1, 1, "Write configuration (Diff)")
    set_fields_http(ctx.http(), did, ctx.token(), payload, cas=args.cas, version=args.version)
    ok("acknowledged")
    return 0


def _mqtt_payload(args) -> dict:
    """Legacy `mqtt write` used raw JSON; keep that working."""
    return _payload(args)


def run(ctx: Context, args) -> int:
    aws.apply_defaults(ctx.output, args)
    did = _did(ctx, args)

    if args.transport == "factory":
        if args.action == "read":
            return _read_factory(ctx, args, did)
        if args.action == "write":
            return _write_factory(ctx, args, did)
        raise CutterError(f"{args.action} needs --transport mqtt")

    cfg = aws.load_default(ctx.output)
    if args.ca is None and args.broker and cfg and args.broker != cfg.endpoint:
        if ctx.materials.ca_cert.exists():
            args.ca = ctx.materials.ca_cert
    if not args.broker:
        raise CutterError("--broker is required for MQTT operations")

    with _client(args) as mqtt:
        if args.action == "read":
            step(1, 1, f"Read {args.type}")
            text = read_mqtt(mqtt, did, args.type, wait=args.wait)
            if not text:
                raise CutterError("no reply (a Full read can take ~30 s; try --wait 60)")
            print(text[:12000])
            if args.save:
                args.save.write_text(text)
                ok(f"saved -> {args.save}")
            info(f"_v={find_version(text)}")
            return 0

        if args.action == "write":
            payload = _mqtt_payload(args)
            if not payload:
                raise CutterError("write needs --set or --json")
            step(1, 1, "Write config (Diff)")
            text = write_mqtt(mqtt, did, payload, cas=args.cas, version=args.version, wait=args.wait or 10.0)
            print(text)
            if '"ack"' in text or '"c":200' in text:
                ok("acknowledged")
                return 0
            raise CutterError("not acknowledged; nothing was applied")

        if args.action in {"plant-ca", "plant-kjwt"}:
            if args.action == "plant-ca":
                slot = args.slot or "c-r"
                cert_path = args.cert_file or ctx.materials.ca_cert
            else:
                slot = args.slot or "k-jwt"
                cert_path = args.cert_file or ctx.materials.p("kjwt.pem")
            if args.action == "plant-kjwt" and not args.cert_file:
                ctx.materials.ensure_kjwt()
            if cert_path is None or not Path(cert_path).exists():
                raise CutterError(f"{args.action} needs a certificate file (--cert-file or materials)")
            step(1, 1, f"Plant {cert_path} into db.{slot}")
            plant_cert_mqtt(
                did=did,
                slot=slot,
                cert_text=load_cert_text(Path(cert_path)),
                host=args.broker,
                port=args.broker_port,
                ca=args.ca,
                cert=args.cert,
                key=args.key,
                insecure=args.insecure,
            )
            warn("keep the broker up before the device reconnects after a reboot")
            return 0

        if args.action == "control":
            if not args.actuator:
                raise CutterError("control needs --actuator")
            value = args.value
            if value is None:
                raise CutterError("control needs --value")
            payload = {"n": args.actuator}
            if args.boolean:
                payload["vb"] = value.lower() in {"1", "true", "yes", "on"}
            else:
                payload["v"] = float(value) if "." in value else int(value)
            payload["t"] = int(time.time())
            payload["bn"] = f"urn:dev:ow:{did}:"
            topic = f"d/{did}/a/{args.actuator}"
            step(1, 1, f"Publish {topic}")
            mqtt.publish(topic, payload)
            ok(json.dumps(payload))
            return 0

    raise CutterError(f"unknown action {args.action!r}")
