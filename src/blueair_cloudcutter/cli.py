"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, exploit
from .context import Context
from .errors import CutterError
from .helpers import aws as aws_cmd
from .helpers import (
    ble,
    doctor,
    flash,
    liberate,
    materials,
    mqtt,
    serve,
)
from .helpers import (
    capture as capture_cmd,
)
from .util import error, hand_back_output, warn


def _device_args(p: argparse.ArgumentParser) -> None:
    """Allow --ip/--did after the subcommand, without clobbering the group value."""
    p.add_argument("--ip", default=argparse.SUPPRESS, help="device LAN IP")
    p.add_argument("--did", default=argparse.SUPPRESS, help="device UUID")


def _broker_args(p: argparse.ArgumentParser, *, with_broker: bool = True) -> None:
    if with_broker:
        p.add_argument("--broker", help="MQTT broker hostname or IP")
        p.add_argument("--broker-port", type=int, default=8883)
    p.add_argument("--ca", type=Path, help="CA used to verify the broker")
    p.add_argument("--cert", type=Path, help="client certificate, if the broker requires one")
    p.add_argument("--key", type=Path, help="client private key")
    p.add_argument("--insecure", action="store_true", help="do not verify the broker hostname")


def _exploit_parser(sub) -> None:
    e = sub.add_parser(
        "exploit",
        help="one command: AP, BLE, capture, AWS, then local control or firmware",
    )
    e.add_argument("--iface", help="AP interface (for example wld0)")
    e.add_argument(
        "--ssid",
        help="home WiFi SSID (required for local control and firmware; moves the device there)",
    )
    e.add_argument("--password", help="home WiFi password")
    e.add_argument(
        "--skip-wifi-setup",
        action="store_true",
        help="do not move the device to your WiFi before the next step; "
        "use it when the device is already there. --ssid/--password are still "
        "used after the local-control reset and in FactoryCmd.",
    )
    e.add_argument("--channel", type=int, default=6, help="AP channel (default 6)")
    e.add_argument("--gateway", default="192.168.50.1", help="AP gateway address")
    e.add_argument(
        "--local-broker",
        help="broker hostname the device dials (DNS name, not an IP)",
    )
    e.add_argument(
        "--broker-ca",
        type=Path,
        help="CA that signed your broker certificate (default: generate a bundle)",
    )
    e.add_argument("--firmware", type=Path, help="custom .bin to install through factory mode")
    e.add_argument(
        "--local-control",
        action="store_true",
        help="plant your broker CA and move the device to it",
    )
    e.add_argument(
        "--onboard-only",
        action="store_true",
        help="stop after onboarding and DID discovery",
    )
    e.add_argument(
        "--device",
        help="onboarded device: DID, certificate id, BLE address or list index",
    )
    e.add_argument("--address", help="BLE address (default: scan and pick the BlueAir device)")
    e.add_argument(
        "--device-cert",
        type=Path,
        help="already captured device client certificate (PEM or DER); "
        "skips the provisioning AP and packet capture",
    )
    e.add_argument("--region", help="AWS region (default: from the AWS profile/login)")
    e.add_argument("--profile", help="AWS CLI profile")
    e.add_argument(
        "--reprovision",
        action="store_true",
        help="provision over BLE even if a DID is already known",
    )
    e.add_argument("--dry-run", action="store_true", help="check the firmware image, do not flash")
    e.add_argument("--did", default=argparse.SUPPRESS, help="device UUID")
    e.set_defaults(func=exploit.run)


def _aws_parser(sub) -> None:
    a = sub.add_parser("aws", help="AWS login, onboarding and device records")
    a.add_argument(
        "action",
        choices=("guide", "login", "check", "onboard", "show", "discover", "devices"),
    )
    a.add_argument("--device", help="onboarded device: DID, certificate id, BLE address or list index")
    a.add_argument("--region", help="AWS region (default: from the AWS profile/login)")
    a.add_argument("--profile", help="AWS CLI profile (default: boto3 credential chain)")
    a.add_argument("--device-cert", type=Path, help="captured client certificate (c-b), PEM or DER")
    a.add_argument("--thing", help="thing name (default: blueair-device-<cert prefix>)")
    a.add_argument("--policy", default="blueair-policy")
    a.add_argument(
        "--control-name",
        help="control identity name (default: blueair-controller-<cert prefix>)",
    )
    a.add_argument("--access-key", help="login: access key ID (prompted if omitted)")
    a.add_argument(
        "--secret-key",
        help="login: secret key (prompted if omitted; prefer the prompt)",
    )
    a.add_argument("--session-token", help="login: session token for temporary credentials")
    a.add_argument(
        "--setup-code",
        help="login: one-line code from scripts/aws-bootstrap.sh (contains the key)",
    )
    a.add_argument("--sso", action="store_true", help="login: use IAM Identity Center in the browser")
    a.add_argument("--sso-start-url", help="login: IAM Identity Center start URL")
    a.add_argument("--sso-region", help="login: SSO region (default: profile or us-east-1)")
    a.add_argument("--sso-account", help="login: account id (picked interactively if omitted)")
    a.add_argument("--sso-role", help="login: role name (picked interactively if omitted)")
    a.add_argument("--no-browser", action="store_true", help="login: print the URL, do not open it")
    a.add_argument("--timeout", type=float, default=60)
    a.set_defaults(func=aws_cmd.run)


def _ble_parser(hs) -> None:
    bl = hs.add_parser("ble", help="Bluetooth provisioning, factory mode, events, WiFi")
    bl.add_argument(
        "action", choices=("scan", "provision", "factory", "events", "info", "wifi-scan", "filter")
    )
    bl.add_argument("--address", help="BLE address/UUID from `helpers ble scan`")
    bl.add_argument("--name", help="device name substring")
    bl.add_argument("--timeout", type=float, default=10.0, help="scan duration")
    bl.add_argument("--blueair-only", action="store_true", help="only list devices advertising the service")
    bl.add_argument("--all", action="store_true", help="list every BLE device, not just BlueAir ones")
    bl.add_argument("--ble-timeout", type=float, default=20.0)
    bl.add_argument("--ble-settle", type=float, default=0.0, help="delay after each write")
    bl.add_argument(
        "--api",
        help="override the built-in fake provisioning API (requires --auth)",
    )
    bl.add_argument(
        "--auth",
        help="override the built-in fake provisioning API (requires --api)",
    )
    bl.add_argument("--fake-api-port", type=int, default=8000)
    bl.add_argument(
        "--fake-api-host",
        help="address the device uses for the fake API (default: this host's LAN IP)",
    )
    bl.add_argument("--fake-api-wait", type=float, default=60.0)
    bl.add_argument("--broker", help="ConfigCmd broker_url (required for provision)")
    bl.add_argument("--region", help="ConfigCmd region")
    bl.add_argument("--random-text")
    bl.add_argument("--secure-random")
    bl.add_argument(
        "--full-config", action="store_true", help="send all six ConfigCmd fields, including empty"
    )
    bl.add_argument("--ssid", "--wifi-ssid", dest="ssid", help="WiFi SSID to provision")
    bl.add_argument(
        "--password", "--wifi-password", dest="password", help="WiFi password (or use --open-network)"
    )
    bl.add_argument("--open-network", action="store_true")
    bl.add_argument("--factory-url", help="FactoryCmd url (base URL of your factory server)")
    bl.add_argument("--factory-ssid", help="factory AP SSID")
    bl.add_argument("--factory-password", help="factory AP password")
    bl.add_argument("--factory-token", help="JWT for FactoryCmd (default: mint from materials/kjwt.key)")
    bl.add_argument("--filter-type", default="")
    bl.add_argument("--filter-value")
    bl.set_defaults(func=ble.run)


def _flash_parser(hs) -> None:
    f = hs.add_parser("flash", help="install custom firmware, or restore the official image")
    _device_args(f)
    f.add_argument("--custom", help="unsigned ESP32 app .bin")
    f.add_argument(
        "--official",
        help="a BlueAir-signed app image; alone it restores that image into the passive slot",
    )
    f.add_argument(
        "--no-dump", action="store_true", default=True, help="use the erase-size overflow (default)"
    )
    f.add_argument("--fw-version", default="1.0.9", help="version string written into the manifest")
    f.add_argument(
        "--image-name",
        help="manifest image name; must contain the di.hw family prefix "
        "(default: derived from di.hw, else ba_nb_wifi.bin)",
    )
    f.add_argument("--header16", help="override the 16-byte image header (hex)")
    f.add_argument("--pad", type=int, default=1048832 + 8192)
    f.add_argument("--settle", type=float, default=2.0)
    f.add_argument("--no-reset", action="store_true", help="stop after the swap; do not reboot")
    f.add_argument(
        "--send-pad", action="store_true", help="transmit the padding instead of only declaring it"
    )
    f.add_argument("--dry-run", action="store_true")
    f.set_defaults(func=flash.run)


def _liberate_parser(hs) -> None:
    lib = hs.add_parser("liberate", help="plant a broker CA and move the device to your broker")
    lib.add_argument("--ip", default=argparse.SUPPRESS, help="device LAN IP")
    lib.add_argument("--transport", choices=("factory", "mqtt"), default="factory")
    lib.add_argument(
        "--slot", choices=("c-r", "c-r2"), help="trust anchor to replace (default c-r; c-r2 has no effect)"
    )
    lib.add_argument(
        "--broker", help="broker the device is on now (MQTT transport), or the local broker (factory)"
    )
    lib.add_argument("--local-broker", help="local broker address the device will dial")
    lib.add_argument("--broker-port", type=int, default=8883)
    lib.add_argument("--san", action="append", help="extra SAN for the broker certificate")
    lib.add_argument("--ssid", help="WiFi SSID to move the device to (factory transport)")
    lib.add_argument("--wifi-password")
    lib.add_argument("--api", help="legacy API URL to store (optional)")
    lib.add_argument("--auth", help="legacy auth URL to store (optional)")
    lib.add_argument("--bssid", help="AP BSSID, aa:bb:cc:dd:ee:ff (default all zeros)")
    lib.add_argument("--no-reset", action="store_true", help="do not reboot after provision/ssid")
    lib.add_argument("--wait", type=float, default=120)
    lib.add_argument(
        "--restore-roots", action="store_true", help="write the stock Amazon/Starfield roots back"
    )
    lib.add_argument("--did", default=argparse.SUPPRESS, help="device UUID")
    _broker_args(lib, with_broker=False)
    lib.set_defaults(func=liberate.run)


def _mqtt_parser(hs) -> None:
    m = hs.add_parser("mqtt", help="read/write config, plant a CA or JWT, control actuators")
    _device_args(m)
    m.add_argument("action", choices=("read", "write", "plant-ca", "plant-kjwt", "control"))
    m.add_argument("--transport", choices=("mqtt", "factory"), default="mqtt")
    m.add_argument("--type", default="State", choices=("State", "Full", "Diff"))
    m.add_argument("--save", type=Path)
    m.add_argument("--set", action="append", metavar="SECTION.KEY=VALUE")
    m.add_argument("--json")
    m.add_argument("--cas", type=int)
    m.add_argument("--cfg-version", dest="version", type=int)
    m.add_argument(
        "--wait",
        type=float,
        default=None,
        help="seconds to wait for a reply (default: 15 for State/Diff, 90 for Full)",
    )
    m.add_argument("--read-v", type=int, default=1, help="baseline version for --type Diff")
    m.add_argument("--slot")
    m.add_argument("--cert-file", type=Path)
    m.add_argument("--actuator")
    m.add_argument("--value")
    m.add_argument("--boolean", action="store_true")
    _broker_args(m)
    m.set_defaults(func=mqtt.run)


def _serve_parser(hs) -> None:
    v = hs.add_parser("serve", help="run the factory rendezvous, network services or broker")
    v.add_argument("service", choices=("factory", "network", "broker", "fake-api"))
    v.add_argument("--host", default="0.0.0.0")
    v.add_argument(
        "--cert-host",
        default="factoryserver.blueair",
        help="factory certificate SAN (use the AP gateway IP for an IP URL)",
    )
    v.add_argument("--listen-port", type=int, default=8443)
    v.add_argument("--no-tls", action="store_true")
    v.add_argument("--once", action="store_true")
    v.add_argument("--timeout", type=float, default=300)
    v.add_argument("--iface", help="AP interface (required for network/broker)")
    v.add_argument("--ssid", default="BAFactory")
    v.add_argument("--psk", default="9102revreSyrotcaF")
    v.add_argument("--country", help="Wi-Fi country code, e.g. HU")
    v.add_argument("--gateway", default="192.168.50.1")
    v.add_argument(
        "--dhcp-dns",
        help="DNS handed to the device (default: local dnsmasq; use the uplink router for NTP)",
    )
    v.add_argument("--start", action="store_true")
    v.add_argument("--broker-port", type=int, default=8883)
    v.add_argument("--api-port", type=int, default=8000, help="fake-api listen port")
    v.add_argument("--san", action="append")
    v.set_defaults(func=serve.run)


def _capture_parser(hs) -> None:
    cap = hs.add_parser("capture", help="capture the device client certificate from its TLS handshake")
    cap.add_argument("--interface", required=True, help="AP interface to sniff")
    cap.add_argument("--timeout", type=float, default=120)
    cap.add_argument("--out", type=Path, help="output PEM (default output/device.pem)")
    cap.add_argument("--pcap", type=Path, help="also save the captured packets")
    cap.set_defaults(func=capture_cmd.run)


def _materials_parser(hs) -> None:
    mt = hs.add_parser("materials", help="generate or inspect local keys and certificates")
    mt.add_argument("action", choices=("init", "show"), default="init", nargs="?")
    mt.add_argument("--san", action="append")
    mt.add_argument("--org", default="BlueAir CloudCutter")
    mt.set_defaults(func=materials.run)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="blueair-cloudcutter",
        description="Local control and custom firmware for BlueAir AWS IoT purifiers.",
        epilog="Run without a subcommand for the guided exploit. Manual commands live under `helpers`.",
    )
    p.add_argument("--output", default=os.environ.get("BLUEAIR_CLOUDCUTTER_OUTPUT", "output"), type=Path)
    p.add_argument("--did", help="device UUID")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = p.add_subparsers(dest="command")
    _exploit_parser(sub)
    sub.add_parser("doctor", help="check the local environment").set_defaults(func=doctor.run)
    _aws_parser(sub)

    h = sub.add_parser("helpers", help="manual and recovery commands")
    h.add_argument("--ip", help="device LAN IP")
    h.add_argument("--did", help="device UUID")
    h.add_argument("--port", type=int, default=443, help="device HTTPS port (default 443)")
    h.add_argument("--token-file", type=Path, help="JWT to send instead of minting one")
    h.add_argument("--bind", help="source IP to bind on a dual-homed host")
    hs = h.add_subparsers(dest="helper")
    _ble_parser(hs)
    _capture_parser(hs)
    _flash_parser(hs)
    _liberate_parser(hs)
    _mqtt_parser(hs)
    _serve_parser(hs)
    _materials_parser(hs)

    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        args = parser.parse_args([*argv, "exploit"])

    if args.verbose:
        os.environ["BLUEAIR_CLOUDCUTTER_VERBOSE"] = "1"

    ctx = Context(
        output=args.output,
        ip=getattr(args, "ip", None),
        did=args.did,
        port=getattr(args, "port", 443),
        token_file=getattr(args, "token_file", None),
        bind=getattr(args, "bind", None),
    )
    if args.command in {"aws", "exploit"} and not os.environ.get("AWS_PROFILE"):
        marker = args.output / "aws-profile"
        if marker.exists():
            os.environ["AWS_PROFILE"] = marker.read_text().strip()
        else:
            from .aws import sso_profiles

            profiles = sso_profiles()
            if len(profiles) == 1:
                os.environ["AWS_PROFILE"] = profiles[0]

    try:
        if args.command == "helpers":
            if args.helper == "serve":
                args.port = args.listen_port
            if args.helper == "flash":
                args.version = args.fw_version
                if args.official:
                    args.no_dump = False
            if args.helper == "liberate":
                args.reset = not args.no_reset
        return args.func(ctx, args)
    except CutterError as exc:
        error(str(exc))
        return 2
    except KeyboardInterrupt:
        print()
        warn("interrupted")
        return 130
    finally:
        hand_back_output(ctx.output)
