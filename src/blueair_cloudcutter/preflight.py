"""Environment checks. Run before any destructive operation."""

from __future__ import annotations

import asyncio
import importlib.util
import os
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    required: bool = True


def _module(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _port_status(port: int, proto: str) -> tuple[bool, str]:
    kind = socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM
    s = socket.socket(socket.AF_INET, kind)
    try:
        s.bind(("0.0.0.0", port))
        return True, "free"
    except PermissionError:
        return False, "requires root"
    except OSError as exc:
        return False, f"in use ({exc.strerror or exc})"
    finally:
        s.close()


def user_namespace_is_host() -> bool | None:
    """False when container root is mapped to another uid (rootless/userns-remap)."""
    uid_map = Path("/proc/self/uid_map")
    if not uid_map.exists():
        return None
    try:
        fields = [line.split() for line in uid_map.read_text().splitlines() if line.strip()]
        # An identity map is "0 0 4294967295"; rootless Docker and userns-remap
        # map container root to a host uid/subuid instead.
        return len(fields) == 1 and fields[0][:2] == ["0", "0"] and int(fields[0][2]) > 1_000_000
    except (OSError, ValueError, IndexError):
        return None


def _bluez_status(timeout: float = 5.0) -> tuple[bool, str]:
    """Probe BlueZ through the same dbus-fast path bleak uses."""
    try:
        from dbus_fast import BusType, Message, MessageType
        from dbus_fast.aio import MessageBus
        from dbus_fast.auth import UID_NOT_SPECIFIED, AuthExternal
    except ImportError:
        return False, "dbus-fast not installed"

    async def probe() -> str:
        bus = await MessageBus(bus_type=BusType.SYSTEM, auth=AuthExternal(UID_NOT_SPECIFIED)).connect()
        try:
            reply = await bus.call(
                Message(
                    destination="org.bluez",
                    path="/",
                    interface="org.freedesktop.DBus.ObjectManager",
                    member="GetManagedObjects",
                )
            )
        finally:
            bus.disconnect()
        if reply.message_type is MessageType.ERROR:
            return str(reply.body[0]) if reply.body else "error reply"
        objects = reply.body[0] if reply.body else {}
        return f"{len(objects)} objects"

    try:
        return True, asyncio.run(asyncio.wait_for(probe(), timeout))
    except Exception as exc:  # noqa: BLE001 - report any bus/connection failure
        return False, str(exc).splitlines()[0] or exc.__class__.__name__


def checks(output: Path) -> list[Check]:
    out: list[Check] = []
    out.append(Check("python", sys.version_info >= (3, 10), sys.version.split()[0]))
    out.append(
        Check(
            "paho-mqtt",
            _module("paho.mqtt"),
            "installed" if _module("paho.mqtt") else "missing",
            required=False,
        )
    )
    for name, extra in (("bleak", "BLE"), ("boto3", "AWS onboarding"), ("scapy", "certificate capture")):
        out.append(
            Check(
                name,
                _module(name),
                "installed" if _module(name) else f"missing ({extra} only)",
                required=False,
            )
        )
    out.append(
        Check("cryptography", _module("cryptography"), "installed" if _module("cryptography") else "missing")
    )
    for tool, required in (
        ("openssl", False),
        ("mosquitto", False),
        ("hostapd", False),
        ("dnsmasq", False),
        ("iw", False),
        ("iptables", False),
    ):
        path = shutil.which(tool)
        out.append(Check(tool, bool(path), path or "not installed", required=required))

    for port, proto, why in (
        (53, "udp", "AP DNS"),
        (67, "udp", "AP DHCP"),
        (8443, "tcp", "factory server"),
        (8883, "tcp", "local broker"),
        (443, "tcp", "fake API"),
        (8000, "tcp", "fake API fallback"),
    ):
        free, detail = _port_status(port, proto)
        if port == 53 and not free:
            detail += " (ok: AP can hand out the uplink router as DNS)"
        elif port == 67 and not free:
            detail += " -> stop the other DHCP server (AdGuard or a stale dnsmasq)"
        elif port == 443 and not free:
            detail += " (fake API will fall back to 8000)"
        elif port == 8000 and not free:
            detail += " (fake API needs 443 or 8000)"
        out.append(Check(f"{proto}/{port}", free, f"{detail} ({why})", required=(port == 67)))

    dbus = Path("/run/dbus/system_bus_socket")
    out.append(Check("bluetooth D-Bus", dbus.exists(), str(dbus), required=False))
    if dbus.exists():
        reachable, detail = _bluez_status()
        out.append(Check("bluez access", reachable, detail, required=False))

    if shutil.which("docker"):
        try:
            probe = subprocess.run(
                ["docker", "info", "--format", "{{json .SecurityOptions}}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            detail = (probe.stdout or probe.stderr).strip() or "unknown"
            rootless = "rootless" in detail
            out.append(
                Check(
                    "docker",
                    not rootless,
                    "rootless (BLE ok; AP/capture need rootful Docker)" if rootless else detail,
                    required=False,
                )
            )
        except (OSError, subprocess.SubprocessError) as exc:
            out.append(Check("docker", False, str(exc), required=False))

    wireless = sorted(p.name for p in Path("/sys/class/net").glob("*") if (p / "wireless").exists())
    out.append(Check("wireless ifaces", bool(wireless), ", ".join(wireless) or "none", required=False))

    identity = user_namespace_is_host()
    if identity is not None:
        out.append(
            Check(
                "user namespace",
                identity,
                "host" if identity else "namespaced (AP/capture need rootful Docker)",
                required=False,
            )
        )

    try:
        probe = output / ".write-test"
        probe.write_text("ok")
        probe.unlink()
        out.append(Check("output writable", True, str(output)))
    except OSError as exc:
        out.append(Check("output writable", False, str(exc)))

    return out


def print_checks(items: list[Check]) -> bool:
    from .util import ok, warn

    all_required = True
    for c in items:
        if c.ok:
            ok(f"{c.name:16s} {c.detail}")
        else:
            warn(f"{c.name:16s} {c.detail}")
            if c.required:
                all_required = False
    return all_required


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def in_docker() -> bool:
    return Path("/.dockerenv").exists() or os.environ.get("BLUEAIR_CLOUDCUTTER_DOCKER") == "1"
