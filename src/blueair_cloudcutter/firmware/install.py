"""Install a custom app image over the factory HTTPS endpoint.

The chain itself is in `chain.py`; this module handles the image checks, the
header override and the run state. Both the exploit and `helpers flash` call it.
"""

from __future__ import annotations

from pathlib import Path

from ..constants import G4_HEADER16, PAD_DEFAULT
from ..context import Context
from ..errors import CutterError, SafetyError
from ..httpclient import DeviceHTTP
from ..util import info, ok, step, warn
from . import chain
from .multipart import image_name_for, inspect_preserve


def load_image(path: str | Path, what: str) -> bytes:
    p = Path(path)
    if not p.exists():
        raise CutterError(f"{what}: no such file: {p}")
    data = p.read_bytes()
    if not data.startswith(b"\xe9"):
        raise CutterError(f"{what}: {p} does not start with 0xE9 (not an ESP32 app image)")
    return data


def parse_header16(value: str | None) -> bytes:
    if not value:
        return G4_HEADER16
    raw = bytes.fromhex(value.replace("0x", "").replace(" ", "").replace(":", ""))
    if len(raw) != 16:
        raise SafetyError(f"--header16 must be 16 bytes (32 hex chars), got {len(raw)}")
    if raw[0] != 0xE9:
        raise SafetyError("--header16 must start with 0xE9")
    return raw


def _image_name(ctx: Context, value: str | None) -> str:
    return value or image_name_for(ctx.state.hw)


def dry_run(
    ctx: Context,
    *,
    custom: bytes,
    version: str,
    image_name: str | None = None,
    pad: int = PAD_DEFAULT,
) -> int:
    name = _image_name(ctx, image_name)
    info(str(inspect_preserve(version, pad, image_name=name)))
    info(f"manifest image name: {name}")
    info(f"custom image: {len(custom)} B, starts {custom[:4].hex()}")
    return 0


def install(
    ctx: Context,
    *,
    custom: bytes,
    official: bytes | None = None,
    no_dump: bool = True,
    version: str = "1.0.9",
    image_name: str | None = None,
    header16: str | None = None,
    pad: int = PAD_DEFAULT,
    settle: float = 2.0,
    reboot: bool = True,
    send_pad: bool = False,
    custom_path: str | None = None,
) -> int:
    if not ctx.ip:
        raise CutterError("device IP unknown; the factory endpoint needs the device's LAN IP")
    if not ctx.did:
        ctx.discover()
    name = _image_name(ctx, image_name)

    step(1, 2, "Arm and swap")
    if not no_dump and not official:
        raise SafetyError("--official <image> is required unless you pass --no-dump")
    if no_dump:
        info("using the erase-size overflow; the passive slot's existing signed image is preserved")
        info(str(inspect_preserve(version, pad, image_name=name)))
    else:
        info(f"using the supplied signed image ({len(official or b'')} B)")
        info(f"manifest image name: {name}")

    result = chain.run(
        ctx.ip,
        ctx.did,
        ctx.token(),
        custom,
        version=version,
        official=official,
        no_dump=no_dump,
        header16=parse_header16(header16) if no_dump else None,
        pad=pad,
        settle=settle,
        bind=ctx.bind,
        port=ctx.port,
        reboot=reboot,
        send_pad=send_pad,
        image_name=name,
    )
    if custom_path:
        ctx.state.custom_firmware = str(Path(custom_path))
    ctx.state.mark("flash", armed=result.armed, swapped=result.swapped, rebooted=result.rebooted)
    ctx.save()

    step(2, 2, "Done")
    ok("custom firmware written")
    if reboot:
        info("watch UART for your firmware's banner")
        warn("it boots in PENDING_VERIFY: the payload must call esp_ota_mark_app_valid_cancel_rollback()")
    return 0


def restore_official(
    ctx: Context,
    *,
    official: bytes,
    version: str = "1.0.9",
    image_name: str | None = None,
    reboot: bool = True,
) -> int:
    """Write a vendor-signed image with a normal OTA upload.

    No STM32 entry and no padding: the MCU bail exists only to keep the device up
    for the unsigned swap. Here the handler accepts the ESP32 image, moves the
    boot pointer and reboots by itself. The slot that is already running is
    official too, so both OTA slots end up holding a signed image.
    """
    if not ctx.ip:
        raise CutterError("device IP unknown; the factory endpoint needs the device's LAN IP")
    if not ctx.did:
        ctx.discover()
    name = _image_name(ctx, image_name)

    step(1, 2, "Write the official image to the passive slot")
    http = DeviceHTTP(ctx.ip, ctx.port, timeout=600, bind=ctx.bind)
    chain.upload_official(
        http,
        ctx.did,
        ctx.token(),
        official,
        version=version,
        image_name=name,
    )
    if reboot:
        # The handler usually reboots on success. If it is still up, ask it to;
        # a reset that races the reboot is harmless and gets no response.
        chain.reset(http, ctx.did, ctx.token())

    ctx.state.mark("official_restore", image=name)
    ctx.save()
    step(2, 2, "Done")
    ok("official image written; both OTA slots now hold a signed image")
    return 0
