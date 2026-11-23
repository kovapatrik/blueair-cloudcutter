"""Multipart bodies for the factory-mode `provision/image` endpoint.

The handler does not consume a conventional multipart stream. It reads the
first chunk into a fixed 3096-byte buffer, scans that buffer for the first
`0xE9` (the ESP32 image magic), and writes `3096 - position` bytes from there.

The request layout follows from that detail:

* a normal upload places the firmware after the headers, so the write starts at
  the magic byte and covers the whole image;
* the `--no-dump` upload deliberately pads the meta part so the magic byte sits
  at offset 3080, which makes the forced write exactly 16 bytes.

The manifest's `image` field is also checked against the device family
(`strstr(image, "nb")` for `di.hw` `nb_*`), so it is not a free-form filename;
see `image_name_for()` below.

The 16 bytes are the image header, which is a build constant. Writing it back
over itself is a no-op because flash encryption is deterministic. Other builds
(wrong flash size, different app layout) need a different header; that is what
`--header16` is for.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from ..constants import (
    BOUNDARY,
    E9_TARGET,
    G4_HEADER16,
    MCU_BUFF,
    OTA_BUF,
    OVERFLOW_SIZE,
)

_DELIM = b"--" + BOUNDARY
# The factory handler gates the ESP32 image on the device family, not on a file
# on disk: for the nb_* boards it requires strstr(manifest_image, "nb") and
# di.hw in {nb_l_1.0, nb_m_1.0}. This string is only the manifest label and the
# multipart filename, but it must still carry the family prefix. Other device
# families can differ, so `image_name_for(hw)` derives it from `di.hw`.
DEFAULT_IMAGE_NAME = "ba_nb_wifi.bin"
_MCU_IMAGE_NAME = "ba_nb_mcu.bin"
_ESP32_TARGET = "ESP32-WROOM-32"
_STM32_TARGET = "STM32"
_STM32_SIZE = 1024  # only has to be non-zero


def image_name_for(hw: str | None) -> str:
    """Return a manifest image name that carries the `di.hw` family prefix.

    `hw` is the value read from the device (for example `nb_l_1.0`); the OTA
    gate is a strstr() on the manifest's `image` field, so `ba_nb_wifi.bin`
    passes the `nb` check. Blank or unknown values fall back to the G4 `nb`
    name.
    """
    family = (hw or "").split("_", 1)[0].strip().lower()
    if family.isalnum():
        return f"ba_{family}_wifi.bin"
    return DEFAULT_IMAGE_NAME


@dataclass(frozen=True)
class Upload:
    body: bytes
    declared_length: int
    description: str

    @property
    def unsent_padding(self) -> int:
        return max(0, self.declared_length - len(self.body))


def _part_header(name: str, filename: str) -> bytes:
    return (
        _DELIM
        + b"\r\n"
        + f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
        + b"Content-Type: application/octet-stream\r\n\r\n"
    )


def manifest(
    version: str,
    *,
    esp32_size: int,
    image_name: str = DEFAULT_IMAGE_NAME,
    include_stm32: bool = False,
    pad: int = 0,
) -> bytes:
    images = [
        {"target": _ESP32_TARGET, "image": image_name, "size": esp32_size},
    ]
    if include_stm32:
        images.append({"target": _STM32_TARGET, "image": _MCU_IMAGE_NAME, "size": _STM32_SIZE})
    obj = {"version": version, "images": images}
    if pad:
        obj["pad"] = "A" * pad
    return json.dumps(obj).encode()


def image_upload(
    firmware: bytes,
    version: str,
    *,
    include_stm32: bool = False,
    pad: int = 0,
    declared_extra: int = 0,
    image_name: str = DEFAULT_IMAGE_NAME,
) -> Upload:
    """A normal firmware upload.

    `declared_extra` is advertised in Content-Length but never sent. Combined
    with a non-zero STM32 size it makes the MCU stage bail without rebooting:
    the remaining-body comparison runs before any read.
    """
    meta = manifest(
        version,
        esp32_size=len(firmware),
        image_name=image_name,
        include_stm32=include_stm32,
        pad=pad,
    )
    body = _part_header("meta", "meta") + meta + b"\r\n" + _part_header("image", image_name) + firmware
    return Upload(
        body=body,
        declared_length=len(body) + declared_extra,
        description=(
            f"{len(firmware)} B image"
            + (f", STM32 entry, +{declared_extra} B declared-not-sent" if include_stm32 else "")
        ),
    )


def _preserve_prefix(version: str, pad: int, image_name: str) -> bytes:
    meta = manifest(
        version,
        esp32_size=OVERFLOW_SIZE,
        image_name=image_name,
        include_stm32=True,
        pad=pad,
    )
    return _part_header("meta", "meta") + meta + b"\r\n" + _part_header("image", image_name)


def preserve_upload(
    version: str,
    *,
    header16: bytes = G4_HEADER16,
    image_name: str = DEFAULT_IMAGE_NAME,
    declared_extra: int = MCU_BUFF + 8192,
) -> Upload:
    """The `--no-dump` phase-1 upload.

    * manifest ESP32 size is -2, so `esp_ota_begin` erases nothing;
    * the meta JSON is padded until the image's 0xE9 lands on offset 3080;
    * exactly 16 bytes follow, so the handler's forced write is one block that
      reproduces the bytes already in flash.
    """
    if len(header16) != 16:
        raise ValueError(f"header16 must be exactly 16 bytes, got {len(header16)}")
    if header16[0] != 0xE9:
        raise ValueError("header16 must start with 0xE9 (esp_ota_write rejects it otherwise)")

    pad = 1
    for _ in range(12):
        prefix = _preserve_prefix(version, pad, image_name)
        delta = E9_TARGET - len(prefix)
        if delta == 0:
            break
        pad += delta
        if pad < 1:
            raise ValueError("cannot pad the meta part down to the required offset")
    else:
        raise ValueError("could not converge on the 0xE9 offset")

    prefix = _preserve_prefix(version, pad, image_name)
    if len(prefix) != E9_TARGET:
        raise ValueError(f"prefix is {len(prefix)} B, need exactly {E9_TARGET}")
    if b"\xe9" in prefix:
        raise ValueError("0xE9 occurs before the image; the scan would stop early")

    body = prefix + header16
    return Upload(
        body=body,
        declared_length=len(body) + declared_extra,
        description=(
            f"header-only: size={OVERFLOW_SIZE}, 0xE9 at {E9_TARGET}, "
            f"16 B write, +{declared_extra} B declared-not-sent"
        ),
    )


def inspect_preserve(
    version: str,
    declared_extra: int = MCU_BUFF + 8192,
    *,
    image_name: str = DEFAULT_IMAGE_NAME,
) -> dict:
    """Dry-run helper: report the layout without building a request."""
    up = preserve_upload(version, declared_extra=declared_extra, image_name=image_name)
    return {
        "body_length": len(up.body),
        "declared_length": up.declared_length,
        "magic_offset": up.body.index(b"\xe9"),
        "write_length": OTA_BUF - up.body.index(b"\xe9"),
        "mcu_remaining": up.declared_length - len(up.body) - E9_TARGET,
        "mcu_threshold": MCU_BUFF,
    }
