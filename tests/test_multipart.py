from __future__ import annotations

import json

import pytest

from blueair_cloudcutter.constants import E9_TARGET, G4_HEADER16, MCU_BUFF, OTA_BUF, OVERFLOW_SIZE
from blueair_cloudcutter.firmware.multipart import (
    DEFAULT_IMAGE_NAME,
    image_name_for,
    image_upload,
    inspect_preserve,
    preserve_upload,
)


def test_preserve_layout_is_exact():
    up = preserve_upload("1.0.9")
    assert len(up.body) == OTA_BUF
    assert up.body.index(b"\xe9") == E9_TARGET
    assert OTA_BUF - E9_TARGET == 16
    assert up.body[E9_TARGET:] == G4_HEADER16
    assert up.body.count(b"\xe9") == 1


def test_preserve_declares_but_does_not_send_padding():
    up = preserve_upload("1.0.9", declared_extra=MCU_BUFF + 8192)
    assert up.unsent_padding == MCU_BUFF + 8192
    assert up.declared_length > len(up.body)
    # The MCU-stage check is `remaining <= MCU_BUFF`; remaining is the declared
    # excess plus everything after the 16-byte header.
    remaining = up.declared_length - len(up.body) + (len(up.body) - E9_TARGET)
    assert remaining > MCU_BUFF


def test_preserve_manifest_uses_the_overflow_size():
    up = preserve_upload("1.0.9")
    assert b'"size": -2' in up.body or b'"size":-2' in up.body
    assert str(OVERFLOW_SIZE).encode() in up.body


def test_preserve_rejects_a_bad_header():
    with pytest.raises(ValueError):
        preserve_upload("1.0.9", header16=b"\x00" * 16)
    with pytest.raises(ValueError):
        preserve_upload("1.0.9", header16=b"\xe9" * 15)


def test_inspect_matches_the_body():
    report = inspect_preserve("1.0.9")
    assert report["body_length"] == 3096
    assert report["magic_offset"] == 3080
    assert report["write_length"] == 16
    assert report["mcu_remaining"] > report["mcu_threshold"]


def test_image_name_follows_the_hw_family():
    assert DEFAULT_IMAGE_NAME == "ba_nb_wifi.bin"
    assert image_name_for("nb_l_1.0") == "ba_nb_wifi.bin"
    assert image_name_for("nb_m_1.0") == "ba_nb_wifi.bin"
    assert image_name_for("gp_m_2.0") == "ba_gp_wifi.bin"
    assert image_name_for(None) == DEFAULT_IMAGE_NAME
    assert image_name_for("") == DEFAULT_IMAGE_NAME


def test_preserve_keeps_the_magic_offset_for_other_families():
    up = preserve_upload("1.0.9", image_name="ba_gp_wifi.bin")
    assert up.body.index(b"\xe9") == E9_TARGET
    assert b'"image": "ba_gp_wifi.bin"' in up.body


def test_image_upload_has_meta_then_firmware():
    fw = b"\xe9" + b"\x00" * 99
    up = image_upload(fw, "1.0.9")
    assert up.body.endswith(fw)
    assert b'"target": "ESP32-WROOM-32"' in up.body
    assert b'"size": 100' in up.body
    assert b"STM32" not in up.body


def test_image_upload_with_stm32_and_padding():
    fw = b"\xe9" + b"\x00" * 31
    up = image_upload(fw, "1.0.9", include_stm32=True, declared_extra=MCU_BUFF + 1)
    assert b'"target": "STM32"' in up.body
    assert b'"size": 1024' in up.body
    assert up.unsent_padding == MCU_BUFF + 1


def test_boundary_is_parseable_json_after_the_meta_part():
    up = preserve_upload("1.0.9")
    start = up.body.index(b"{")
    end = up.body.index(b"\r\n", start)
    meta = json.loads(up.body[start:end])
    assert meta["images"][0]["size"] == OVERFLOW_SIZE
    assert meta["images"][1]["target"] == "STM32"
