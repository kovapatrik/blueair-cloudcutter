from __future__ import annotations

import pytest

from blueair_cloudcutter.ble import protobuf as pb


def test_varint_roundtrip():
    for value in (0, 1, 127, 128, 300, 16384, 2**32 - 1, 2**64 - 1):
        encoded = pb.encode_varint(value)
        decoded, offset = pb.decode_varint(encoded)
        assert decoded == value
        assert offset == len(encoded)


def test_negative_int32_roundtrip():
    encoded = pb.encode_varint(-50)
    decoded, _ = pb.decode_varint(encoded)
    assert pb.to_int32(decoded) == -50


def test_field_encoding():
    assert pb.field_varint(1, 0) == b"\x08\x00"
    assert pb.field_bytes(1, b"\x01\x02") == b"\x0a\x02\x01\x02"
    assert pb.field_string(2, "x") == b"\x12\x01x"
    assert pb.field_message(11, b"") == b"\x5a\x00"
    assert pb.field_bool(1, True) == b"\x08\x01"


def test_decode_fields_and_helpers():
    data = pb.field_varint(1, 7) + pb.field_string(2, "hello") + pb.field_varint(3, 300)
    fields = pb.decode_fields(data)
    assert pb.get_varint(fields, 1) == 7
    assert pb.get_string(fields, 2) == "hello"
    assert pb.get_varint(fields, 3) == 300
    assert pb.find(fields, 99) is None


def test_truncated_input_is_rejected():
    with pytest.raises(pb.ProtobufError):
        pb.decode_fields(b"\x0a\x05ab")
    with pytest.raises(pb.ProtobufError):
        pb.decode_varint(b"\x80")
