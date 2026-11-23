"""Minimal protobuf wire codec.

The BlueAir BLE protocol uses protobuf3, but only a small, fixed set of
messages. Rather than depending on generated code, this module implements the
four wire types the protocol uses and leaves the message shapes to
`messages.py`.

Wire format reference: https://protobuf.dev/programming-guides/encoding/
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from ..errors import CutterError

WIRE_VARINT = 0
WIRE_FIXED64 = 1
WIRE_LEN = 2
WIRE_FIXED32 = 5

WIRE_NAMES = {0: "varint", 1: "fixed64", 2: "len", 5: "fixed32"}


class ProtobufError(ValueError, CutterError):
    """Malformed protobuf data, or a field of the wrong wire type."""


def encode_varint(value: int) -> bytes:
    if value < 0:
        # int32/int64 negatives are encoded as a 10-byte two's-complement varint.
        value &= (1 << 64) - 1
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    value = 0
    shift = 0
    for i in range(offset, len(data)):
        byte = data[i]
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, i + 1
        shift += 7
        if shift >= 70:
            raise ProtobufError("varint is too long")
    raise ProtobufError("truncated varint")


def _key(field: int, wire: int) -> bytes:
    if field <= 0:
        raise ProtobufError(f"invalid field number {field}")
    return encode_varint((field << 3) | wire)


def field_varint(field: int, value: int) -> bytes:
    return _key(field, WIRE_VARINT) + encode_varint(value)


def field_bool(field: int, value: bool) -> bytes:
    return field_varint(field, 1 if value else 0)


def field_bytes(field: int, value: bytes) -> bytes:
    return _key(field, WIRE_LEN) + encode_varint(len(value)) + value


def field_string(field: int, value: str) -> bytes:
    return field_bytes(field, value.encode("utf-8"))


def field_message(field: int, payload: bytes) -> bytes:
    """An empty message is still encoded (`key`, length 0) so a oneof selects it."""
    return field_bytes(field, payload)


@dataclass(frozen=True)
class Field:
    number: int
    wire: int
    value: int | bytes


def decode_fields(data: bytes) -> list[Field]:
    fields: list[Field] = []
    offset = 0
    while offset < len(data):
        key, offset = decode_varint(data, offset)
        number, wire = key >> 3, key & 0x7
        if number == 0:
            raise ProtobufError("field number 0 is invalid")
        if wire == WIRE_VARINT:
            value, offset = decode_varint(data, offset)
        elif wire == WIRE_LEN:
            length, offset = decode_varint(data, offset)
            if offset + length > len(data):
                raise ProtobufError("truncated length-delimited field")
            value = data[offset : offset + length]
            offset += length
        elif wire == WIRE_FIXED64:
            if offset + 8 > len(data):
                raise ProtobufError("truncated fixed64 field")
            value = data[offset : offset + 8]
            offset += 8
        elif wire == WIRE_FIXED32:
            if offset + 4 > len(data):
                raise ProtobufError("truncated fixed32 field")
            value = data[offset : offset + 4]
            offset += 4
        else:
            raise ProtobufError(f"unsupported wire type {wire}")
        fields.append(Field(number, wire, value))
    return fields


def find(fields: list[Field], number: int) -> Field | None:
    for field in fields:
        if field.number == number:
            return field
    return None


def find_all(fields: list[Field], number: int) -> list[Field]:
    return [field for field in fields if field.number == number]


def get_varint(fields: list[Field], number: int, default: int = 0) -> int:
    field = find(fields, number)
    if field is None:
        return default
    if field.wire != WIRE_VARINT:
        raise ProtobufError(f"field {number} is {WIRE_NAMES.get(field.wire)}, expected varint")
    return int(field.value)


def get_bool(fields: list[Field], number: int, default: bool = False) -> bool:
    return bool(get_varint(fields, number, 1 if default else 0))


def get_bytes(fields: list[Field], number: int, default: bytes = b"") -> bytes:
    field = find(fields, number)
    if field is None:
        return default
    if field.wire != WIRE_LEN:
        raise ProtobufError(f"field {number} is {WIRE_NAMES.get(field.wire)}, expected length-delimited")
    return bytes(field.value)


def get_string(fields: list[Field], number: int, default: str = "") -> str:
    return get_bytes(fields, number, default.encode()).decode("utf-8", "replace")


def get_message(fields: list[Field], number: int) -> list[Field] | None:
    payload = find(fields, number)
    if payload is None:
        return None
    if payload.wire != WIRE_LEN:
        raise ProtobufError(f"field {number} is not a message")
    return decode_fields(bytes(payload.value))


def to_int32(value: int) -> int:
    """Interpret an unsigned varint as a signed 32-bit integer."""
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value & 0x80000000 else value


def iter_repeated_messages(fields: list[Field], number: int) -> Iterator[list[Field]]:
    for field in find_all(fields, number):
        if field.wire != WIRE_LEN:
            raise ProtobufError(f"repeated field {number} is not a message")
        yield decode_fields(bytes(field.value))


def enum_value(enum_class, value: int, what: str):
    """Convert an integer to an IntEnum, with a useful error on unknown values."""
    try:
        return enum_class(value)
    except ValueError as exc:
        raise ProtobufError(f"unknown {what}: {value}") from exc
