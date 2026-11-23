"""Typed encoders/decoders for the BlueAir BLE protobuf messages.

Field numbers are taken from the `.proto` files from the Android app.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from ..protos import custom_commands_pb2 as custom_pb
from . import protobuf as pb
from .protobuf import ProtobufError


class EspStatus(IntEnum):
    Success = 0
    InvalidSecScheme = 1
    InvalidProto = 2
    TooManySessions = 3
    InvalidArgument = 4
    InternalError = 5
    CryptoError = 6
    InvalidSession = 7


class CustomStatus(IntEnum):
    Success = 0
    Fail = 1


class Sec1MsgType(IntEnum):
    SessionCommand0 = 0
    SessionResponse0 = 1
    SessionCommand1 = 2
    SessionResponse1 = 3


class WifiStationState(IntEnum):
    Connected = 0
    Connecting = 1
    Disconnected = 2
    ConnectionFailed = 3


class WifiConnectFailedReason(IntEnum):
    AuthError = 0
    NetworkNotFound = 1


class WifiAuthMode(IntEnum):
    Open = 0
    WEP = 1
    WPA_PSK = 2
    WPA2_PSK = 3
    WPA_WPA2_PSK = 4
    WPA2_ENTERPRISE = 5
    WPA3_PSK = 6
    WPA2_WPA3_PSK = 7
    WAPI_PSK = 8
    OWE = 9
    WPA3_ENT_192 = 10
    UNKNOWN = 255


def _wifi_auth_mode(value: int) -> WifiAuthMode:
    """Auth mode is informational; a newer AP mode must not abort a scan."""
    try:
        return WifiAuthMode(value)
    except ValueError:
        return WifiAuthMode.UNKNOWN


class WifiConfigMsgType(IntEnum):
    CmdGetStatus = 0
    RespGetStatus = 1
    CmdSetConfig = 2
    RespSetConfig = 3
    CmdApplyConfig = 4
    RespApplyConfig = 5


class WifiScanMsgType(IntEnum):
    CmdScanStart = 0
    RespScanStart = 1
    CmdScanStatus = 2
    RespScanStatus = 3
    CmdScanResult = 4
    RespScanResult = 5


# CommandWrapper oneof field numbers
WRAPPER_START_CMD = 1
WRAPPER_START_RESP = 2
WRAPPER_CONFIG_CMD = 3
WRAPPER_CONFIG_RESP = 4
WRAPPER_EVENT_CMD = 5
WRAPPER_EVENT_RESP = 6
WRAPPER_ADDRESS_CMD = 7
WRAPPER_ADDRESS_RESP = 8
WRAPPER_STOP_CMD = 9
WRAPPER_STOP_RESP = 10
WRAPPER_FACTORY_CMD = 11
WRAPPER_FACTORY_RESP = 12
WRAPPER_FILTER_READ_CMD = 13
WRAPPER_FILTER_READ_RESP = 14
WRAPPER_FILTER_SET_CMD = 15
WRAPPER_FILTER_SET_RESP = 16

# The six ConfigCmd oneof fields, in the order the device expects them.
CONFIG_FIELDS = {
    "api_url": 1,
    "auth_url": 2,
    "broker_url": 3,
    "region": 4,
    "random_text": 5,
    "secure_random": 6,
}


# --------------------------------------------------------------------------
# Session (Security 1)
# --------------------------------------------------------------------------


def encode_session_command0(client_pubkey: bytes) -> bytes:
    if len(client_pubkey) != 32:
        raise ValueError("client public key must be 32 bytes")
    sec1 = pb.field_varint(1, Sec1MsgType.SessionCommand0) + pb.field_message(
        20, pb.field_bytes(1, client_pubkey)
    )
    return pb.field_varint(2, 1) + pb.field_message(11, sec1)  # SecScheme1


def encode_session_command1(client_verify_data: bytes) -> bytes:
    sec1 = pb.field_varint(1, Sec1MsgType.SessionCommand1) + pb.field_message(
        22, pb.field_bytes(2, client_verify_data)
    )
    return pb.field_varint(2, 1) + pb.field_message(11, sec1)


@dataclass(frozen=True)
class SessionResponse0:
    status: EspStatus
    device_pubkey: bytes
    device_random: bytes


@dataclass(frozen=True)
class SessionResponse1:
    status: EspStatus
    device_verify_data: bytes


def _decode_session_payload(data: bytes, expected_msg: Sec1MsgType, response_field: int) -> list[pb.Field]:
    outer = pb.decode_fields(data)
    sec1 = pb.get_message(outer, 11)
    if sec1 is None:
        raise ProtobufError("session response has no sec1 payload")
    msg = pb.get_varint(sec1, 1, -1)
    if msg != expected_msg:
        raise ProtobufError(f"session response msg is {msg}, expected {int(expected_msg)}")
    response = pb.get_message(sec1, response_field)
    if response is None:
        raise ProtobufError(f"session response has no field {response_field}")
    return response


def decode_session_response0(data: bytes) -> SessionResponse0:
    sub = _decode_session_payload(data, Sec1MsgType.SessionResponse0, 21)
    return SessionResponse0(
        status=pb.enum_value(EspStatus, pb.get_varint(sub, 1), "status"),
        device_pubkey=pb.get_bytes(sub, 2),
        device_random=pb.get_bytes(sub, 3),
    )


def decode_session_response1(data: bytes) -> SessionResponse1:
    sub = _decode_session_payload(data, Sec1MsgType.SessionResponse1, 23)
    return SessionResponse1(
        status=pb.enum_value(EspStatus, pb.get_varint(sub, 1), "status"),
        device_verify_data=pb.get_bytes(sub, 3),
    )


def encode_session_response0(status: int, device_pubkey: bytes, device_random: bytes) -> bytes:
    payload = pb.field_varint(1, status) + pb.field_bytes(2, device_pubkey) + pb.field_bytes(3, device_random)
    sec1 = pb.field_varint(1, Sec1MsgType.SessionResponse0) + pb.field_message(21, payload)
    return pb.field_varint(2, 1) + pb.field_message(11, sec1)


def encode_session_response1(status: int, device_verify_data: bytes) -> bytes:
    payload = pb.field_varint(1, status) + pb.field_bytes(3, device_verify_data)
    sec1 = pb.field_varint(1, Sec1MsgType.SessionResponse1) + pb.field_message(23, payload)
    return pb.field_varint(2, 1) + pb.field_message(11, sec1)


# --------------------------------------------------------------------------
# Custom commands
# --------------------------------------------------------------------------


def encode_start_cmd() -> bytes:
    return custom_pb.CommandWrapper(start_cmd=custom_pb.StartCmd()).SerializeToString()


def encode_stop_cmd() -> bytes:
    return custom_pb.CommandWrapper(stop_cmd=custom_pb.StopCmd()).SerializeToString()


def encode_event_cmd(event_get: bool = True) -> bytes:
    cmd = custom_pb.EventGet if event_get else custom_pb.EventClearAll
    return custom_pb.CommandWrapper(event_cmd=custom_pb.EventCmd(cmd=cmd)).SerializeToString()


def encode_config_cmd(field: str, value: str) -> bytes:
    if field not in CONFIG_FIELDS:
        raise ValueError(f"unknown config field {field!r}")
    wrapper = custom_pb.CommandWrapper()
    setattr(wrapper.config_cmd, field, value)
    return wrapper.SerializeToString()


def encode_factory_cmd(url: str, ssid: str, pwd: str, token: str) -> bytes:
    # Generated from custom_commands.proto: url=1, ssid=2, pwd=3, token=4.
    wrapper = custom_pb.CommandWrapper()
    wrapper.factory_cmd.url = url
    wrapper.factory_cmd.ssid = ssid
    wrapper.factory_cmd.pwd = pwd
    wrapper.factory_cmd.token = token
    return wrapper.SerializeToString()


def encode_address_cmd() -> bytes:
    return custom_pb.CommandWrapper(address_cmd=custom_pb.AddressCmd()).SerializeToString()


def encode_filter_read_cmd(filter_type: str) -> bytes:
    return custom_pb.CommandWrapper(
        filter_read_cmd=custom_pb.FilterReadCmd(type=filter_type)
    ).SerializeToString()


def encode_filter_set_cmd(value: str) -> bytes:
    return custom_pb.CommandWrapper(filter_set_cmd=custom_pb.FilterSetCmd(filter=value)).SerializeToString()


def decode_command_wrapper(data: bytes) -> tuple[int, list[pb.Field]]:
    fields = pb.decode_fields(data)
    for number in (
        WRAPPER_START_RESP,
        WRAPPER_CONFIG_RESP,
        WRAPPER_EVENT_RESP,
        WRAPPER_ADDRESS_RESP,
        WRAPPER_STOP_RESP,
        WRAPPER_FACTORY_RESP,
        WRAPPER_FILTER_READ_RESP,
        WRAPPER_FILTER_SET_RESP,
    ):
        sub = pb.get_message(fields, number)
        if sub is not None:
            return number, sub
    present = sorted({f.number for f in fields})
    raise ProtobufError(f"unrecognised CommandWrapper response, fields={present}")


def decode_status_response(data: bytes, expected_wrapper_field: int) -> CustomStatus | EspStatus:
    number, sub = decode_command_wrapper(data)
    if number != expected_wrapper_field:
        raise ProtobufError(f"expected wrapper field {expected_wrapper_field}, got {number}")
    return pb.enum_value(CustomStatus, pb.get_varint(sub, 1), "status")


@dataclass(frozen=True)
class EventResponse:
    json: str
    number_of_events: int


def decode_event_response(data: bytes) -> EventResponse:
    number, sub = decode_command_wrapper(data)
    if number != WRAPPER_EVENT_RESP:
        raise ProtobufError(f"expected event response, got wrapper field {number}")
    return EventResponse(
        json=pb.get_string(sub, 1),
        number_of_events=pb.to_int32(pb.get_varint(sub, 2)),
    )


def decode_address_response(data: bytes) -> str:
    number, sub = decode_command_wrapper(data)
    if number != WRAPPER_ADDRESS_RESP:
        raise ProtobufError(f"expected address response, got wrapper field {number}")
    return pb.get_string(sub, 1)


def decode_filter_read_response(data: bytes) -> int:
    number, sub = decode_command_wrapper(data)
    if number != WRAPPER_FILTER_READ_RESP:
        raise ProtobufError(f"expected filter read response, got wrapper field {number}")
    return pb.get_varint(sub, 1)


# --------------------------------------------------------------------------
# WiFi config
# --------------------------------------------------------------------------


def encode_wifi_set_config(ssid: str, password: str, bssid: bytes = b"", channel: int = 0) -> bytes:
    payload = pb.field_bytes(1, ssid.encode()) + pb.field_bytes(2, password.encode())
    if bssid:
        payload += pb.field_bytes(3, bssid)
    if channel:
        payload += pb.field_varint(4, channel)
    return pb.field_varint(1, WifiConfigMsgType.CmdSetConfig) + pb.field_message(12, payload)


def encode_wifi_apply_config() -> bytes:
    return pb.field_varint(1, WifiConfigMsgType.CmdApplyConfig) + pb.field_message(14, b"")


def encode_wifi_get_status() -> bytes:
    return pb.field_varint(1, WifiConfigMsgType.CmdGetStatus) + pb.field_message(10, b"")


def _wifi_payload(data: bytes) -> tuple[int, list[pb.Field]]:
    fields = pb.decode_fields(data)
    msg = pb.get_varint(fields, 1, -1)
    for number in (10, 11, 12, 13, 14, 15):
        sub = pb.get_message(fields, number)
        if sub is not None:
            return number, sub
    raise ProtobufError(f"WiFiConfigPayload has no known payload (msg={msg})")


@dataclass(frozen=True)
class WifiStatusResponse:
    status: EspStatus
    sta_state: WifiStationState
    fail_reason: WifiConnectFailedReason | None
    connected: WifiConnectedState | None


@dataclass(frozen=True)
class WifiConnectedState:
    ip4_addr: str
    auth_mode: WifiAuthMode
    ssid: bytes
    bssid: bytes
    channel: int


def decode_wifi_set_config_response(data: bytes) -> EspStatus:
    number, sub = _wifi_payload(data)
    if number != 13:
        raise ProtobufError(f"expected RespSetConfig, got field {number}")
    return pb.enum_value(EspStatus, pb.get_varint(sub, 1), "status")


def decode_wifi_apply_config_response(data: bytes) -> EspStatus:
    number, sub = _wifi_payload(data)
    if number != 15:
        raise ProtobufError(f"expected RespApplyConfig, got field {number}")
    return pb.enum_value(EspStatus, pb.get_varint(sub, 1), "status")


def decode_wifi_status_response(data: bytes) -> WifiStatusResponse:
    number, sub = _wifi_payload(data)
    if number != 11:
        raise ProtobufError(f"expected RespGetStatus, got field {number}")
    fail_reason = pb.get_varint(sub, 10, -1)
    connected_fields = pb.get_message(sub, 11)
    connected = None
    if connected_fields is not None:
        connected = WifiConnectedState(
            ip4_addr=pb.get_string(connected_fields, 1),
            auth_mode=_wifi_auth_mode(pb.get_varint(connected_fields, 2)),
            ssid=pb.get_bytes(connected_fields, 3),
            bssid=pb.get_bytes(connected_fields, 4),
            channel=pb.to_int32(pb.get_varint(connected_fields, 5)),
        )
    return WifiStatusResponse(
        status=pb.enum_value(EspStatus, pb.get_varint(sub, 1), "status"),
        sta_state=pb.enum_value(WifiStationState, pb.get_varint(sub, 2), "station state"),
        fail_reason=pb.enum_value(WifiConnectFailedReason, fail_reason, "fail reason")
        if fail_reason >= 0
        else None,
        connected=connected,
    )


# --------------------------------------------------------------------------
# WiFi scan
# --------------------------------------------------------------------------


def encode_scan_start(passive: bool = False, group_channels: int = 0, period_ms: int = 120) -> bytes:
    payload = (
        pb.field_bool(1, True)  # blocking
        + pb.field_bool(2, passive)
        + pb.field_varint(3, group_channels)
        + pb.field_varint(4, period_ms)
    )
    return pb.field_varint(1, WifiScanMsgType.CmdScanStart) + pb.field_message(10, payload)


def encode_scan_status() -> bytes:
    return pb.field_varint(1, WifiScanMsgType.CmdScanStatus) + pb.field_message(12, b"")


def encode_scan_result(start_index: int, count: int) -> bytes:
    payload = pb.field_varint(1, start_index) + pb.field_varint(2, count)
    return pb.field_varint(1, WifiScanMsgType.CmdScanResult) + pb.field_message(14, payload)


@dataclass(frozen=True)
class ScanStatus:
    status: EspStatus
    scan_finished: bool
    result_count: int


def decode_scan_status(data: bytes) -> ScanStatus:
    fields = pb.decode_fields(data)
    status = pb.enum_value(EspStatus, pb.get_varint(fields, 2), "status")
    sub = pb.get_message(fields, 13)
    if sub is None:
        raise ProtobufError("scan status response has no RespScanStatus")
    return ScanStatus(
        status=status,
        scan_finished=pb.get_bool(sub, 1),
        result_count=pb.get_varint(sub, 2),
    )


@dataclass(frozen=True)
class WifiNetwork:
    ssid: str
    bssid: str
    channel: int
    rssi: int
    security: WifiAuthMode


def decode_scan_results(data: bytes) -> list[WifiNetwork]:
    fields = pb.decode_fields(data)
    status = pb.enum_value(EspStatus, pb.get_varint(fields, 2), "status")
    if status != EspStatus.Success:
        raise ProtobufError(f"scan result status is {status.name}")
    sub = pb.get_message(fields, 15)
    if sub is None:
        raise ProtobufError("scan result response has no RespScanResult")
    out: list[WifiNetwork] = []
    for entry in pb.iter_repeated_messages(sub, 1):
        out.append(
            WifiNetwork(
                ssid=pb.get_bytes(entry, 1).decode("utf-8", "replace"),
                channel=pb.get_varint(entry, 2),
                rssi=pb.to_int32(pb.get_varint(entry, 3)),
                bssid=pb.get_bytes(entry, 4).hex(),
                security=_wifi_auth_mode(pb.get_varint(entry, 5)),
            )
        )
    return out
