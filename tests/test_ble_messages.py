from __future__ import annotations

from blueair_cloudcutter.ble import messages as m
from blueair_cloudcutter.ble import protobuf as pb


def test_start_stop_event_commands():
    assert m.encode_start_cmd() == b"\x0a\x00"
    assert m.encode_stop_cmd() == b"\x4a\x00"
    assert m.encode_event_cmd() == b"\x2a\x00"


def test_config_cmd_uses_the_oneof_field():
    encoded = m.encode_config_cmd("broker_url", "x")
    assert encoded == b"\x1a\x03\x1a\x01x"
    fields = pb.decode_fields(encoded)
    sub = pb.get_message(fields, m.WRAPPER_CONFIG_CMD)
    assert pb.get_string(sub, 3) == "x"


def test_factory_cmd_fields():
    encoded = m.encode_factory_cmd("http://x", "BAFactory", "secret", "token")
    fields = pb.decode_fields(encoded)
    sub = pb.get_message(fields, m.WRAPPER_FACTORY_CMD)
    assert pb.get_string(sub, 1) == "http://x"
    assert pb.get_string(sub, 2) == "BAFactory"
    assert pb.get_string(sub, 3) == "secret"
    assert pb.get_string(sub, 4) == "token"

    from blueair_cloudcutter.protos import custom_commands_pb2

    generated = custom_commands_pb2.CommandWrapper(
        factory_cmd=custom_commands_pb2.FactoryCmd(
            url="http://x", ssid="BAFactory", pwd="secret", token="token"
        )
    ).SerializeToString()
    assert encoded == generated


def test_session_command0_shape():
    pubkey = bytes(range(32))
    encoded = m.encode_session_command0(pubkey)
    outer = pb.decode_fields(encoded)
    assert pb.get_varint(outer, 2) == 1  # SecScheme1
    sec1 = pb.get_message(outer, 11)
    assert pb.get_varint(sec1, 1) == 0  # Session_Command0
    cmd0 = pb.get_message(sec1, 20)
    assert pb.get_bytes(cmd0, 1) == pubkey


def test_session_response0_roundtrip():
    pubkey = bytes(range(32))
    nonce = bytes(range(16))
    encoded = m.encode_session_response0(0, pubkey, nonce)
    decoded = m.decode_session_response0(encoded)
    assert decoded.status == m.EspStatus.Success
    assert decoded.device_pubkey == pubkey
    assert decoded.device_random == nonce


def test_session_response1_roundtrip():
    verify = b"v" * 32
    encoded = m.encode_session_response1(0, verify)
    decoded = m.decode_session_response1(encoded)
    assert decoded.status == m.EspStatus.Success
    assert decoded.device_verify_data == verify


def test_wifi_set_config_shape():
    encoded = m.encode_wifi_set_config("wifi", "password")
    fields = pb.decode_fields(encoded)
    assert pb.get_varint(fields, 1) == m.WifiConfigMsgType.CmdSetConfig
    sub = pb.get_message(fields, 12)
    assert pb.get_bytes(sub, 1) == b"wifi"
    assert pb.get_bytes(sub, 2) == b"password"


def test_scan_status_and_results_decode():
    status = pb.field_varint(1, 3) + pb.field_message(13, pb.field_bool(1, True) + pb.field_varint(2, 2))
    decoded = m.decode_scan_status(status)
    assert decoded.scan_finished
    assert decoded.result_count == 2

    entry1 = (
        pb.field_bytes(1, b"wifi")
        + pb.field_varint(2, 6)
        + pb.field_varint(3, -50)
        + pb.field_bytes(4, bytes.fromhex("aabbccddeeff"))
        + pb.field_varint(5, 3)
    )
    entry2 = (
        pb.field_bytes(1, b"other")
        + pb.field_varint(2, 11)
        + pb.field_varint(3, -70)
        + pb.field_bytes(4, bytes.fromhex("001122334455"))
        + pb.field_varint(5, 0)
    )
    entry3 = (
        pb.field_bytes(1, b"wapi")
        + pb.field_varint(2, 1)
        + pb.field_varint(3, -80)
        + pb.field_bytes(4, bytes.fromhex("001122334466"))
        + pb.field_varint(5, 8)
    )
    entry4 = (
        pb.field_bytes(1, b"future")
        + pb.field_varint(2, 1)
        + pb.field_varint(3, -90)
        + pb.field_bytes(4, bytes.fromhex("001122334477"))
        + pb.field_varint(5, 99)
    )
    results = (
        pb.field_varint(1, 5)
        + pb.field_varint(2, 0)
        + pb.field_message(
            15,
            pb.field_bytes(1, entry1)
            + pb.field_bytes(1, entry2)
            + pb.field_bytes(1, entry3)
            + pb.field_bytes(1, entry4),
        )
    )
    networks = m.decode_scan_results(results)
    assert networks[0].ssid == "wifi"
    assert networks[0].rssi == -50
    assert networks[0].bssid == "aabbccddeeff"
    assert networks[1].ssid == "other"
    assert networks[1].security == m.WifiAuthMode.Open
    assert networks[2].security == m.WifiAuthMode.WAPI_PSK
    assert networks[3].security == m.WifiAuthMode.UNKNOWN
