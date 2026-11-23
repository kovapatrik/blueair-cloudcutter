"""Per-device onboarding records."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from blueair_cloudcutter import devices
from blueair_cloudcutter.errors import CutterError


def _cfg(tmp_path, cert_id: str, did: str = "", address: str = "") -> SimpleNamespace:
    return SimpleNamespace(
        region="eu-west-1",
        endpoint="example-ats.iot.eu-west-1.amazonaws.com",
        thing="blueair-device",
        policy="blueair-policy",
        device_cert=str(tmp_path / f"{cert_id}.pem"),
        control_cert=str(tmp_path / f"{cert_id}.cert.pem"),
        control_key=str(tmp_path / f"{cert_id}.key"),
        control_name="blueair-controller",
        account="123",
        did=did,
        device_cert_arn=f"arn:aws:iot:eu-west-1:123:cert/{cert_id}",
        address=address,
    )


def test_upsert_keeps_both_devices(tmp_path):
    first = devices.upsert(tmp_path, _cfg(tmp_path, "aaa", did="did-a"), address="AA:BB")
    second = devices.upsert(tmp_path, _cfg(tmp_path, "bbb", did="did-b"))

    records = devices.load(tmp_path)
    assert [record.cert_id for record in records] == [first.cert_id, second.cert_id]
    assert devices.select(records, "did-a").cert_id == "aaa"
    assert devices.select(records, "did-b").cert_id == "bbb"
    assert devices.select(records, "AA:bb").cert_id == "aaa"
    assert devices.select(records, "1").cert_id == "aaa"

    active = json.loads((tmp_path / "aws.json").read_text())
    assert active["did"] == "did-b"


def test_address_survives_did_update(tmp_path):
    devices.upsert(tmp_path, _cfg(tmp_path, "aaa"), address="AA:BB:CC")
    did_cfg = _cfg(tmp_path, "aaa", did="did-a")
    devices.upsert(tmp_path, did_cfg, did="did-a")

    record = devices.load(tmp_path)[0]
    assert record.did == "did-a"
    assert record.address == "AA:BB:CC"


def test_select_unknown_and_ambiguous(tmp_path):
    devices.upsert(tmp_path, _cfg(tmp_path, "aaa", did="did-a"))
    with pytest.raises(CutterError):
        devices.select(devices.load(tmp_path), "nope")

    devices.upsert(tmp_path, _cfg(tmp_path, "aab", did="did-b"))
    with pytest.raises(CutterError):
        devices.select(devices.load(tmp_path), "aa")


def test_legacy_aws_json_is_adopted(tmp_path):
    raw = {
        "region": "eu-west-1",
        "endpoint": "example",
        "thing": "blueair-device",
        "policy": "blueair-policy",
        "device_cert": str(tmp_path / "device.pem"),
        "control_cert": str(tmp_path / "control.cert.pem"),
        "control_key": str(tmp_path / "control.key"),
        "account": "123",
        "did": "did-legacy",
        "device_cert_arn": "arn:aws:iot:eu-west-1:123:cert/legacy",
    }
    (tmp_path / "aws.json").write_text(json.dumps(raw))

    records = devices.load(tmp_path)
    assert len(records) == 1
    assert records[0].did == "did-legacy"
    assert records[0].cert_id == "legacy"
