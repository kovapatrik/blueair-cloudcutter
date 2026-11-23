from __future__ import annotations

import argparse
from pathlib import Path

from blueair_cloudcutter import aws


def test_config_roundtrip(tmp_path):
    cfg = aws.AwsConfig(
        region="eu-west-1",
        endpoint="example-ats.iot.eu-west-1.amazonaws.com",
        thing="blueair-device",
        policy="blueair-policy",
        device_cert="/tmp/device.pem",
        control_cert="/tmp/control.pem",
        control_key="/tmp/control.key",
        control_name="blueair-controller",
        account="123456789012",
        did="00000000-0000-0000-0000-000000000000",
    )
    cfg.save(aws.default_path(tmp_path))
    loaded = aws.AwsConfig.load(aws.default_path(tmp_path))
    assert loaded == cfg
    assert "example-ats" in aws.format_config(loaded)


def test_load_default_missing(tmp_path):
    assert aws.load_default(tmp_path) is None


def test_apply_defaults(tmp_path):
    cfg = aws.AwsConfig(
        region="eu-west-1",
        endpoint="endpoint",
        thing="thing",
        policy="policy",
        device_cert="device.pem",
        control_cert="control.pem",
        control_key="control.key",
        control_name="controller",
        did="did-1",
    )
    cfg.save(aws.default_path(tmp_path))
    args = argparse.Namespace(broker=None, cert=None, key=None, did=None)
    assert aws.apply_defaults(tmp_path, args) == cfg
    assert args.broker == "endpoint"
    assert args.cert == Path("control.pem")
    assert args.key == Path("control.key")
    assert args.did == "did-1"


def test_apply_defaults_does_not_override(tmp_path):
    cfg = aws.AwsConfig(
        region="eu-west-1",
        endpoint="endpoint",
        thing="thing",
        policy="policy",
        device_cert="device.pem",
        control_cert="control.pem",
        control_key="control.key",
        control_name="controller",
    )
    cfg.save(aws.default_path(tmp_path))
    args = argparse.Namespace(broker="explicit", cert=None, key=None, did="explicit-did")
    aws.apply_defaults(tmp_path, args)
    assert args.broker == "explicit"
    assert args.did == "explicit-did"
