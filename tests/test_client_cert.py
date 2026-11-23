"""Supplied client certificates can be PEM or DER."""

from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from blueair_cloudcutter import certs, cli, devices, exploit
from blueair_cloudcutter.context import Context
from blueair_cloudcutter.errors import CutterError


def _certificate() -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device")])
    now = dt.datetime.now(dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def test_der_is_normalized_to_pem(tmp_path):
    cert = _certificate()
    der = tmp_path / "device.der"
    der.write_bytes(cert.public_bytes(serialization.Encoding.DER))

    out = certs.ensure_pem_certificate(der, tmp_path / "device.pem")

    assert out == tmp_path / "device.pem"
    assert out.read_bytes() == cert.public_bytes(serialization.Encoding.PEM)
    assert certs.certificate_pem_bytes(out) == cert.public_bytes(serialization.Encoding.PEM)


def test_pem_is_kept(tmp_path):
    cert = _certificate()
    pem = tmp_path / "device.pem"
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    out = certs.ensure_pem_certificate(pem, pem)

    assert out == pem
    assert out.read_bytes() == cert.public_bytes(serialization.Encoding.PEM)


def test_invalid_certificate_is_rejected(tmp_path):
    path = tmp_path / "device.pem"
    path.write_text("not a certificate")

    with pytest.raises(CutterError):
        certs.load_certificate(path)


def test_exploit_supplied_certificate_skips_ap_and_capture(monkeypatch, tmp_path):
    cert = _certificate()
    source = tmp_path / "captured.der"
    source.write_bytes(cert.public_bytes(serialization.Encoding.DER))

    calls = {}

    def fake_onboard(**kwargs):
        calls["onboard"] = kwargs
        return SimpleNamespace(
            region="eu-west-1",
            endpoint="example-ats.iot.eu-west-1.amazonaws.com",
            device_cert=str(kwargs["device_cert"]),
            device_cert_arn="",
            did="",
        )

    monkeypatch.setattr(exploit, "_select_record", lambda ctx, args: None)
    monkeypatch.setattr(exploit.aws, "load_default", lambda output: None)
    monkeypatch.setattr(
        exploit.aws,
        "check",
        lambda region, profile: {
            "account": "123456789012",
            "region": "eu-west-1",
            "endpoint": "example-ats.iot.eu-west-1.amazonaws.com",
        },
    )
    monkeypatch.setattr(exploit.aws, "onboard", fake_onboard)
    monkeypatch.setattr(exploit, "_discover", lambda ctx, cfg, timeout: "did-from-mqtt")

    def fail(*args, **kwargs):
        raise AssertionError("the AP and capture must not run for a supplied certificate")

    monkeypatch.setattr(exploit, "_start_ap", fail)
    monkeypatch.setattr(exploit, "_CaptureJob", fail)
    monkeypatch.setattr(exploit, "_move_to_wifi", fail)

    parser = cli.build_parser()
    args = parser.parse_args(
        [
            "--output",
            str(tmp_path),
            "exploit",
            "--device-cert",
            str(source),
            "--skip-wifi-setup",
            "--onboard-only",
        ]
    )
    ctx = Context(output=tmp_path)

    assert exploit.run(ctx, args) == 0
    assert calls["onboard"]["device_cert"] == tmp_path / "device.pem"
    assert (tmp_path / "device.pem").read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")
    assert ctx.did == "did-from-mqtt"


def test_supplied_certificate_selects_the_matching_record(monkeypatch, tmp_path):
    cert = _certificate()
    pem = tmp_path / "device.pem"
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    record = devices.DeviceRecord(
        cert_id=devices.cert_id_from_pem(pem),
        region="eu-west-1",
        endpoint="example-ats.iot.eu-west-1.amazonaws.com",
        thing="blueair-device",
        policy="blueair-policy",
        device_cert=str(pem),
        control_cert=str(tmp_path / "control.cert.pem"),
        control_key=str(tmp_path / "control.key"),
        did="did-known",
    )
    devices.save(tmp_path, [record])
    devices.activate(tmp_path, record)

    def fail(*args, **kwargs):
        raise AssertionError("a supplied certificate must select its own record")

    monkeypatch.setattr(exploit, "_select_record", fail)
    monkeypatch.setattr(exploit.aws, "check", fail)

    parser = cli.build_parser()
    args = parser.parse_args(
        [
            "--output",
            str(tmp_path),
            "exploit",
            "--device-cert",
            str(pem),
            "--onboard-only",
        ]
    )
    ctx = Context(output=tmp_path)

    assert exploit.run(ctx, args) == 0
    assert ctx.did == "did-known"
