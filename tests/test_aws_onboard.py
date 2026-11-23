from __future__ import annotations

import datetime as dt
import sys
import types

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from blueair_cloudcutter import aws


class _NotFound(Exception):
    pass


class FakeIot:
    class exceptions:
        ResourceNotFoundException = _NotFound

    def __init__(self) -> None:
        self.calls = []
        self.cert = None

    def describe_endpoint(self, endpointType):
        return {"endpointAddress": "example-ats.iot.eu-west-1.amazonaws.com"}

    def get_policy(self, policyName):
        if policyName not in self.calls:
            self.calls.append(policyName)
            raise _NotFound()

    def create_policy(self, policyName, policyDocument):
        self.calls.append(("create_policy", policyName))

    def describe_thing(self, thingName):
        if ("thing", thingName) not in self.calls:
            self.calls.append(("thing", thingName))
            raise _NotFound()

    def create_thing(self, thingName):
        self.calls.append(("create_thing", thingName))

    def describe_certificate(self, certificateId):
        if self.cert is None:
            raise _NotFound()
        return {"certificateDescription": {"certificateArn": self.cert}}

    def register_certificate_without_ca(self, certificatePem, status):
        self.cert = "arn:aws:iot:eu-west-1:123:cert/device"
        self.calls.append(("register", status))
        return {"certificateArn": self.cert}

    def attach_policy(self, policyName, target):
        self.calls.append(("attach_policy", target))

    def attach_thing_principal(self, thingName, principal):
        self.calls.append(("attach_thing", thingName, principal))

    def create_keys_and_certificate(self, setAsActive):
        self.calls.append(("create_keys", setAsActive))
        return {
            "certificateArn": "arn:aws:iot:eu-west-1:123:cert/control",
            "certificatePem": "-----BEGIN CERTIFICATE-----\ncontrol\n-----END CERTIFICATE-----\n",
            "keyPair": {
                "PrivateKey": "fake-key",
                "PublicKey": "pub",
            },
        }


class FakeSts:
    def get_caller_identity(self):
        return {"Account": "123456789012", "Arn": "arn:aws:iam::123:user/test"}


class FakeSession:
    def __init__(self, *args, **kwargs):
        self.iot = FakeIot()
        self.sts = FakeSts()

    def client(self, name):
        return self.sts if name == "sts" else self.iot


def _device_cert() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def test_onboard(monkeypatch, tmp_path):
    fake = types.SimpleNamespace(Session=FakeSession)
    monkeypatch.setitem(sys.modules, "boto3", fake)

    device_cert = tmp_path / "device.pem"
    device_cert.write_bytes(_device_cert())
    cfg = aws.onboard(
        output=tmp_path,
        device_cert=device_cert,
        thing="blueair-device",
        region="eu-west-1",
        policy="blueair-policy",
        control_name="blueair-controller",
    )

    assert cfg.endpoint == "example-ats.iot.eu-west-1.amazonaws.com"
    assert cfg.thing == "blueair-device"
    assert cfg.account == "123456789012"
    device_dir = next((tmp_path / "devices").iterdir())
    assert (device_dir / "control.cert.pem").exists()
    assert (device_dir / "control.private.key").exists()
    assert (device_dir / "device.pem").exists()
    assert cfg.device_cert == str(device_dir / "device.pem")
    assert (tmp_path / "devices.json").exists()
    assert aws.load_default(tmp_path) == cfg


def test_onboard_accepts_a_der_certificate(monkeypatch, tmp_path):
    fake = types.SimpleNamespace(Session=FakeSession)
    monkeypatch.setitem(sys.modules, "boto3", fake)

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    device_cert = tmp_path / "device.der"
    device_cert.write_bytes(cert.public_bytes(serialization.Encoding.DER))

    cfg = aws.onboard(output=tmp_path, device_cert=device_cert, region="eu-west-1")

    device_copy = next((tmp_path / "devices").iterdir()) / "device.pem"
    assert device_copy.read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")
    assert cfg.device_cert == str(device_copy)


def test_onboard_uses_unique_default_names(monkeypatch, tmp_path):
    fake = types.SimpleNamespace(Session=FakeSession)
    monkeypatch.setitem(sys.modules, "boto3", fake)

    pem = _device_cert()
    device_cert = tmp_path / "device.pem"
    device_cert.write_bytes(pem)
    cfg = aws.onboard(output=tmp_path, device_cert=device_cert, region="eu-west-1")

    suffix = aws._cert_id(pem)[:12]
    assert cfg.thing == f"blueair-device-{suffix}"
    assert cfg.control_name == f"blueair-controller-{suffix}"


def test_default_names_differ_per_certificate():
    first = aws._cert_id(_device_cert())
    second = aws._cert_id(_device_cert())
    assert first != second
    assert aws.default_thing_name(first) != aws.default_thing_name(second)
    assert aws.default_control_name(first) != aws.default_control_name(second)


def test_check(monkeypatch):
    fake = types.SimpleNamespace(Session=FakeSession)
    monkeypatch.setitem(sys.modules, "boto3", fake)
    result = aws.check("eu-west-1")
    assert result["account"] == "123456789012"
    assert result["endpoint"].startswith("example-ats")
