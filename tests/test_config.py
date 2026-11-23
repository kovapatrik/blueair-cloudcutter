from __future__ import annotations

import pytest

from blueair_cloudcutter import certs, configapi
from blueair_cloudcutter.certs import Materials
from blueair_cloudcutter.errors import SafetyError


def test_envelope_shape():
    env = configapi.envelope("did-1", 10, 11)
    assert env["_t"] == "Diff"
    assert env["_cas"] == 10
    assert env["_v"] == 11
    assert env["_s"] == {"sig": ""}
    assert env["_id"] == "did-1"


def test_forbidden_keys_are_refused():
    with pytest.raises(SafetyError):
        configapi.validate_payload({"db": {"c-cli": "x"}})
    with pytest.raises(SafetyError):
        configapi.validate_payload({"db": {"psk": "x"}})
    with pytest.raises(SafetyError):
        configapi.validate_payload({"nope": {}})


def test_safe_payload_is_accepted():
    configapi.validate_payload({"db": {"c-r2": "pem"}, "di": {"hw": "nb_l_1.0"}})


def test_version_eid_and_cas_parsing():
    body = '{"_v": 42, "_eid": "e-1", "di": {"hw": "nb_l_1.0"}, "db": {"did": "d-1"}}'
    assert configapi.find_version(body) == 42
    assert configapi.find_eid(body) == "e-1"
    assert configapi.find_hw(body) == "nb_l_1.0"
    assert configapi.find_did(body) == "d-1"
    reply = "JSON _cas (1) != current config version (42)"
    assert configapi._CAS_RX.search(reply).group(1) == "42"


def test_mint_and_verify_rs256(tmp_path):
    m = Materials(tmp_path)
    m.ensure_kjwt()
    token = certs.mint_rs256(m.p("kjwt.key"))
    header, payload, signature = token.split(".")
    assert header and payload and signature

    import base64
    import json

    def b64d(part: str) -> bytes:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))

    assert json.loads(b64d(header))["alg"] == "RS256"
    assert json.loads(b64d(payload)) == {}

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    key = serialization.load_pem_private_key(m.p("kjwt.key").read_bytes(), password=None)
    key.public_key().verify(
        b64d(signature), f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256()
    )


def test_materials_are_idempotent(tmp_path):
    m = Materials(tmp_path)
    m.ensure_all(["192.168.1.10", "broker.local"])
    first = m.ca_cert.read_bytes()
    m.ensure_all(["192.168.1.10", "broker.local"])
    assert m.ca_cert.read_bytes() == first
    assert m.p("broker-chain.pem").exists()
    assert "CN=" in m.summary()


def test_broker_certificate_is_reused_for_the_same_sans(tmp_path):
    m = Materials(tmp_path)
    m.ensure_broker(["broker.local"])
    first_cert = m.broker_cert.read_bytes()
    first_key = m.broker_key.read_bytes()

    m.ensure_broker(["broker.local"])
    assert m.broker_cert.read_bytes() == first_cert
    assert m.broker_key.read_bytes() == first_key

    m.ensure_broker(["other.local"])
    assert m.broker_cert.read_bytes() != first_cert
