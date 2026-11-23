from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from blueair_cloudcutter.capture import parse_tls_certificates


def _cert_der() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-device")])
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
    return cert.public_bytes(serialization.Encoding.DER)


def _tls_record(payload: bytes, content_type: int = 22) -> bytes:
    return bytes([content_type]) + b"\x03\x03" + len(payload).to_bytes(2, "big") + payload


def _cert_message(der: bytes) -> bytes:
    cert_list = len(der).to_bytes(3, "big") + der
    body = len(cert_list).to_bytes(3, "big") + cert_list
    return b"\x0b" + len(body).to_bytes(3, "big") + body


def test_parse_tls_certificate():
    der = _cert_der()
    stream = _tls_record(_cert_message(der))
    assert parse_tls_certificates(stream) == [der]


def test_parse_handshake_split_across_records():
    der = _cert_der()
    msg = _cert_message(der)
    split = len(msg) // 2
    stream = _tls_record(msg[:split]) + _tls_record(msg[split:])
    assert parse_tls_certificates(stream) == [der]


def test_no_certificate_returns_empty():
    assert parse_tls_certificates(b"") == []
    assert parse_tls_certificates(_tls_record(b"\x0e\x00\x00\x00", 22)) == []
    assert parse_tls_certificates(_tls_record(b"hello", 23)) == []
