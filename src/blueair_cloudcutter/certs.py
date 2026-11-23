"""Certificate, key and JWT material generation.

Everything the tool needs is generated locally and written to
`<output>/materials/` (gitignored). Nothing is copied from the vendor.

Layout:
    ca.pem / ca.key                     root CA planted into the device (db.c-r)
    int.pem / int.key                   intermediate, mirrors the stock 3-level chain
    broker.pem / broker.key             mosquitto server certificate (leaf + int chain file)
    broker-chain.pem                    leaf + intermediate, what mosquitto serves
    kjwt.pem / kjwt.key                 self-signed RSA cert for db.k-jwt + RS256 tokens

The device verifies factory tokens against the certificate in `db.k-jwt`. A
token signed with the matching private key is accepted; if `k-jwt` is absent
(after an NVS wipe), any token is accepted, but the header must still be a
well-formed three-part JWT.
"""

from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import json
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from .errors import CutterError
from .util import info, ok

_ONE_DAY = dt.timedelta(days=1)


def _name(cn: str, org: str, ou: str | None = None) -> x509.Name:
    attrs = [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ]
    if ou:
        attrs.insert(1, x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    return x509.Name(attrs)


def _write_key(path: Path, key) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def load_certificate(path: Path) -> x509.Certificate:
    """Load an X.509 certificate from PEM or DER."""
    try:
        data = path.read_bytes()
        if b"-----BEGIN CERTIFICATE-----" in data:
            return x509.load_pem_x509_certificate(data)
        return x509.load_der_x509_certificate(data)
    except OSError as exc:
        raise CutterError(f"cannot read certificate {path}: {exc}") from exc
    except ValueError as exc:
        raise CutterError(f"{path} is not a PEM or DER X.509 certificate") from exc


def certificate_pem_bytes(path: Path) -> bytes:
    """The certificate as PEM, whatever the input encoding was."""
    return load_certificate(path).public_bytes(serialization.Encoding.PEM)


def ensure_pem_certificate(path: Path, out: Path) -> Path:
    """Return ``path`` as PEM, writing ``out`` when the input is elsewhere or DER."""
    pem = certificate_pem_bytes(path)
    if path.resolve() != out.resolve():
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(pem)
        return out
    if path.read_bytes() != pem:
        path.write_bytes(pem)
    return path


def _validity(days: int) -> tuple[dt.datetime, dt.datetime]:
    now = dt.datetime.now(dt.timezone.utc)
    return now - _ONE_DAY, now + dt.timedelta(days=days)


def _build_cert(
    *,
    subject: x509.Name,
    issuer: x509.Name,
    public_key,
    signing_key,
    days: int,
    is_ca: bool,
    san: list[str] | None = None,
    path_length: int | None = None,
) -> x509.Certificate:
    not_before, not_after = _validity(days)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=not is_ca,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if san:
        names: list[x509.GeneralName] = []
        for value in san:
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(value)))
            except ValueError:
                names.append(x509.DNSName(value))
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return builder.sign(signing_key, hashes.SHA256())


class Materials:
    def __init__(self, root: Path, org: str = "BlueAir CloudCutter") -> None:
        self.root = root
        self.org = org
        self.root.mkdir(parents=True, exist_ok=True)

    # -- paths -------------------------------------------------------------

    def p(self, name: str) -> Path:
        return self.root / name

    @property
    def ca_cert(self) -> Path:
        return self.p("ca.pem")

    @property
    def ca_key(self) -> Path:
        return self.p("ca.key")

    @property
    def broker_cert(self) -> Path:
        return self.p("broker.pem")

    @property
    def broker_key(self) -> Path:
        return self.p("broker.key")

    # -- generation --------------------------------------------------------

    def ensure_ca(self, days: int = 3650) -> None:
        if self.ca_cert.exists() and self.ca_key.exists():
            return
        key = ec.generate_private_key(ec.SECP256R1())
        name = _name("BlueAir CloudCutter Root CA", self.org, "Liberation")
        cert = _build_cert(
            subject=name,
            issuer=name,
            public_key=key.public_key(),
            signing_key=key,
            days=days,
            is_ca=True,
            path_length=1,
        )
        _write_key(self.ca_key, key)
        _write_cert(self.ca_cert, cert)
        ok(f"generated root CA -> {self.ca_cert}")

    def ensure_intermediate(self, days: int = 3650) -> None:
        if self.p("int.pem").exists() and self.p("int.key").exists():
            return
        self.ensure_ca()
        ca_key = serialization.load_pem_private_key(self.ca_key.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(self.ca_cert.read_bytes())
        key = ec.generate_private_key(ec.SECP256R1())
        name = _name("BlueAir CloudCutter Intermediate CA", self.org, "Liberation")
        cert = _build_cert(
            subject=name,
            issuer=ca_cert.subject,
            public_key=key.public_key(),
            signing_key=ca_key,
            days=days,
            is_ca=True,
            path_length=0,
        )
        _write_key(self.p("int.key"), key)
        _write_cert(self.p("int.pem"), cert)
        ok(f"generated intermediate -> {self.p('int.pem')}")

    def _broker_is_current(self, sans: list[str]) -> bool:
        wanted = {name.casefold() for name in (sans or ["localhost"])}
        if not (
            self.broker_cert.exists() and self.broker_key.exists() and self.p("broker-chain.pem").exists()
        ):
            return False
        try:
            leaf = x509.load_pem_x509_certificate(self.broker_cert.read_bytes())
            key = serialization.load_pem_private_key(self.broker_key.read_bytes(), password=None)
            chain = self.p("broker-chain.pem").read_bytes()
            int_cert = x509.load_pem_x509_certificate(self.p("int.pem").read_bytes())
            names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except (OSError, ValueError, x509.ExtensionNotFound):
            return False

        if leaf.not_valid_after_utc <= dt.datetime.now(dt.timezone.utc):
            return False
        current = {str(name.value).casefold() for name in names}
        if not wanted.issubset(current):
            return False
        der = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if leaf.public_key().public_bytes(*der) != key.public_key().public_bytes(*der):
            return False
        expected = leaf.public_bytes(serialization.Encoding.PEM) + int_cert.public_bytes(
            serialization.Encoding.PEM
        )
        return chain == expected

    def ensure_broker(self, sans: list[str], days: int = 825) -> None:
        """Broker leaf certificate. SANs should include the hostname or LAN IP."""
        self.ensure_intermediate()
        if self._broker_is_current(sans):
            info(f"broker certificate already covers {', '.join(sans or ['localhost'])}")
            return
        int_key = serialization.load_pem_private_key(self.p("int.key").read_bytes(), password=None)
        int_cert = x509.load_pem_x509_certificate(self.p("int.pem").read_bytes())
        key = ec.generate_private_key(ec.SECP256R1())
        name = _name("mqtt.local", self.org, "Broker")
        cert = _build_cert(
            subject=name,
            issuer=int_cert.subject,
            public_key=key.public_key(),
            signing_key=int_key,
            days=days,
            is_ca=False,
            san=sans or ["localhost"],
        )
        _write_key(self.broker_key, key)
        _write_cert(self.broker_cert, cert)
        chain = cert.public_bytes(serialization.Encoding.PEM) + int_cert.public_bytes(
            serialization.Encoding.PEM
        )
        self.p("broker-chain.pem").write_bytes(chain)
        ok(f"generated broker certificate for {', '.join(sans or ['localhost'])} -> {self.broker_cert}")

    def ensure_kjwt(self, days: int = 3650) -> None:
        if self.p("kjwt.pem").exists() and self.p("kjwt.key").exists():
            return
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = _name("jwt.blueair", "Blueair AB", "IoT")
        cert = _build_cert(
            subject=name,
            issuer=name,
            public_key=key.public_key(),
            signing_key=key,
            days=days,
            is_ca=False,
        )
        _write_key(self.p("kjwt.key"), key)
        _write_cert(self.p("kjwt.pem"), cert)
        ok(f"generated k-jwt identity -> {self.p('kjwt.pem')}")

    def ensure_all(self, sans: list[str] | None = None) -> None:
        self.ensure_ca()
        self.ensure_intermediate()
        self.ensure_broker(sans or ["localhost"])
        self.ensure_kjwt()

    # -- inspection --------------------------------------------------------

    def summary(self) -> str:
        lines = []
        for cert_path in ("ca.pem", "int.pem", "broker.pem", "kjwt.pem"):
            path = self.p(cert_path)
            if not path.exists():
                lines.append(f"{cert_path:14s} missing")
                continue
            cert = x509.load_pem_x509_certificate(path.read_bytes())
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            lines.append(f"{cert_path:14s} CN={cn}  expires {cert.not_valid_after_utc:%Y-%m-%d}")
        return "\n".join(lines)


def load_cert_text(path: Path) -> str:
    text = path.read_text().strip()
    if "BEGIN CERTIFICATE" not in text:
        raise CutterError(f"{path} is not a PEM certificate")
    # The device requires real newlines; json.dumps will escape them.
    return text + "\n"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def mint_rs256(key_path: Path, payload: dict | None = None, *, include_iat: bool = False) -> str:
    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except FileNotFoundError as exc:
        raise CutterError(f"JWT key not found: {key_path}") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise CutterError(f"{key_path} is not an RSA private key (RS256 requires RSA)")

    header = {"alg": "RS256", "typ": "JWT"}
    claims = dict(payload or {})
    if include_iat:
        claims.setdefault("iat", int(time.time()))

    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64url(json.dumps(claims, separators=(",", ":")).encode())
    )
    signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return signing_input + "." + _b64url(signature)


def mint_static_token() -> str:
    """A syntactically valid token for the wiped-NVS case.

    `http_server_jwt_verify` fails open when `k-jwt` is absent, but the HTTP
    handler still requires the Authorization header to look like a JWT. This
    token has the right shape and an RS256 header; the signature is a dummy.
    It only works on a device with no verification key at all.
    """
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64url(b"{}")
    signature = _b64url(b"\x00" * 256)
    return f"{header}.{body}.{signature}"
