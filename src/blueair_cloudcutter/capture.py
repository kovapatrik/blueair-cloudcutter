"""Capture the device's client certificate from its AWS IoT TLS handshake.

The device uses mutual TLS to the AWS IoT broker. In TLS 1.2 the client's
Certificate message is sent in the clear (before the encrypted application
data), so an AP that carries the device's traffic can observe it. Only the
public certificate is needed; the private key stays on the device.

This is the no-UART replacement for reading `c-b` out of the NVS dump.
"""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from .errors import CutterError
from .util import info, ok

TLS_HANDSHAKE = 22
TLS_CLIENT_CERT = 11


def _records(data: bytes) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    i = 0
    while i + 5 <= len(data):
        content_type = data[i]
        length = int.from_bytes(data[i + 3 : i + 5], "big")
        end = i + 5 + length
        if end > len(data):
            break
        out.append((content_type, data[i + 5 : end]))
        i = end
    return out


def _certificates_from_handshake(handshake: bytes) -> list[bytes]:
    certs: list[bytes] = []
    i = 0
    while i + 4 <= len(handshake):
        msg_type = handshake[i]
        length = int.from_bytes(handshake[i + 1 : i + 4], "big")
        body = handshake[i + 4 : i + 4 + length]
        i += 4 + length
        if msg_type != TLS_CLIENT_CERT or len(body) < 6:
            continue
        total = int.from_bytes(body[:3], "big")
        body = body[3 : 3 + total]
        j = 0
        while j + 3 <= len(body):
            cert_len = int.from_bytes(body[j : j + 3], "big")
            j += 3
            cert = body[j : j + cert_len]
            j += cert_len
            if cert:
                certs.append(cert)
    return certs


def parse_tls_certificates(data: bytes) -> list[bytes]:
    """Extract DER certificates from a TLS stream fragment."""
    handshake = b"".join(payload for typ, payload in _records(data) if typ == TLS_HANDSHAKE)
    if not handshake:
        return []
    return _certificates_from_handshake(handshake)


def capture(
    interface: str,
    *,
    out: Path,
    timeout: float = 120.0,
    pcap: Path | None = None,
) -> Path:
    try:
        from scapy.all import IP, TCP, Raw, sniff, wrpcap
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise CutterError(
            "scapy is not installed. Install the capture extra: pip install 'blueair-cloudcutter[capture]'"
        ) from exc

    info(f"listening on {interface} for TLS client certificates (port 8883)")
    info("the device must connect to the real AWS endpoint through this AP")
    streams: dict[tuple, bytearray] = {}
    found: dict[str, bytes] = {}
    packets = []

    def handle(pkt) -> None:
        if IP not in pkt or TCP not in pkt or Raw not in pkt:
            return
        if pkt[TCP].dport != 8883:  # only client -> broker
            return
        if pcap is not None:
            packets.append(pkt)
        key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        buf = streams.setdefault(key, bytearray())
        buf.extend(bytes(pkt[Raw].load))
        certs = parse_tls_certificates(bytes(buf))
        if certs:
            found["der"] = certs[0]

    sniff(
        iface=interface,
        filter="tcp port 8883",
        prn=handle,
        store=False,
        timeout=timeout,
        stop_filter=lambda _pkt: bool(found),
    )

    if pcap is not None and packets:
        pcap.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(pcap), packets)
        info(f"pcap saved -> {pcap}")

    if "der" not in found:
        raise CutterError(
            "no client certificate captured. Check that the device is connected to "
            "the AP, that it is dialing the real AWS IoT endpoint, and that the AP "
            "interface is being sniffed (not a bridged port that hides stations)."
        )

    cert = x509.load_der_x509_certificate(found["der"])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(cert.public_bytes(Encoding.PEM))
    ok(f"captured client certificate -> {out}")
    info(f"subject: {cert.subject.rfc4514_string()}")
    return out
