"""Minimal factory server.

After an NVS wipe the device falls back to its compiled-in factory defaults:
SSID `BAFactory`, and it POSTs a hello to
`https://factoryserver.blueair:8443/factory` (some firmware uses
`/fs/hello-message`).

The factory server is a rendezvous point, not a firmware source. It only has to
answer 200 and record where the device came from. That gives us the device's LAN
IP (and usually its DID) without any discovery protocol.

TLS: the device's trust store was wiped along with NVS, so it cannot validate a
public CA. A self-signed certificate for `factoryserver.blueair` is enough. If
the device turns out to still validate, use `--no-tls` only after checking the
UART log.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import ssl
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .constants import FACTORY_HOST
from .util import extract_uuid, info, ok


@dataclass
class Hello:
    source_ip: str
    path: str
    body: str
    did: str | None
    at: str = field(default_factory=lambda: dt.datetime.now().isoformat(timespec="seconds"))

    @property
    def json(self):
        try:
            return json.loads(self.body)
        except json.JSONDecodeError:
            return None


class _Handler(BaseHTTPRequestHandler):
    server_version = "BlueAirFactory/1.0"

    def _handle(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        info(f"factory {method} {self.path} from {self.client_address[0]}")
        if body:
            info(f"  body: {body[:1200]}")
        hello = Hello(
            source_ip=self.client_address[0],
            path=self.path,
            body=body,
            did=extract_uuid(body) or extract_uuid(self.path),
        )
        if not hello.did:
            # The hello may be form-encoded or carry a different field name.
            hello.did = extract_uuid(json.dumps(dict(self.headers)))
        self.server.hellos.append(hello)  # type: ignore[attr-defined]
        if self.path.rstrip("/") in {"", "/fs/hello-message", "/factory"}:
            ok(f"hello from {hello.source_ip}" + (f"  did={hello.did}" if hello.did else ""))

        payload = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PUT(self) -> None:
        self._handle("PUT")

    def log_message(self, *args) -> None:
        pass


def _self_signed(host: str, outdir: Path) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    outdir.mkdir(parents=True, exist_ok=True)
    stem = host.replace(":", "_").replace("/", "_")
    cert_path, key_path = outdir / f"factory-{stem}-cert.pem", outdir / f"factory-{stem}-key.pem"
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = dt.datetime.now(dt.timezone.utc)
    try:
        san = [x509.IPAddress(ipaddress.ip_address(host))]
    except ValueError:
        san = [x509.DNSName(host)]
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


class FactoryServer:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8443,
        *,
        tls: bool = True,
        material_dir: Path | None = None,
        cert_host: str = FACTORY_HOST,
    ) -> None:
        self.host = host
        self.port = port
        self.tls = tls
        self.cert_host = cert_host
        self.material_dir = material_dir or Path("output/materials")
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def hellos(self) -> list[Hello]:
        return self._httpd.hellos if self._httpd else []  # type: ignore[attr-defined]

    def start(self) -> FactoryServer:
        self._httpd = ThreadingHTTPServer((self.host, self.port), _Handler)
        self._httpd.hellos = []  # type: ignore[attr-defined]
        if self.tls:
            cert, key = _self_signed(self.cert_host, self.material_dir)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
            self._httpd.socket = ctx.wrap_socket(self._httpd.socket, server_side=True)
        scheme = "https" if self.tls else "http"
        info(f"factory server listening on {scheme}://{self.host}:{self.port} (cert {self.cert_host})")
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
        self._httpd = None

    def __enter__(self) -> FactoryServer:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    def wait_for_hello(self, timeout: float = 300.0) -> Hello | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            for hello in list(self.hellos):
                path = hello.path.rstrip("/")
                if path in {"", "/fs/hello-message", "/factory"}:
                    return hello
                if path.endswith("/fs/hello-message") or path.endswith("/factory"):
                    return hello
            time.sleep(0.5)
        return None
