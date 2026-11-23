"""Shared command context: paths, state, credentials and auto-discovery."""

from __future__ import annotations

import datetime as _dt
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .certs import Materials, mint_rs256, mint_static_token
from .configapi import find_did, find_hw, find_version
from .errors import DeviceError, SafetyError
from .httpclient import DeviceHTTP
from .util import info, read_json, warn, write_json


@dataclass
class State:
    """Persistent run state, so a failed step can be resumed.

    State lives in `<output>/state.json` and is written after every step. It
    holds no secrets: only device identity, versions, file paths and step
    results.
    """

    version: int = 1
    created: str = ""
    updated: str = ""
    device_ip: str | None = None
    did: str | None = None
    hw: str | None = None
    config_version: int | None = None
    custom_firmware: str | None = None
    official_firmware: str | None = None
    steps: dict = field(default_factory=dict)

    @staticmethod
    def _now() -> str:
        return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")

    def mark(self, name: str, **data) -> None:
        self.steps[name] = {"at": self._now(), **data}
        self.updated = self._now()

    def done(self, name: str) -> bool:
        return bool(self.steps.get(name))

    def save(self, path: Path) -> None:
        if not self.created:
            self.created = self._now()
        self.updated = self._now()
        write_json(path, asdict(self))

    @classmethod
    def load(cls, path: Path) -> State:
        raw = read_json(path, default=None)
        if not isinstance(raw, dict):
            return cls()
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in raw.items() if k in known})


@dataclass
class Context:
    output: Path
    ip: str | None = None
    did: str | None = None
    port: int = 443
    token_file: Path | None = None
    bind: str | None = None
    timeout: float = 60.0
    state: State = field(default_factory=State)

    def __post_init__(self) -> None:
        self.output.mkdir(parents=True, exist_ok=True)
        (self.output / "materials").mkdir(exist_ok=True)
        (self.output / "logs").mkdir(exist_ok=True)
        self.materials = Materials(self.output / "materials")
        self.state = State.load(self.state_path)
        if self.ip is None:
            self.ip = self.state.device_ip
        if self.did is None:
            self.did = self.state.did

    # -- paths -------------------------------------------------------------

    @property
    def state_path(self) -> Path:
        return self.output / "state.json"

    @property
    def material_dir(self) -> Path:
        return self.output / "materials"

    def save(self) -> None:
        self.state.device_ip = self.ip or self.state.device_ip
        self.state.did = self.did or self.state.did
        self.state.save(self.state_path)

    # -- credentials -------------------------------------------------------

    def token(self) -> str:
        """Factory-mode Authorization token.

        Priority:
          1. an explicit --token-file,
          2. a token signed by our generated k-jwt key (the normal case),
          3. a syntactically valid unsigned token (only works when k-jwt is
             absent, i.e. after an NVS wipe).
        """
        if self.token_file:
            if not self.token_file.exists():
                raise SafetyError(f"token file not found: {self.token_file}")
            return self.token_file.read_text().strip()
        key = self.material_dir / "kjwt.key"
        if key.exists():
            return mint_rs256(key)
        warn("no k-jwt key yet; using a token that only works on a wiped device")
        return mint_static_token()

    # -- HTTP --------------------------------------------------------------

    def http(self, *, timeout: float | None = None) -> DeviceHTTP:
        if not self.ip:
            raise DeviceError("device IP unknown; pass --ip or run discovery first")
        return DeviceHTTP(self.ip, self.port, timeout=timeout or self.timeout, bind=self.bind)

    # -- discovery ---------------------------------------------------------

    def discover(self, *, read_type: str = "State") -> str:
        """Read the device config and populate did/hw/version.

        Requires the factory HTTPS server to be up (factory mode). If the DID is
        unknown, the firmware's own placeholder URI is tried first: after an NVS
        wipe the device has no DID, and that is the path it serves.
        """
        from .configapi import read_http
        from .constants import PLACEHOLDER_DID

        http = self.http()
        token = self.token()
        candidates = [self.did] if self.did else []
        candidates.append(PLACEHOLDER_DID)

        last = None
        for did in candidates:
            resp = read_http(http, did, token, read_type)
            last = resp
            if resp.ok:
                version = find_version(resp.body)
                hw = find_hw(resp.body)
                found = find_did(resp.body)
                if found:
                    self.did = found
                elif not self.did:
                    self.did = did
                self.state.config_version = version
                self.state.hw = hw
                self.state.device_ip = self.ip
                self.state.did = self.did
                self.save()
                info(f"device did={self.did} hw={hw!r} config _v={version}")
                return resp.body
        raise DeviceError(f"configuration/get failed: {last}")
