"""Onboarding records for one or more purifiers.

``output/aws.json`` stays the *active* device so the rest of the CLI keeps
working, but every onboarded certificate also gets its own record in
``output/devices.json`` and its own directory under ``output/devices/<id>/``.
That way onboarding a second purifier no longer overwrites the first one's
certificate, control identity or DID.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from .errors import CutterError
from .util import info, ok, read_json, write_json

INDEX = "devices.json"
ACTIVE = "aws.json"


@dataclass
class DeviceRecord:
    cert_id: str
    region: str
    endpoint: str
    thing: str
    policy: str
    device_cert: str
    control_cert: str
    control_key: str
    control_name: str = ""
    account: str = ""
    did: str = ""
    arn: str = ""
    name: str = ""
    address: str = ""

    @property
    def label(self) -> str:
        who = self.name or self.thing or "purifier"
        did = self.did or "did unknown"
        return f"{who}  {did}  cert {self.cert_id[:8]}"

    def matches(self, selector: str) -> bool:
        query = selector.strip().casefold()
        if not query:
            return False
        values = {
            self.cert_id.casefold(),
            self.did.casefold(),
            self.thing.casefold(),
            self.name.casefold(),
            self.address.casefold(),
            self.arn.casefold(),
        }
        if len(query) >= 4:
            values.add(self.cert_id[: len(query)].casefold())
        return query in values


def index_path(output: Path) -> Path:
    return output / INDEX


def cert_id_from_arn(arn: str) -> str:
    return arn.rsplit("/", 1)[-1] if ":cert/" in arn or "/cert/" in arn else ""


def cert_id_from_pem(path: Path) -> str:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        cert = x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError):
        return ""
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def _record(raw: dict) -> DeviceRecord | None:
    known = {field.name for field in fields(DeviceRecord)}
    values = {key: raw.get(key, "") for key in known if raw.get(key) is not None}
    if not values.get("arn"):
        values["arn"] = str(raw.get("device_cert_arn") or "")
    if not values.get("cert_id"):
        values["cert_id"] = cert_id_from_arn(str(values.get("arn", "")))
    if not values.get("cert_id") and values.get("device_cert"):
        values["cert_id"] = cert_id_from_pem(Path(str(values["device_cert"])))
    if not values.get("cert_id"):
        return None
    for key in ("region", "endpoint", "thing", "policy", "device_cert", "control_cert", "control_key"):
        values.setdefault(key, "")
    return DeviceRecord(**values)


def load(output: Path) -> list[DeviceRecord]:
    """Load the registry, adopting a legacy single-device ``aws.json``."""
    raw = read_json(index_path(output), default=None)
    entries: list = []
    if isinstance(raw, dict):
        entries = raw.get("devices", [])
    elif isinstance(raw, list):
        entries = raw

    records = [record for item in entries if isinstance(item, dict) and (record := _record(item))]
    if records:
        return records

    legacy = read_json(output / ACTIVE, default=None)
    if isinstance(legacy, dict):
        adopted = _record(legacy)
        if adopted is not None:
            return [adopted]
    return []


def save(output: Path, records: list[DeviceRecord]) -> None:
    write_json(
        index_path(output),
        {"version": 1, "devices": [asdict(record) for record in records]},
    )


def activate(output: Path, record: DeviceRecord) -> None:
    """Make ``record`` the device ``output/aws.json`` points at."""
    from .aws import AwsConfig

    cfg = AwsConfig(
        region=record.region,
        endpoint=record.endpoint,
        thing=record.thing,
        policy=record.policy,
        device_cert=record.device_cert,
        control_cert=record.control_cert,
        control_key=record.control_key,
        control_name=record.control_name,
        account=record.account,
        did=record.did,
        device_cert_arn=record.arn,
    )
    cfg.save(output / ACTIVE)


def upsert(
    output: Path,
    cfg,
    *,
    did: str | None = None,
    name: str | None = None,
    address: str | None = None,
) -> DeviceRecord:
    """Add or update the record for an onboarded device and make it active."""
    cert_id = cert_id_from_arn(getattr(cfg, "device_cert_arn", "")) or cert_id_from_pem(Path(cfg.device_cert))
    if not cert_id:
        raise CutterError(f"cannot identify the device certificate {cfg.device_cert}")

    records = load(output)
    record = next((item for item in records if item.cert_id == cert_id), None)
    if record is None:
        record = DeviceRecord(
            cert_id=cert_id,
            region=cfg.region,
            endpoint=cfg.endpoint,
            thing=cfg.thing,
            policy=cfg.policy,
            device_cert=cfg.device_cert,
            control_cert=cfg.control_cert,
            control_key=cfg.control_key,
            control_name=getattr(cfg, "control_name", ""),
        )
        records.append(record)

    record.region = cfg.region or record.region
    record.endpoint = cfg.endpoint or record.endpoint
    record.thing = cfg.thing or record.thing
    record.policy = cfg.policy or record.policy
    record.device_cert = cfg.device_cert or record.device_cert
    record.control_cert = cfg.control_cert or record.control_cert
    record.control_key = cfg.control_key or record.control_key
    record.control_name = getattr(cfg, "control_name", None) or record.control_name
    record.account = cfg.account or record.account
    record.arn = cfg.device_cert_arn or record.arn
    record.did = did if did is not None else (getattr(cfg, "did", "") or record.did)
    if name:
        record.name = name
    if address:
        record.address = address

    save(output, records)
    activate(output, record)
    return record


def select(records: list[DeviceRecord], selector: str) -> DeviceRecord:
    """Pick by DID, certificate id/prefix, thing, BLE address or 1-based index."""
    query = selector.strip()
    if not records:
        raise CutterError("no onboarded devices yet; run the exploit first")

    if query.isdigit():
        index = int(query) - 1
        if 0 <= index < len(records):
            return records[index]

    matches = [record for record in records if record.matches(query)]
    if not matches:
        raise CutterError(
            f"no onboarded device matches {selector!r}; "
            f"known: {', '.join(record.did or record.cert_id[:8] for record in records)}"
        )
    if len(matches) > 1:
        raise CutterError(f"{selector!r} matches {len(matches)} devices; use the DID or certificate id")
    return matches[0]


def prompt(records: list[DeviceRecord], *, allow_new: bool = False) -> DeviceRecord | None:
    print("\nOnboarded devices:")
    for number, record in enumerate(records, 1):
        print(f"  {number}) {record.label}")
    if allow_new:
        print(f"  {len(records) + 1}) a new purifier (provision over BLE)")

    while True:
        answer = input("Choose device [1]: ").strip() or "1"
        if answer.isdigit():
            index = int(answer) - 1
            if 0 <= index < len(records):
                return records[index]
            if allow_new and index == len(records):
                return None
        print(f"Enter 1-{len(records) + (1 if allow_new else 0)}.")


def format_table(records: list[DeviceRecord]) -> str:
    if not records:
        return "No onboarded devices."
    lines = ["Onboarded devices:", ""]
    for number, record in enumerate(records, 1):
        lines.append(f"  {number}) {record.label}")
        if record.address:
            lines.append(f"     BLE address: {record.address}")
        if record.thing:
            lines.append(f"     thing:       {record.thing}")
        if record.region:
            lines.append(f"     region:      {record.region}")
    return "\n".join(lines)


def resolve(
    output: Path,
    selector: str | None = None,
    *,
    interactive: bool = False,
    allow_new: bool = False,
    activate_record: bool = True,
) -> DeviceRecord | None:
    """Select an onboarded device, prompting when there are several.

    Returns ``None`` when the user chose to provision a new device.
    """
    records = load(output)
    if selector:
        record = select(records, selector)
    elif len(records) == 1:
        record = records[0]
    elif not records:
        return None
    elif interactive:
        record = prompt(records, allow_new=allow_new)
    else:
        raise CutterError("multiple onboarded devices; pass --did <did> (or --device) to choose one")

    if record is None:
        return None
    if activate_record:
        activate(output, record)
        info(f"selected {record.label}")
        ok(f"active config -> {output / ACTIVE}")
    return record
