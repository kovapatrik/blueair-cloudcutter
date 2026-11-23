"""CmConfig read/write.

Two transports, same envelope:

* HTTPS in factory mode: POST /d/<did>/configuration/get and /configuration
* MQTT: d/<did>/c/read and d/<did>/c/prov

The write envelope is a `Diff`: only the fields included are changed. Writes are
atomic. An error applies nothing, so a failed write is safe to retry.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from typing import Any

from .constants import (
    CONFIG_ENTITY_ID,
    CONFIG_IT,
    CONFIG_SECTIONS,
    FORBIDDEN_CONFIG_KEYS,
)
from .errors import DeviceError, SafetyError
from .httpclient import DeviceHTTP, Response
from .util import info

_VERSION_RX = re.compile(r'"_v"\s*:\s*(\d+)')
_HW_RX = re.compile(r'"hw"\s*:\s*"([^"]*)"')
_DID_RX = re.compile(r'"did"\s*:\s*"([^"]*)"')
_EID_RX = re.compile(r'"_eid"\s*:\s*"([^"]*)"')
_CAS_RX = re.compile(r"current config version \((\d+)\)")


def envelope(did: str, cas: int, version: int, eid: str | None = None) -> dict[str, Any]:
    return {
        "_eid": eid or CONFIG_ENTITY_ID,
        "eid": "",
        "_id": did,
        "_s": {"sig": ""},  # not verified by the device
        "_cas": cas,
        "_v": version,
        "_it": CONFIG_IT,
        "_t": "Diff",
        "id": str(uuid.uuid4()),
    }


def validate_payload(payload: dict[str, Any]) -> None:
    if not isinstance(payload, dict) or not payload:
        raise SafetyError("nothing to write")
    for section, body in payload.items():
        if section not in CONFIG_SECTIONS:
            raise SafetyError(f"unknown section {section!r}; expected one of {', '.join(CONFIG_SECTIONS)}")
        if isinstance(body, dict):
            for key in body:
                if (section, key) in FORBIDDEN_CONFIG_KEYS:
                    raise SafetyError(
                        f"refusing to write {section}.{key}: connection-critical and irreversible"
                    )


def find_version(text: str) -> int | None:
    m = _VERSION_RX.search(text or "")
    return int(m.group(1)) if m else None


def find_hw(text: str) -> str | None:
    m = _HW_RX.search(text or "")
    return m.group(1) if m else None


def find_did(text: str) -> str | None:
    m = _DID_RX.search(text or "")
    return m.group(1) if m else None


def find_eid(text: str) -> str | None:
    m = _EID_RX.search(text or "")
    return m.group(1) if m else None


# --------------------------------------------------------------------------
# HTTPS (factory mode)
# --------------------------------------------------------------------------


def read_http(
    http: DeviceHTTP, did: str, token: str, read_type: str = "State", v: int | None = None
) -> Response:
    body_obj: dict[str, Any] = {"t": read_type}
    if read_type == "Diff":
        body_obj["v"] = v if v is not None else 1
        body_obj["s"] = {"sig": ""}
    body = json.dumps(body_obj).encode()
    return http.request(
        "POST",
        f"/d/{did}/configuration/get",
        body=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        timeout=30,
    )


def write_http(http: DeviceHTTP, did: str, token: str, obj: dict[str, Any]) -> Response:
    return http.post_json(f"/d/{did}/configuration", obj, token, timeout=30)


def set_fields_http(
    http: DeviceHTTP,
    did: str,
    token: str,
    payload: dict[str, Any],
    *,
    cas: int | None = None,
    version: int | None = None,
    eid: str | None = None,
) -> Response:
    validate_payload(payload)
    if cas is None or eid is None:
        resp = read_http(http, did, token)
        if not resp.ok:
            raise DeviceError(f"configuration/get failed: {resp}")
        if cas is None:
            cas = find_version(resp.body)
        if eid is None:
            eid = find_eid(resp.body)
        if cas is None:
            # A wiped device can come back with no version at all. Start at 0;
            # a 409 reply tells us the real value and the retry below uses it.
            cas = 0
    obj = envelope(did, cas, version if version is not None else cas + 1, eid)
    obj.update(payload)
    resp = write_http(http, did, token, obj)
    if not acked(resp):
        m = _CAS_RX.search(resp.body or "")
        if m:
            obj["_cas"] = int(m.group(1))
            obj["_v"] = obj["_cas"] + 1
            resp = write_http(http, did, token, obj)
    if not acked(resp):
        raise DeviceError(
            f"write was not acked ({resp}). The apply is atomic, so nothing changed. Re-read _v and retry."
        )
    return resp


def acked(resp: Response) -> bool:
    if resp.status != 200:
        return False
    text = resp.body or ""
    return '"ack"' in text or '"c":200' in text or '"c": 200' in text


# --------------------------------------------------------------------------
# MQTT
# --------------------------------------------------------------------------


def read_mqtt(
    mqtt,
    did: str,
    read_type: str = "State",
    wait: float | None = None,
    v: int | None = None,
    attempts: int | None = None,
    wait_for_device: bool = False,
) -> str:
    body: dict[str, Any] = {"t": read_type}
    if read_type == "Diff":
        body["v"] = v if v is not None else 1
        body["s"] = {"sig": ""}
    full = read_type == "Full"
    wait = wait if wait is not None else (90.0 if full else 15.0)
    attempts = attempts if attempts is not None else (1 if full else 3)
    if wait_for_device:
        mqtt.wait_for_device(did)
    for attempt in range(1, attempts + 1):
        # State and Diff are quick. A Full read can take about a minute, so it gets
        # one long attempt instead of several short ones.
        text = mqtt.request(f"d/{did}/c/read", body, f"d/{did}/c/read-r", wait=wait)
        if text:
            return text
        if attempt < attempts:
            info(f"no {read_type} reply; retrying")
            time.sleep(2)
    return ""


def write_mqtt(
    mqtt,
    did: str,
    payload: dict[str, Any],
    *,
    cas: int | None = None,
    version: int | None = None,
    eid: str | None = None,
    wait: float = 10.0,
) -> str:
    validate_payload(payload)
    if cas is None or eid is None:
        text = read_mqtt(mqtt, did)
        if cas is None:
            cas = find_version(text) or 0
        if eid is None:
            eid = find_eid(text)
    obj = envelope(did, cas, version if version is not None else cas + 1, eid)
    obj.update(payload)
    reply = mqtt.request(f"d/{did}/c/prov", obj, f"d/{did}/c/prov-r", wait=wait)
    m = _CAS_RX.search(reply or "")
    if m and '"ack"' not in reply and '"c":200' not in reply:
        obj["_cas"] = int(m.group(1))
        obj["_v"] = obj["_cas"] + 1
        reply = mqtt.request(f"d/{did}/c/prov", obj, f"d/{did}/c/prov-r", wait=wait)
    return reply
