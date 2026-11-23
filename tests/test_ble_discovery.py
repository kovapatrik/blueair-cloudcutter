"""Scan normalisation: find the purifier without relying on its name."""

from __future__ import annotations

from types import SimpleNamespace

from blueair_cloudcutter.ble import discovery
from blueair_cloudcutter.ble.transport import SERVICE_UUID


def _adv(**kwargs):
    base = dict(local_name=None, rssi=-60, service_uuids=[], service_data={})
    base.update(kwargs)
    return SimpleNamespace(**base)


def _device(name="", address="AA:BB:CC:DD:EE:FF"):
    return SimpleNamespace(name=name, address=address)


def test_service_uuid_in_advertisement_matches():
    adv = _adv(service_uuids=[SERVICE_UUID])
    entries = discovery._normalise({"AA:BB": (_device(), adv)})

    assert entries[0].service_match


def test_service_data_uuid_also_matches():
    adv = _adv(service_data={SERVICE_UUID: b"\x00"})
    entries = discovery._normalise({"AA:BB": (_device(), adv)})

    assert entries[0].service_match


def test_blueair_device_sorts_before_stronger_others():
    blueair = _adv(local_name="Blue Pure 411i Max", rssi=-80, service_uuids=[SERVICE_UUID])
    other = _adv(local_name="Phone", rssi=-30)

    entries = discovery._normalise(
        {
            "AA:BB": (_device(address="AA:BB"), other),
            "CC:DD": (_device(address="CC:DD"), blueair),
        }
    )

    assert [entry.address for entry in entries] == ["CC:DD", "AA:BB"]
    assert entries[0].service_match
    assert not entries[1].service_match
