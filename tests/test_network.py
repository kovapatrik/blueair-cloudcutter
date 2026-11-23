"""AP network config helpers."""

from __future__ import annotations

from blueair_cloudcutter.certs import Materials
from blueair_cloudcutter.network import (
    Process,
    dnsmasq_conf,
    write_cleanup,
    write_mqtt_bundle,
)


def test_dnsmasq_alternate_port():
    conf = dnsmasq_conf("wld0", gateway="192.168.50.1", dns_port=5353)

    assert "port=5353" in conf
    assert "interface=wld0" in conf
    assert "dhcp-range=192.168.50.10,192.168.50.100" in conf


def test_dnsmasq_default_port_has_no_port_line():
    assert "port=" not in dnsmasq_conf("wld0", gateway="192.168.50.1")


def test_cleanup_script_is_self_deleting(tmp_path):
    path = tmp_path / "cleanup.sh"
    write_cleanup(path, ["echo undo"])

    body = path.read_text()
    assert body.startswith("#!/bin/sh\n")
    assert "echo undo" in body
    assert f"rm -f {path}" in body
    assert path.stat().st_mode & 0o111


def test_dhcp_can_hand_out_public_dns():
    conf = dnsmasq_conf("wld0", gateway="192.168.50.1", dhcp_dns="1.1.1.1")

    assert "dhcp-option=6,1.1.1.1" in conf
    assert "dhcp-option=6,192.168.50.1" not in conf


def test_default_gateway_parser():
    from blueair_cloudcutter.network import parse_default_gateway

    text = "default via 192.168.0.1 dev end0 proto dhcp metric 100\n"
    assert parse_default_gateway(text) == "192.168.0.1"
    assert parse_default_gateway("") is None


def test_dnsmasq_dns_disabled_when_using_router():
    conf = dnsmasq_conf("wld0", gateway="192.168.50.1", dns_port=0, dhcp_dns="192.168.0.1")

    assert "port=0" in conf
    assert "dhcp-option=6,192.168.0.1" in conf


def test_mqtt_bundle_is_self_contained(tmp_path):
    conf = write_mqtt_bundle(
        Materials(tmp_path / "materials"),
        tmp_path / "mqtt",
        port=8883,
        sans=["broker.local"],
    )

    assert conf == tmp_path / "mqtt" / "mosquitto.conf"
    text = conf.read_text()
    assert "listener 8883 0.0.0.0" in text
    assert "cafile ca.pem" in text
    assert "certfile broker-chain.pem" in text
    assert "keyfile broker.key" in text
    assert (conf.parent / "ca.pem").exists()
    assert (conf.parent / "broker-chain.pem").exists()
    assert (conf.parent / "broker.key").stat().st_mode & 0o777 == 0o600
    assert (conf.parent / "start.sh").stat().st_mode & 0o111
    assert 'cd "$(dirname "$0")"' in (conf.parent / "start.sh").read_text()
    assert (conf.parent / "README.txt").exists()


def test_process_echoes_the_log_to_stdout(tmp_path, capsys):
    log = tmp_path / "logs" / "child.log"
    proc = Process(["sh", "-c", "echo hello-from-child"], log, echo=True).start()
    proc.proc.wait(timeout=5)
    proc.stop()

    assert "hello-from-child" in log.read_text()
    out = capsys.readouterr().out
    assert out.count("hello-from-child") == 2  # the command line and the child output


def test_process_keeps_the_log_quiet_without_echo(tmp_path, capsys):
    log = tmp_path / "logs" / "child.log"
    proc = Process(["sh", "-c", "echo hello-from-child"], log).start()
    proc.proc.wait(timeout=5)
    proc.stop()

    assert "hello-from-child" in log.read_text()
    out = capsys.readouterr().out
    assert out.count("hello-from-child") == 1  # only the command line
