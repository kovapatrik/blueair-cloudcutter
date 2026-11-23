"""Supporting servers: the factory rendezvous, the AP/DNS configs, the broker."""

from __future__ import annotations

import time

from ..context import Context
from ..errors import CutterError
from ..factoryserver import FactoryServer
from ..fakeapi import FakeApiServer
from ..network import (
    Process,
    add_dns_redirect,
    ensure_address,
    pick_dns_port,
    prepare_interface,
    remove_address,
    remove_rules,
    start_mosquitto,
    write_cleanup,
    write_configs,
    write_mqtt_bundle,
)
from ..util import info, local_ip, ok


def _factory(ctx: Context, args) -> int:
    server = FactoryServer(
        host=args.host,
        port=args.port,
        tls=not args.no_tls,
        material_dir=ctx.material_dir,
        cert_host=getattr(args, "cert_host", "factoryserver.blueair"),
    )
    server.start()
    hint = args.host if args.host not in {"0.0.0.0", ""} else (local_ip() or "<this machine>")
    ok(f"listening. Add a DNS rewrite: factoryserver.blueair -> {hint}")
    try:
        if args.once:
            hello = server.wait_for_hello(args.timeout)
            if not hello:
                raise CutterError("no hello received before the timeout")
            ok(f"hello from {hello.source_ip}" + (f" did={hello.did}" if hello.did else ""))
            return 0
        info("Ctrl-C to stop")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return 0
    finally:
        server.stop()


def _network(ctx: Context, args) -> int:
    if not getattr(args, "iface", None):
        raise CutterError("serve network/broker needs --iface <wireless interface>")
    dhcp_dns = getattr(args, "dhcp_dns", None)
    if dhcp_dns and dhcp_dns != args.gateway:
        dns_port = 0
    else:
        dns_port = pick_dns_port()
    configs = write_configs(
        ctx.output / "network",
        iface=args.iface,
        ssid=getattr(args, "ssid", "BAFactory"),
        psk=getattr(args, "psk", "9102revreSyrotcaF"),
        country=getattr(args, "country", None),
        gateway=args.gateway,
        ca=ctx.materials.ca_cert if ctx.materials.ca_cert.exists() else None,
        cert=ctx.materials.p("broker-chain.pem") if ctx.materials.p("broker-chain.pem").exists() else None,
        key=ctx.materials.broker_key,
        port=args.broker_port,
        dns_port=dns_port,
        dhcp_dns=dhcp_dns,
    )
    ok(f"configs written to {ctx.output / 'network'}")
    for name, path in configs.items():
        info(f"{name:10s} {path}")

    if dns_port == 0:
        info(f"dnsmasq DNS disabled; DHCP hands out {dhcp_dns}")
    elif dns_port != 53:
        info(f"port 53 is in use; dnsmasq is configured for {dns_port}")
    if not args.start:
        print()
        print(f"  sudo hostapd {configs['hostapd']}")
        print(f"  sudo dnsmasq -C {configs['dnsmasq']} -d")
        if dns_port not in (0, 53):
            for proto in ("udp", "tcp"):
                print(
                    f"  sudo iptables -t nat -A PREROUTING -i {args.iface} -p {proto} "
                    f"--dport 53 -j REDIRECT --to-ports {dns_port}"
                )
        if "mosquitto" in configs:
            print(f"  mosquitto -c {configs['mosquitto']} -v")
        return 0

    procs: list[Process] = []
    added = False
    dns_rules: list[list[str]] = []
    try:
        prepare_interface(args.iface)
        added = ensure_address(args.iface, args.gateway)
        dns_rules = add_dns_redirect(args.iface, dns_port)
        cleanup_lines = [f"iw dev {args.iface} set type managed 2>/dev/null || true"]
        for rule in dns_rules:
            delete = " ".join("-D" if arg == "-A" else arg for arg in rule)
            cleanup_lines.insert(0, f"{delete} 2>/dev/null || true")
        if added:
            cleanup_lines.insert(0, f"ip addr del {args.gateway}/24 dev {args.iface} 2>/dev/null || true")
        write_cleanup(ctx.output / "cleanup.sh", cleanup_lines)
        procs.append(
            Process(["hostapd", str(configs["hostapd"])], ctx.output / "logs" / "hostapd.log").start()
        )
        procs.append(
            Process(
                ["dnsmasq", "-C", str(configs["dnsmasq"]), "-d"], ctx.output / "logs" / "dnsmasq.log"
            ).start()
        )
        if "mosquitto" in configs:
            procs.append(start_mosquitto(configs["mosquitto"], ctx.output / "logs" / "mosquitto.log").start())
        info("services running. Ctrl-C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return 0
    finally:
        for proc in procs:
            proc.stop()
        remove_rules(dns_rules)
        if added:
            remove_address(args.iface, args.gateway)
        (ctx.output / "cleanup.sh").unlink(missing_ok=True)


def _fake_api(ctx: Context, args) -> int:
    server = FakeApiServer(port=args.api_port).start()
    ok(f"fake API on 0.0.0.0:{server.port} (plain HTTP)")
    info(f"api_url  http://<AP-IP>:{server.port}/prod")
    info(f"auth_url http://<AP-IP>:{server.port}/prod/c/authenticate")
    info("Ctrl-C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return 0
    finally:
        server.stop()


def _broker(ctx: Context, args) -> int:
    if not ctx.materials.ca_cert.exists():
        raise CutterError("no materials yet; run `blueair-cloudcutter helpers materials init` first")
    sans = args.san or ["localhost"]
    conf = write_mqtt_bundle(
        ctx.materials,
        ctx.output / "mqtt",
        port=args.broker_port,
        sans=sans,
    )
    proc = start_mosquitto(conf, ctx.output / "logs" / "mosquitto.log", echo=True)
    proc.start()
    time.sleep(1)
    code = proc.proc.poll() if proc.proc else None
    if code is not None:
        raise CutterError(f"mosquitto exited with code {code}; see {proc.log}")
    ok(f"mosquitto running with {conf}")
    info(f"broker log: {proc.log} (also shown below)")
    info("Ctrl-C to stop")
    try:
        while True:
            code = proc.proc.poll() if proc.proc else None
            if code is not None:
                if code == 0:
                    return 0
                raise CutterError(f"mosquitto exited with code {code}; see {proc.log}")
            time.sleep(0.5)
    except KeyboardInterrupt:
        return 0
    finally:
        proc.stop()


def run(ctx: Context, args) -> int:
    if args.service == "factory":
        return _factory(ctx, args)
    if args.service == "network":
        return _network(ctx, args)
    if args.service == "fake-api":
        return _fake_api(ctx, args)
    if args.service == "broker":
        return _broker(ctx, args)
    raise CutterError(f"unknown service {args.service!r}")
