"""Capture the device's public client certificate."""

from __future__ import annotations

from pathlib import Path

from ..capture import capture
from ..context import Context
from ..util import step


def run(ctx: Context, args) -> int:
    step(1, 1, "Capture the device client certificate")
    out = Path(args.out) if args.out else ctx.output / "device.pem"
    capture(
        args.interface,
        out=out,
        timeout=args.timeout,
        pcap=Path(args.pcap) if args.pcap else None,
    )
    print()
    print("Next:")
    print(f"  blueair-cloudcutter aws onboard --device-cert {out} --thing <did>")
    print("  # or skip the AP with an already captured certificate:")
    print(f"  blueair-cloudcutter exploit --device-cert {out} --onboard-only")
    return 0
