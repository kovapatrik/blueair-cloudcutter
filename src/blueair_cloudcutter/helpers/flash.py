"""Flash custom firmware, or restore the official image through the factory endpoint."""

from __future__ import annotations

from ..context import Context
from ..errors import CutterError
from ..firmware import install
from ..util import info


def run(ctx: Context, args) -> int:
    custom = install.load_image(args.custom, "--custom") if args.custom else None
    official = install.load_image(args.official, "--official") if args.official else None

    if custom is None:
        if official is None:
            raise CutterError(
                "pass --custom <app.bin>, or --official <signed image> to restore the official firmware"
            )
        if args.dry_run:
            info(f"official image: {len(official)} B")
            info("would write it to the passive slot and reboot")
            return 0
        return install.restore_official(
            ctx,
            official=official,
            version=args.version,
            image_name=getattr(args, "image_name", None),
            reboot=not args.no_reset,
        )

    if args.dry_run:
        return install.dry_run(
            ctx,
            custom=custom,
            version=args.version,
            image_name=getattr(args, "image_name", None),
            pad=args.pad,
        )
    return install.install(
        ctx,
        custom=custom,
        official=official,
        no_dump=args.no_dump,
        version=args.version,
        image_name=getattr(args, "image_name", None),
        header16=getattr(args, "header16", None),
        pad=args.pad,
        settle=args.settle,
        reboot=not args.no_reset,
        send_pad=args.send_pad,
        custom_path=args.custom,
    )
