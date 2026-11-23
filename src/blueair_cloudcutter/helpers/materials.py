from __future__ import annotations

from ..context import Context
from ..util import info, ok, step


def run(ctx: Context, args) -> int:
    action = getattr(args, "action", "init") or "init"
    if action == "show":
        if not ctx.materials.ca_cert.exists():
            info("no materials yet; run `blueair-cloudcutter helpers materials init`")
            return 1
        print(ctx.materials.summary())
        return 0

    step(1, 1, "Certificate material")
    sans = list(args.san or [])
    if not sans:
        sans = ["localhost", "127.0.0.1"]
    ctx.materials.org = args.org
    ctx.materials.ensure_all(sans)
    ok("materials ready in " + str(ctx.material_dir))
    print()
    print(ctx.materials.summary())
    print()
    info("These files are private. output/ is gitignored; do not publish it.")
    return 0
