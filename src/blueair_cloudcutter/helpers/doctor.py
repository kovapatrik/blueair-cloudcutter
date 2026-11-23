from __future__ import annotations

from .. import preflight
from ..context import Context


def run(ctx: Context, args) -> int:
    items = preflight.checks(ctx.output)
    ok_all = preflight.print_checks(items)
    print()
    if ok_all:
        print("Core requirements satisfied.")
        return 0
    print("Some required tools are missing. Install them, or use the Docker wrapper.")
    return 1
