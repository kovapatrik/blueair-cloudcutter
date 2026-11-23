#!/usr/bin/env python3
"""Regenerate the checked-in protobuf modules from src/blueair_cloudcutter/protos."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROTOS = ROOT / "src" / "blueair_cloudcutter" / "protos"

subprocess.run(
    [
        "protoc",
        f"-I{PROTOS}",
        f"--python_out={PROTOS}",
        *[str(path) for path in sorted(PROTOS.glob("*.proto"))],
    ],
    check=True,
)

# protoc emits top-level imports when the .proto files do not use package
# paths. Rewrite them so the modules work as blueair_cloudcutter.protos.*.
for path in PROTOS.glob("*_pb2.py"):
    text = path.read_text()
    text = re.sub(
        r"^import (\w+_pb2) as (\w+)$",
        r"from blueair_cloudcutter.protos import \1 as \2",
        text,
        flags=re.MULTILINE,
    )
    path.write_text(text)
