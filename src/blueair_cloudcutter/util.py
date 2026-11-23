"""Small shared helpers: output, subprocesses, files, prompts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def info(msg: str) -> None:
    print(f"[*] {msg}", flush=True)


def ok(msg: str) -> None:
    print(_c("32", f"[+] {msg}"), flush=True)


def warn(msg: str) -> None:
    print(_c("33", f"[!] {msg}"), flush=True)


def error(msg: str) -> None:
    print(_c("31", f"[-] {msg}"), file=sys.stderr, flush=True)


def step(n: int, total: int, msg: str) -> None:
    print(_c("1", f"\n[{n}/{total}] {msg}"), flush=True)


def header(msg: str) -> None:
    print(_c("1", f"\n=== {msg} ==="), flush=True)


def die(msg: str, code: int = 1) -> None:
    error(msg)
    raise SystemExit(code)


def confirm(question: str, default: bool = False) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    try:
        answer = input(question + suffix).strip().lower()
    except EOFError:
        return False
    if not answer:
        return default
    return answer in {"y", "yes"}


def which(name: str) -> str | None:
    return shutil.which(name)


def run(cmd: list[str], *, check: bool = True, capture: bool = True, **kw) -> subprocess.CompletedProcess:
    info(" ".join(cmd))
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        capture_output=capture,
        **kw,
    )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def extract_uuid(text: str) -> str | None:
    if not text:
        return None
    m = re.search(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        text,
    )
    return m.group(0).lower() if m else None


def safe_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "device"


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def hand_back_output(path: Path) -> None:
    """Chown an output tree to the invoking user after a sudo run."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not (uid and gid) or not is_root():
        return
    try:
        os.chown(path, int(uid), int(gid))
        for child in path.rglob("*"):
            os.chown(child, int(uid), int(gid))
    except OSError:
        pass


def tempdir(prefix: str = "blueair-cloudcutter-") -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix))


def local_ip() -> str | None:
    """Best-effort LAN address of this machine (no packets are sent)."""
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()
