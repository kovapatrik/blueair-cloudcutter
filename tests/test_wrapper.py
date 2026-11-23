"""The wrapper never starts mosquitto as root."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "blueair-cloudcutter.sh"

FAKE_ENGINE = """#!/bin/sh
case "$1" in
  info) case "$2" in --format) echo '[]' ;; *) exit 0 ;; esac ;;
  --version) echo "Docker version 27.0.0, build test" ;;
  image) exit 0 ;;
  run) printf '%s\\n' "$@" > "$ARGS_FILE" ;;
esac
exit 0
"""

pytestmark = pytest.mark.skipif(
    os.geteuid() == 0, reason="the wrapper cannot tell root apart from a sudo run as root"
)


def wrapper_env(tmp_path: Path) -> tuple[dict, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    engine = bin_dir / "docker"
    engine.write_text(FAKE_ENGINE)
    engine.chmod(0o755)

    args_file = tmp_path / "args"
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "ARGS_FILE": str(args_file),
        "BLUEAIR_CLOUDCUTTER_OUTPUT": str(tmp_path / "output"),
        "BLUEAIR_CLOUDCUTTER_ENGINE": "docker",
        "SUDO_UID": str(os.getuid()),
        "SUDO_GID": str(os.getgid()),
    }
    return env, args_file


def run_wrapper(tmp_path: Path, *args: str) -> list[str]:
    env, args_file = wrapper_env(tmp_path)
    subprocess.run(["bash", str(SCRIPT), *args], check=True, env=env, capture_output=True)
    return args_file.read_text().splitlines()


def test_broker_runs_as_the_invoking_user(tmp_path):
    args = run_wrapper(tmp_path, "helpers", "serve", "broker", "--san", "broker.local")

    assert args[args.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"


def test_other_commands_keep_the_default_user(tmp_path):
    args = run_wrapper(tmp_path, "helpers", "serve", "factory", "--no-tls")

    assert "--user" not in args


def test_onboarded_exploit_does_not_require_the_ap(tmp_path):
    out = tmp_path / "output"
    out.mkdir()
    (out / "aws.json").write_text('{"did": "1cd9a74c-209c-436a-9ead-a81784ca265e"}')

    args = run_wrapper(tmp_path, "exploit", "--skip-wifi-setup")

    assert "exploit" in args
    assert "--iface" not in args
    assert "--pid=host" not in args


def test_supplied_device_certificate_does_not_require_the_ap(tmp_path):
    args = run_wrapper(tmp_path, "exploit", "--device-cert", "device.pem", "--onboard-only")

    assert "exploit" in args
    assert "--iface" not in args
    assert "--pid=host" not in args


def test_native_mode_is_removed(tmp_path):
    env, args_file = wrapper_env(tmp_path)

    result = subprocess.run(
        ["bash", str(SCRIPT), "--native", "doctor"],
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "--native was removed" in result.stderr
    assert not args_file.exists()
