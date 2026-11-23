#!/bin/sh
# Keep output/ owned by the invoking user, not root.
set -e
trap 'chown -R "${HOST_UID:-0}:${HOST_GID:-0}" /output 2>/dev/null || true' EXIT
exec blueair-cloudcutter --output /output "$@"
