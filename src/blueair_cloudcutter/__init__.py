"""BlueAir CloudCutter: local control and custom firmware for BlueAir AWS IoT devices."""

from __future__ import annotations

import os

# Rootless containers map container uid 0 to the host user, so the uid that
# bleak announces in D-Bus AUTH EXTERNAL does not match SO_PEERCRED. Bleak 0.20+
# reads this variable; -1 omits the uid and lets the daemon use the kernel
# identity. The uid is optional in the D-Bus spec.
os.environ.setdefault("BLEAK_DBUS_AUTH_UID", "-1")

__version__ = "0.1.0"
