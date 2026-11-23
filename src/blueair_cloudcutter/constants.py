"""Values that are specific to the Blue Pure / Blue Max (`nb_*`) family.

Everything here was verified against firmware 1.0.4 / 1.0.6 on an
`nb_l_1.0` device (Blue Pure 411i Max / Blue Max 3250i). Other models in the
family are expected to be identical for the protocol, but the image header must
be confirmed against a dump before flashing.

Raw flash access (backup/restore/slot switching) is deliberately not part of
this library; see `docs/flash-access.md`.
"""

from __future__ import annotations

# --------------------------------------------------------------------------
# The `--no-dump` chain
# --------------------------------------------------------------------------

G4_HEADER16 = bytes.fromhex("e906023f18180840ee00000000000100")

# provisionImagePostHandler / esp_ota_begin constants
MCU_BUFF = 1048832  # remaining request body must EXCEED this
OTA_BUF = 3096  # first-chunk buffer; the handler scans it for 0xE9
E9_TARGET = OTA_BUF - 16  # put the magic byte here -> exactly one 16-byte write

# cJSON clamps positive numbers to INT_MAX; a negative number survives and is
# read back as uint32_t. (0xFFFFFFFE + 0xFFF) & 0xFFFFF000 == 0.
OVERFLOW_SIZE = -2
OVERFLOW_RANGE = (-4095, -2)

# Default padding *declared* in Content-Length but never transmitted.
PAD_DEFAULT = MCU_BUFF + 8192

# Multipart boundary. On the wire it is b"--" + BOUNDARY (28 dashes + "BAOTA").
BOUNDARY = b"--------------------------BAOTA"

# --------------------------------------------------------------------------
# Factory mode
# --------------------------------------------------------------------------

FACTORY_SSID = "BAFactory"
FACTORY_PSK = "9102revreSyrotcaF"  # "FactoryServer2019" reversed

# Short-lived AP used for the no-UART provisioning window. Like cloudcutter's
# cloudcutterflash/abcdabcd, the PSK is fixed: the device receives it over BLE,
# so there is nothing for the user to type.
AP_SSID = "BlueAirCloudCutter"
AP_PSK = "blueaircutter"
FACTORY_HOST = "factoryserver.blueair"
FACTORY_PORT = 8443
FACTORY_HELLO_PATH = "/fs/hello-message"
FACTORY_EVENTS_PATH = "/fs/events"

# The URI template baked into the firmware. Used when the device has no DID
# (for example after an NVS wipe).
PLACEHOLDER_DID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

# --------------------------------------------------------------------------
# Protocol
# --------------------------------------------------------------------------

DEFAULT_HTTP_PORT = 443
DEFAULT_MQTT_PORT = 8883
# Read from the device's own `c/read` reply (`_eid`) and reused for writes.
# This placeholder is only a fallback; `configapi` discovers the real value.
CONFIG_ENTITY_ID = "00000000-0000-0000-0000-000000000000"
CONFIG_IT = "urn:blueair:openapi:version:blue:0.0.5"

CONFIG_SECTIONS = ("di", "db", "da", "ds", "dc", "df", "fc")

# Connection-critical and irreversible. The tool refuses to write these.
FORBIDDEN_CONFIG_KEYS = frozenset({("db", "c-cli"), ("db", "psk")})

# Safe slots to overwrite for broker liberation, in order of preference.
# c-r is the active trust anchor. c-r2 is a rotation slot and has no effect.
BROKER_CA_SLOTS = ("c-r", "c-r2")
