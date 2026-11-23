#!/usr/bin/env bash
# Entrypoint
#
#   ./blueair-cloudcutter.sh                 guided exploit (container)
#   ./blueair-cloudcutter.sh exploit ...     explicit exploit flags
#   ./blueair-cloudcutter.sh helpers ...     manual and recovery commands
#
# Docker is required because the image pins dependencies and ships hostapd,
# dnsmasq and mosquitto. It is Linux-only for the hardware steps (AP mode and
# Bluetooth).
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${BLUEAIR_CLOUDCUTTER_IMAGE:-ghcr.io/kovapatrik/blueair-cloudcutter:0.1.0}"
OUT="${BLUEAIR_CLOUDCUTTER_OUTPUT:-$PWD/output}"
ENGINE="${BLUEAIR_CLOUDCUTTER_ENGINE:-docker}"

# nmcli can be installed while NetworkManager is not running (common on NixOS
# with systemd-networkd). Calling it then returns 8, and `set -e` would abort the
# wrapper before it even prints the AP line.
have_nmcli() {
  command -v nmcli >/dev/null 2>&1 || return 1
  nmcli -t -f DEVICE device status >/dev/null 2>&1
}

if [[ "${1:-}" == "--native" ]]; then
  echo "--native was removed. Install Docker or Podman and run this script through it." >&2
  exit 2
fi

if ! command -v "$ENGINE" >/dev/null 2>&1; then
  if [ "$ENGINE" = "docker" ] && command -v podman >/dev/null 2>&1; then
    ENGINE=podman
  else
    echo "$ENGINE not found. Install Docker or Podman, or set BLUEAIR_CLOUDCUTTER_ENGINE." >&2
    exit 1
  fi
fi

if ! "$ENGINE" info >/dev/null 2>&1; then
  echo "Cannot talk to $ENGINE. Start it, fix your user session, or run with sudo." >&2
  exit 1
fi

ROOTLESS=0
SECURITY_OPTIONS="$("$ENGINE" info --format '{{json .SecurityOptions}}' 2>/dev/null || true)"
case "$SECURITY_OPTIONS" in
  *rootless*) ROOTLESS=1 ;;
esac
# podman-docker / a `docker` shim: the Docker Info format may differ, so ask podman.
ENGINE_VERSION="$("$ENGINE" --version 2>&1 || true)"
case "$ENGINE_VERSION" in
  *[Pp]odman*)
    PODMAN_ROOTLESS="$("$ENGINE" info --format '{{.Host.Security.Rootless}}' 2>/dev/null || true)"
    if [ -z "$PODMAN_ROOTLESS" ] && command -v podman >/dev/null 2>&1; then
      PODMAN_ROOTLESS="$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || true)"
    fi
    case "$PODMAN_ROOTLESS" in
      true*) ROOTLESS=1 ;;
    esac
    ;;
esac

get_opt() {
  local key="$1"
  shift
  while [ "$#" -gt 0 ]; do
    case "$1" in
      "$key") [ "$#" -gt 1 ] && { printf '%s\n' "$2"; return 0; }; return 1 ;;
      "$key"=*) printf '%s\n' "${1#*=}"; return 0 ;;
    esac
    shift
  done
  return 1
}

pick_wireless() {
  local entry choice
  local ifaces=()
  for entry in /sys/class/net/*/wireless; do
    [ -e "$entry" ] || continue
    ifaces+=("$(basename "$(dirname "$entry")")")
  done
  if [ "${#ifaces[@]}" -eq 0 ]; then
    return 1
  fi
  if [ "${#ifaces[@]}" -eq 1 ]; then
    printf '%s\n' "${ifaces[0]}"
    return 0
  fi
  if [ -t 0 ]; then
    echo "Wireless interfaces:" >&2
    select choice in "${ifaces[@]}"; do
      if [ -n "${choice:-}" ]; then
        printf '%s\n' "$choice"
        return 0
      fi
    done
  fi
  printf '%s\n' "${ifaces[0]}"
}

# Rootless containers run in a private user namespace and without capabilities over
# the host's network namespace. `ble` works (the D-Bus uid mismatch is handled by
# dbus_shim), but AP mode and raw capture need the host network namespace and
# capabilities, which rootless mode cannot grant.
needs_host_netns() {
  case "${1:-}" in
    ""|exploit) return 0 ;;
    helpers)
      case "${2:-}" in
        capture) return 0 ;;
        serve)
          case "${3:-}" in
            network) return 0 ;;
          esac
          ;;
      esac
      ;;
  esac
  return 1
}

if [ "$ROOTLESS" = 1 ] && needs_host_netns "$@" && [ "${BLUEAIR_CLOUDCUTTER_ALLOW_ROOTLESS:-0}" != "1" ]; then
  cat >&2 <<EOF
Rootless containers cannot run AP mode or raw capture: capabilities only apply to
resources owned by the container's own user namespace, so hostapd and scapy
cannot touch the host Wi-Fi adapter.

Run the whole command as root:
    sudo ./blueair-cloudcutter.sh $*

BLE (ble scan / ble provision) does work rootless.
Set BLUEAIR_CLOUDCUTTER_ALLOW_ROOTLESS=1 to try anyway.
EOF
  exit 1
fi

if [ "${BLUEAIR_CLOUDCUTTER_REBUILD:-0}" = "1" ]; then
  "$ENGINE" build -t "$IMAGE" "$HERE"
elif ! "$ENGINE" image inspect "$IMAGE" >/dev/null 2>&1; then
  "$ENGINE" pull "$IMAGE" >/dev/null 2>&1 || "$ENGINE" build -t "$IMAGE" "$HERE"
fi

mkdir -p "$OUT"

HOST_UID="${SUDO_UID:-$(id -u)}"
HOST_GID="${SUDO_GID:-$(id -g)}"

# The broker binds an unprivileged port and only touches output/. Run it as the
# invoking user: mosquitto started as root drops to its own user before loading
# the 0600 broker.key and cannot read it, so never let it start as root.
USER_ARGS=()
if [ "${1:-}" = "helpers" ] && [ "${2:-}" = "serve" ] && [ "${3:-}" = "broker" ]; then
  if [ "$HOST_UID" -eq 0 ]; then
    HOST_UID="$(stat -c %u "$HERE" 2>/dev/null || id -u)"
    HOST_GID="$(stat -c %g "$HERE" 2>/dev/null || id -g)"
  fi
  if [ "$(id -u)" -eq 0 ]; then
    chown -R "$HOST_UID:$HOST_GID" "$OUT" 2>/dev/null || true
  fi
  USER_ARGS=(--user "$HOST_UID:$HOST_GID")
fi

if [ -z "${AWS_PROFILE:-}" ] && [ -f "$OUT/aws-profile" ]; then
  AWS_PROFILE="$(cat "$OUT/aws-profile")"
  export AWS_PROFILE
fi

# The exploit starts the AP only when it has to capture a new certificate or
# provision a device with no DID. Mirror exploit.py's need_ap here, so an
# already-onboarded device does not require a wireless interface at all.
exploit_needs_ap() {
  # A supplied client certificate comes from an AP or router capture the user
  # already did, so the exploit never starts its own AP.
  get_opt --device-cert "$@" >/dev/null && return 1
  get_opt --reprovision "$@" >/dev/null && return 0
  [ -f "$OUT/aws.json" ] || return 0
  get_opt --did "$@" >/dev/null && return 1
  grep -q '"did": *"[^"]' "$OUT/aws.json" && return 1
  return 0
}

AP_REQUESTED=0
AP_IFACE=""
case "${1:-}" in
  ""|exploit)
    if exploit_needs_ap "$@"; then
      AP_REQUESTED=1
      AP_IFACE="$(get_opt --iface "$@" || true)"
    fi
    ;;
  helpers)
    if [ "${2:-}" = "serve" ] && [ "${3:-}" = "network" ]; then
      for arg in "$@"; do [ "$arg" = "--start" ] && AP_REQUESTED=1; done
      AP_IFACE="$(get_opt --iface "$@" || true)"
    fi
    ;;
esac

AP_RUN_ARGS=()
FIRMWARES="$HERE/firmwares"
mkdir -p "$FIRMWARES"
FIRMWARES_MOUNTS=(-v "$FIRMWARES:/firmwares:ro")
RUN_ARGS=("$@")
if [ "$#" -eq 0 ]; then
  RUN_ARGS=(exploit)
fi

# The container only mounts output/ and firmwares/. Users copy firmware files
# into firmwares/ and pass just the filename; rewrite it to the container path.
map_firmware() {
  local flag="$1" value="$2" name i
  [ -n "$value" ] || return 0
  name="$(basename "$value")"
  if [ ! -f "$FIRMWARES/$name" ]; then
    echo "firmware not found: $name" >&2
    echo "Copy it into $FIRMWARES/ and pass only the filename." >&2
    exit 1
  fi
  i=0
  while [ "$i" -lt "${#RUN_ARGS[@]}" ]; do
    case "${RUN_ARGS[$i]}" in
      "$flag")
        RUN_ARGS[$((i + 1))]="/firmwares/$name"
        i=$((i + 2))
        ;;
      "$flag"=*)
        RUN_ARGS[$i]="${flag}=/firmwares/$name"
        i=$((i + 1))
        ;;
      *)
        i=$((i + 1))
        ;;
    esac
  done
}

map_firmware --firmware "$(get_opt --firmware "$@" || true)"
map_firmware --custom "$(get_opt --custom "$@" || true)"
map_firmware --official "$(get_opt --official "$@" || true)"

# The container has its own /etc/resolv.conf and no nss-mdns, so a hostname
# that resolves on the Pi (for example a Mac's .local mDNS name) still fails
# inside. Resolve it here and inject it into the container's /etc/hosts.
ADD_HOSTS=()
add_host() {
  local value="$1" host ip
  [ -n "$value" ] || return 0
  host="${value#*://}"
  host="${host%%/*}"
  host="${host%%:*}"
  case "$host" in
    *[A-Za-z]*) ;;
    *) return 0 ;;
  esac
  ip="$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR == 1 {print $1}')"
  if [ -z "$ip" ] && command -v avahi-resolve >/dev/null 2>&1; then
    ip="$(avahi-resolve -4 -n "$host" 2>/dev/null | awk 'NR == 1 {print $2}')"
  fi
  [ -n "$ip" ] && ADD_HOSTS+=(--add-host "$host:$ip")
}

add_host "$(get_opt --local-broker "$@" || true)"
add_host "$(get_opt --broker "$@" || true)"


# Host output paths are mounted at /output inside the container. Translate
# output/... and $OUT/... arguments so --ca output/materials/ca.pem works.
map_output_flag() {
  local flag="$1" value="$2" new i
  [ -n "$value" ] || return 0
  case "$value" in
    /output/*) return 0 ;;
    "$OUT"/*) new="/output/${value#"$OUT"/}" ;;
    output/*) new="/output/${value#output/}" ;;
    ./*output/*) new="/output/${value#./output/}" ;;
    *)
      if [ -e "$OUT/$value" ]; then
        new="/output/$value"
      else
        return 0
      fi
      ;;
  esac
  i=0
  while [ "$i" -lt "${#RUN_ARGS[@]}" ]; do
    case "${RUN_ARGS[$i]}" in
      "$flag")
        RUN_ARGS[$((i + 1))]="$new"
        i=$((i + 2))
        ;;
      "$flag"=*)
        RUN_ARGS[$i]="${flag}=$new"
        i=$((i + 1))
        ;;
      *) i=$((i + 1)) ;;
    esac
  done
}

map_output_flag --ca "$(get_opt --ca "$@" || true)"
map_output_flag --broker-ca "$(get_opt --broker-ca "$@" || true)"
map_output_flag --cert "$(get_opt --cert "$@" || true)"
map_output_flag --key "$(get_opt --key "$@" || true)"
map_output_flag --cert-file "$(get_opt --cert-file "$@" || true)"
map_output_flag --token-file "$(get_opt --token-file "$@" || true)"
map_output_flag --device-cert "$(get_opt --device-cert "$@" || true)"
map_output_flag --out "$(get_opt --out "$@" || true)"
map_output_flag --pcap "$(get_opt --pcap "$@" || true)"
map_output_flag --save "$(get_opt --save "$@" || true)"

PREV_STATE=""
PREV_CONN=""
RFKILL_BLOCKED=0
CLEANED=0

cleanup_host() {
  [ "$CLEANED" = 1 ] && return 0
  CLEANED=1
  if [ "$AP_REQUESTED" = 1 ]; then
    # Undo address/NAT changes even if the container was killed before its own
    # finally block could run. The script is written by the AP code.
    if [ -f "$OUT/cleanup.sh" ]; then
      "$ENGINE" run --rm --privileged --network host --pid=host \
        -v "$OUT:/output" --entrypoint sh "$IMAGE" /output/cleanup.sh \
        >/dev/null 2>&1 || true
    fi
    if have_nmcli; then
      if [ "$PREV_STATE" = "unmanaged" ]; then
        nmcli device set "$AP_IFACE" managed no >/dev/null 2>&1 || true
      else
        nmcli device set "$AP_IFACE" managed yes >/dev/null 2>&1 || true
        if [ -n "$PREV_CONN" ] && [ "$PREV_CONN" != "--" ]; then
          nmcli connection up "$PREV_CONN" >/dev/null 2>&1 || true
        fi
      fi
    fi
    if [ "$RFKILL_BLOCKED" = 1 ] && command -v rfkill >/dev/null 2>&1; then
      rfkill block wifi >/dev/null 2>&1 || true
    fi
    echo "[*] restored host Wi-Fi interface $AP_IFACE" >&2
  fi
  if [ -d "$OUT" ]; then
    chown -R "${SUDO_UID:-$(id -u)}:${SUDO_GID:-$(id -g)}" "$OUT" 2>/dev/null || true
  fi
}

if [ "$AP_REQUESTED" = 1 ]; then
  if [ "$(id -u)" -ne 0 ]; then
    echo "AP setup needs host root: NetworkManager and rfkill must release the adapter." >&2
    echo "Run it with sudo:" >&2
    echo "  sudo ./blueair-cloudcutter.sh $*" >&2
    exit 1
  fi
  [ -n "$AP_IFACE" ] || AP_IFACE="$(pick_wireless || true)"
  if [ -z "$AP_IFACE" ]; then
    echo "No wireless interface found; pass --iface." >&2
    exit 1
  fi

  UPSTREAM="$(ip route show default 2>/dev/null | awk '/default/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
  if [ -n "$UPSTREAM" ] && [ "$UPSTREAM" = "$AP_IFACE" ]; then
    echo "$AP_IFACE is the default route. Use Ethernet for the uplink before starting the AP." >&2
    exit 1
  fi

  if have_nmcli; then
    PREV_STATE="$(nmcli -t -f DEVICE,STATE device status 2>/dev/null | awk -F: -v d="$AP_IFACE" '$1==d {print $2; exit}' || true)"
    PREV_CONN="$(nmcli -g GENERAL.CONNECTION device show "$AP_IFACE" 2>/dev/null || true)"
  fi
  if command -v rfkill >/dev/null 2>&1 && rfkill list wifi 2>/dev/null | grep -q "Soft blocked: yes"; then
    RFKILL_BLOCKED=1
  fi

  trap cleanup_host EXIT
  trap 'cleanup_host; exit 130' INT TERM

  if have_nmcli; then
    nmcli device disconnect "$AP_IFACE" >/dev/null 2>&1 || true
    nmcli device set "$AP_IFACE" managed no >/dev/null 2>&1 || true
  else
    echo "[!] NetworkManager is not running; using iw/ip directly for $AP_IFACE" >&2
  fi
  command -v rfkill >/dev/null 2>&1 && rfkill unblock wifi >/dev/null 2>&1 || true
  command -v iw >/dev/null 2>&1 && iw dev "$AP_IFACE" disconnect >/dev/null 2>&1 || true
  echo "[*] released host Wi-Fi interface $AP_IFACE for the AP"
  AP_RUN_ARGS=(--pid=host)

  if [ -z "$(get_opt --iface "$@" || true)" ]; then
    RUN_ARGS+=(--iface "$AP_IFACE")
  fi
fi

DBUS_ARGS=()
if [ -S /run/dbus/system_bus_socket ]; then
  DBUS_ARGS=(-v /run/dbus:/run/dbus)
fi

AVAHI_ARGS=()
if [ -S /run/avahi-daemon/socket ]; then
  AVAHI_ARGS=(-v /run/avahi-daemon:/run/avahi-daemon)
fi

# Under sudo, HOME is root's; the AWS profile usually lives in the invoking user's.
AWS_HOME="$HOME"
if [ -n "${SUDO_USER:-}" ] && command -v getent >/dev/null 2>&1; then
  SUDO_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  [ -n "$SUDO_HOME" ] && AWS_HOME="$SUDO_HOME"
fi
mkdir -p "$AWS_HOME/.aws" 2>/dev/null || true
if [ -d "$AWS_HOME/.aws" ]; then
  if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_UID:-}" ]; then
    chown "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$AWS_HOME/.aws" 2>/dev/null || true
  fi
  # Read-write: `aws login` writes the standard credentials file here.
  AWS_ARGS=(-v "$AWS_HOME/.aws:/root/.aws")
fi

if "$ENGINE" run --rm -it \
  --privileged --network host \
  "${USER_ARGS[@]}" \
  "${AP_RUN_ARGS[@]}" \
  "${FIRMWARES_MOUNTS[@]}" \
  "${ADD_HOSTS[@]}" \
  "${DBUS_ARGS[@]}" \
  "${AVAHI_ARGS[@]}" \
  "${AWS_ARGS[@]}" \
  -e AWS_PROFILE -e AWS_REGION -e AWS_DEFAULT_REGION \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN \
  -v "$OUT:/output" \
  -e HOST_UID="$HOST_UID" \
  -e HOST_GID="$HOST_GID" \
  -e BLUEAIR_CLOUDCUTTER_IFACE="$AP_IFACE" \
  "$IMAGE" "${RUN_ARGS[@]}"; then
  STATUS=0
else
  STATUS=$?
fi

cleanup_host
exit "$STATUS"
