# Troubleshooting

## Ports and firewall

The AP runs on this machine, but the device's traffic crosses the host firewall
and NAT. A container with `--network host` does not bypass the host firewall.

Device to this machine, input on the AP interface:

| port | proto | purpose | when |
|---|---|---|---|
| 67 | UDP | DHCP (dnsmasq) | always; must be free |
| 443 | TCP | fake provisioning API | default |
| 8000 | TCP | fake provisioning API fallback | when 443 is taken |
| 8443 | TCP | factory server | firmware route |
| 8883 | TCP | local broker | local-control route |

Device to the internet, forwarded through this machine:

| port | proto | purpose |
|---|---|---|
| 53 | UDP | DNS |
| 123 | UDP | NTP |
| 443 | TCP | BlueAir API, if you do not use the fake API |
| 8883 | TCP | AWS IoT endpoint, where the certificate is captured |

The exploit adds NAT and hands out the uplink router as DNS.
`blueair-cloudcutter helpers serve network` does not add NAT. It can run its own
dnsmasq or hand out the uplink router, but you must add the NAT rules yourself.

### NixOS

The AP subnet is `192.168.50.0/24`. The common `ip saddr 192.168.0.0/24` rule
does not cover it.

```nix
networking.firewall.interfaces.wld0 = {
  allowedUDPPorts = [ 53 67 ];
  allowedTCPPorts = [ 53 443 8000 8443 8883 ];
};

# Only if forwarded AP traffic is dropped by the reverse-path chain:
networking.firewall.checkReversePath = false;
```

Temporary rules:

```bash
sudo nft add rule inet nixos-fw input-allow iifname "wld0" udp dport 67 accept
sudo nft add rule inet nixos-fw input-allow iifname "wld0" \
  tcp dport { 443, 8000, 8443, 8883 } accept
sudo nft insert rule inet nixos-fw rpfilter iifname "wld0" accept
```

Remove them with `nft -a list chain ...` and `nft delete rule ... handle N`.
Runtime rules do not survive a reboot. `iptables` is usually not installed on
NixOS; use `nft`.

The rules above are for the AP interface. For the local broker, factory server
and BLE fake API on the normal LAN, use the LAN interface instead. Find it with
`ip route get 1.1.1.1` and take the `dev` value (`eth0`, `end0`, `enp1s0`, ...):

```bash
sudo nft add rule inet nixos-fw input-allow \
  iifname "eth0" tcp dport { 8000, 8443, 8883 } accept
```

For a permanent rule:

```nix
networking.firewall.interfaces.eth0.allowedTCPPorts = [ 8000 8443 8883 ];
```

The BLE fake API uses 8000 by default. If the broker runs on the same host, the
device reaches 8883 on the LAN. The factory server uses 8443.

### Port conflicts

| port | usual owner | fix |
|---|---|---|
| 53 | AdGuard Home, systemd-resolved | not needed by default; dnsmasq runs with `port=0` and DHCP hands out the router |
| 67 | AdGuard DHCP or a stale dnsmasq | must be freed; disable AdGuard DHCP or stop the stale process |
| 443 | another web UI | the fake API falls back to 8000; open 8000 on the AP interface |
| 5353 | Avahi/mDNS | not used by the exploit |
| 8443, 8883 | another server or broker | free them before the factory or broker step |

`doctor` prints these checks. `udp/53` being occupied is informational.
`udp/67` is a hard requirement.

## Local control

### The device is offline after `--onboard-only`

The device is left on the temporary `BlueAirCloudCutter` AP, which stops when the
command exits. Run local control or firmware with `--ssid` and `--password`. The
tool moves the device to that Wi-Fi over BLE before the next step. Reboot it
first: the reboot clears the BLE provisioning flags, and a device in factory
mode also needs it to return to normal mode where BLE is available.

### scp cannot read `output/mqtt/broker.key`

The key is mode 0600. If the command ran under sudo and did not hand ownership
back, it is root-owned. Fix the ownership on the machine that created the
bundle, then copy it:

```bash
sudo chown -R "$USER:$USER" ~/blueair-cloudcutter/output/mqtt
scp <user>@<host>:~/blueair-cloudcutter/output/mqtt/broker.key ./mqtt_bundle/mqtt/
```

The CLI now chowns `output/` back to the invoking user after a sudo run. The
wrapper does the same on exit.

### The MQTT client connects, but there is no config reply

A client connection to AWS does not mean the device is connected. The tool now
logs the publish topic and fails fast if the broker does not acknowledge it:

```text
[*] MQTT publish d/<did>/c/read
```

If that line appears and the reply still times out, the publish reached AWS but
the device is not subscribed to it. In CloudWatch, filter for
`"eventType":"Publish-In"` and the tool's `clientId`
(`blueair-cloudcutter-...`). If the publish is there, check the device side:

- it is on the temporary `BlueAirCloudCutter` AP, which is gone after `--onboard-only`
- it is in factory mode, which has no BLE and no broker connection
- it is on a local broker after an earlier local-control run
- `output/aws.json` has the wrong DID or endpoint

The device's own Connect event has a different principal and client ID. If it is
missing from the same time window, the device is not on that endpoint.

### The broker exits with `Unable to load server key file`

`output/mqtt/broker.key` is mode 0600. If mosquitto starts as root it binds
8883 and then drops to the `mosquitto` user, which cannot read a key owned by
root, so it exits right after opening the port.

The wrapper runs `helpers serve broker` as the invoking user, so the daemon
never drops privileges and reads the key it owns. Keep using the wrapper. If
you start mosquitto by hand, run it as the user that owns `output/mqtt`, not as
root. Do not fix this by making the key world-readable.

`serve broker` echoes mosquitto's log to the terminal and appends it to
`output/logs/mosquitto.log`. A device connection shows up as
`New client connected from <ip> as <did>`. If mosquitto exits, the command
exits with its code instead of sleeping.

### The device does not connect to my broker

- The broker certificate must chain to the CA planted in `db.c-r`. If you
  passed `--broker-ca`, that is the CA. If you did not, it is
  `output/materials/ca.pem`, copied to `output/mqtt/ca.pem`.
- The certificate SAN must match the hostname the device dials. Use a DNS name,
  not an IP. The name must resolve on the device's network after it joins your
  Wi-Fi.
- Keep the broker running before the device reconnects. The exploit does not
  start or stop it.
- `c-r` is the active anchor. `c-r2` has no effect on 1.0.6. Restore the stock
  root with `blueair-cloudcutter helpers liberate --restore-roots`.
- The exploit cannot verify the connection. Check the broker log and the device
  UART log.

### Restore the stock root

The stock Amazon Root CA 1 is bundled with the tool. Write it back over the
broker the device is connected to:

```bash
blueair-cloudcutter helpers liberate --restore-roots \
  --transport mqtt \
  --broker raspberrypi.local \
  --ca output/mqtt/ca.pem \
  --did <uuid>
```

`--ca` verifies the local broker while the write is in flight. The write needs
the device online on that broker; the tool now waits for the config reply and
requires the ack, so a silent timeout is an error instead of a false success.

If the device is in factory mode instead, use the default HTTP transport:

```bash
blueair-cloudcutter helpers liberate --restore-roots --ip <device-ip> --did <uuid>
```

Restoring `c-r` does not change the broker URL stored on the device. After the
next reconnect it trusts AWS again but still dials the old local broker and
fails TLS, so re-onboard or send a new `ConfigCmd` with the AWS endpoint. The
command also clears the `steps.liberate` marker in `output/state.json`; leave
that file alone so the next local-control run does not skip the AWS write.

### `c-r` is gone after a factory reset

A factory reset does not undo `c-r`, `c-d` or `k-jwt`. If the device no longer
trusts the broker, check that the reset really happened and that you planted the
CA on the right device. Restore the stock root or reflash your dump.

### Re-running local control after the CA was planted

A successful c-r write is recorded in `output/state.json` under
`steps.liberate`. A re-run with the same `--local-broker` skips the AWS write
and the pre-step Wi-Fi move, then asks for the reboot and provisions the device
to the local broker. That is the recovery when a run stopped after
`db.c-r written`.

The marker is local state, not a device query. `db.c-r` is write-only. If you
restored the device, changed the CA or broker, or copied `output/` from another
machine, delete `output/state.json` so the tool does not trust a stale marker.

If the device already left AWS, the AWS plant cannot work. Do the BLE step
directly:

```bash
(cd output/mqtt && ./start.sh)
blueair-cloudcutter helpers ble provision \
  --broker <broker-name> --ssid "MyWiFi" --password "..."
```

Or use `blueair-cloudcutter helpers liberate --transport mqtt --broker
<your-broker>`, or the factory route.

### I have no DNS name for the broker

The device needs a name for TLS. Add a DNS record on your router or local DNS
server for the name you pass to `--local-broker`, pointing at the broker. Do
not use an IP, even if the broker listens on one.

## Firmware

### `MCU buff is too small!` never appears, and the device reboots

The arm was lost. Check:

- the manifest's STM32 `size` is non-zero; the tool uses 1024,
- `--pad` exceeds `1048832`; the tool uses `1048832 + 8192`,
- the padding is declared in `Content-Length` and not sent.

### The arm says `Remote end closed connection without response`

That is the expected MCU-size bail. The handler returns `-1` without writing an
HTTP response. The tool waits `--settle` seconds and probes 443. If the device
is still up, the arm is intact and the swap continues. If 443 is gone, the
device rebooted and the arm is lost.

### Phase 2 returns 200

The unsigned image was accepted, which should not happen. Do not reboot.
Investigate first. The tool aborts.

### `Error opening partition` or `ESP32 image size 2147483647`

The manifest `size` was clamped by cJSON because it was sent as a large positive
number. Send a negative number. The usable range is `[-4095, -2]`; the tool uses
`-2`.

### `Error, WiFi fw doesn't match hw!`

The manifest image name must contain the device family from `di.hw`: `nb` for
`nb_l_1.0` and `nb_m_1.0`. The tool derives `ba_<family>_wifi.bin` and falls
back to `ba_nb_wifi.bin`. Override it with `blueair-cloudcutter helpers flash --image-name`. The
value is a manifest label and multipart filename, not a file on disk. The
16-byte header is a build constant; override it with `blueair-cloudcutter helpers flash --header16`
if the board is not a G4 `nb` board.

### `esp_ota_end` fails and the boot pointer does not move

The passive slot did not contain a valid signed image. The device has never
taken an official OTA, or something erased the slot. Pass
`blueair-cloudcutter helpers flash --official <signed image>`.

### The firmware does not survive a reboot

The image boots in `PENDING_VERIFY`. It must call
`esp_ota_mark_app_valid_cancel_rollback()`, or the next reboot rolls back.

## Factory mode

### No hello after the NVS wipe

- Power-cycle the device after `erase-region`.
- It joins `BAFactory` with the compiled-in PSK, not your home Wi-Fi.
- DNS must resolve `factoryserver.blueair` to the machine running
  `blueair-cloudcutter helpers serve factory`.
- Port 8443 must be reachable.
- If the device still validates TLS, `c-r` was not wiped. `blueair-cloudcutter helpers serve
  factory --no-tls` is a last resort after checking the UART log.

### Factory mode stays in `Fact-STA-off` and 443 never opens

The device waits for NTP before it leaves `Fact-STA-off` and starts the factory
HTTPS server. UART shows:

```text
StateMgr: Device starting in FACTORY MODE
StateMgr/Fact-STA-off: Enter
WiFi/STA wait time: Setting up the NTP client
```

It must later print:

```text
WiFi/STA wait time: Got time from NTP
StateMgr/Fact-STA-on: Enter
esp_https_server: Server listening on port 443
```

If it loops on `pool.ntp.org`, the AP has no working DNS or no route to the
internet. Use the exploit, which adds NAT and hands out the uplink router as
DNS, or add NAT manually:

```bash
sudo ./blueair-cloudcutter.sh helpers serve network --iface wld0 \
  --ssid BlueAirCloudCutter --psk blueaircutter \
  --dhcp-dns 192.168.0.1 --start
```

Then add masquerade and forward rules for `192.168.50.0/24` to the uplink.

### `ble provision` associates but dnsmasq sees no DHCP on NixOS

`output/logs/hostapd.log` shows `AP-STA-CONNECTED` and
`EAPOL-4WAY-HS-COMPLETED`, then `AP-STA-DISCONNECTED`. `dnsmasq.log` has no
`DHCPDISCOVER`. The PSK is fine; the host firewall filtered DHCP.

The container uses `--network host`, so the host nftables input chain applies.
NixOS does not open UDP 67 for a DHCP server by default:

```bash
sudo nft add rule inet nixos-fw input-allow iifname "wld0" udp dport 67 accept
```

If DNS or TLS from the AP subnet is still dropped, bypass reverse-path checking
for that interface:

```bash
sudo nft insert rule inet nixos-fw rpfilter iifname "wld0" accept
```

## BLE

### `blueair-cloudcutter helpers ble scan` finds nothing

- BLE is on in normal mode, whether or not the device is provisioned. It is off
  only in factory mode. If the device is in factory mode, reboot it to return
  to normal mode.
- Reboot after any BLE or config operation. Provisioning flags from the previous
  session can keep the next BLE command from being accepted, even in normal mode.
- On macOS, grant Bluetooth permission to the terminal app.
- On Linux, `bluetoothd` must run and the user must reach D-Bus. Try
  `bluetoothctl list`.
- In Docker, mount `/var/run/dbus` and use host networking. The wrapper does
  both.
- If the device is listed without `*`, pass its address:
  `blueair-cloudcutter helpers ble provision --address <value> ...`

### BLE connects but characteristics are missing

The device is not exposing the provisioning interface, or another client is
connected. Disconnect the phone app, reboot the purifier and retry.

### `ble provision` reports a Wi-Fi apply error

Wi-Fi apply errors are common on this firmware. Reboot the purifier and retry.
The device supports only 2.4 GHz networks.

### `ble factory` gets no acknowledgement

`FactoryCmd` can reboot the device before the response is readable. Check the
UART log, or run `blueair-cloudcutter helpers ble scan` again after a few seconds. If the device is
in factory mode, `blueair-cloudcutter helpers serve factory` should receive a hello.

## AWS

### `aws check` fails

- No credentials: run `blueair-cloudcutter aws login`, or set `AWS_PROFILE` or SSO.
- `AccessDenied`: create and attach `deploy/operator-policy.json`.
- Wrong region: pass `--region`. The endpoint and certificates live in a region.

### `capture` sees no certificate

- `capture` needs root or `CAP_NET_RAW`, and the AP or a monitor interface on
  the device's channel.
- The device must dial the real AWS IoT endpoint on 8883.
- If the device is already connected to your AWS, the handshake is over. Reboot
  it and capture the next connection.
- Only TLS 1.2 exposes the client certificate. The device uses TLS 1.2 for AWS
  IoT.

### I do not have an AP, or prefer not to use one

Capture the certificate with Wireshark on a laptop hotspot or with `tcpdump` on
a router, then pass it to the exploit:

```bash
sudo ./blueair-cloudcutter.sh exploit --device-cert output/device.pem \
  --ssid "MyWiFi" --password "..."
```

This skips the AP and packet capture. Bluetooth is still needed to move the
device to your Wi-Fi and AWS endpoint, and the DID is still learned over MQTT.
Put the certificate under `output/` when using the Docker wrapper. The capture
steps and the manual route are in
[`client-certificate.md`](client-certificate.md).

If the device is already on your endpoint, add `--skip-wifi-setup`. If the DID
is not learned, the device has not connected to the AWS endpoint with the
registered certificate. Reboot it and rerun.

### `aws discover` sees no message

- The device certificate must be registered and active.
- Reboot the device so it connects and publishes its boot message.
- The control identity uses the wildcard policy from `aws onboard`. If you
  scoped it, allow the boot topic and `d/<did>/#`.

### `blueair-cloudcutter helpers liberate --transport mqtt` fails

- `output/aws.json` must exist, or pass `--broker`, `--cert`, `--key` and
  `--did`.
- Pass `--local-broker` so the generated broker certificate SAN matches the
  name the device dials.
- `c-r` is the active anchor. `c-r2` has no effect on 1.0.6.

## Config reads and writes

### `configuration/get` returns 405

The endpoint is POST, not GET. `blueair-cloudcutter helpers mqtt --transport factory read` uses
POST. A manual `curl` needs `-X POST -d '{"t":"State"}'`.

### `configuration/get` returns 401, or the JWT is rejected

- If `k-jwt` is present, the token must be signed by the matching key. Run
  `blueair-cloudcutter helpers materials init` and use the generated `kjwt.key`.
- If `k-jwt` is absent after an NVS wipe, any three-part JWT is accepted.

### `c/prov` replies 409

`_cas` does not match the live `_v`. Re-read, then write. The reply contains the
current version. The tool does this automatically.

### A write returns 200 but the field did not change

`_t: "Partial"` is accepted but writes nothing. Use `_t: "Diff"`. The tool
always uses `Diff`.

### A Full config read takes forever

That is normal, about a minute. `State` is instant. The tool waits 15 seconds
for State/Diff and up to 90 seconds for Full.

## Docker and Podman

### `operation not permitted` when mounting `output/`

Docker Desktop on macOS only shares certain host directories. Add the project
folder under Settings, Resources, File sharing.

### Rootless Docker cannot start the AP

Rootless containers cannot grant capabilities over the host network namespace.
Run the command as root with a rootful engine. `--cap-add` does not help.

### BLE fails in a rootless container with `REJECTED: ['EXTERNAL']`

The container root maps to your host uid, so the uid in D-Bus `AUTH EXTERNAL`
does not match `SO_PEERCRED`. The package sets `BLEAK_DBUS_AUTH_UID=-1` on
import; bleak 0.20+ then omits the uid, which is valid D-Bus. If you overrode
that variable, unset it.
