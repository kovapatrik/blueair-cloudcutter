# Instructions

This is the step-by-step guide for tool. The [README](README.md) is the
overview, and the manual routes and recovery commands are in
[`docs/manual.md`](docs/manual.md).

> [!WARNING]
> Using BlueAir CloudCutter detaches the purifier from BlueAir's cloud. Local
> control replaces the broker trust anchor but keeps the stock firmware. Custom
> firmware replaces the stock firmware, and you cannot go back without a flash
> dump taken over UART before flashing. Read the whole page before you start.

## What you need

- A Linux machine with Docker installed. If you already captured the device
  certificate, skip the AP entirely with `--device-cert`; see
  [`docs/client-certificate.md`](docs/client-certificate.md).
- A Wi-Fi adapter dedicated to the provisioning AP. It must not be the interface
  that carries your default route, because the tool moves it into AP mode and
  NATs the purifier through your uplink. An Ethernet uplink is recommended. The
  adapter is not needed when you pass `--device-cert`.
- A Bluetooth adapter on the machine, or a Linux host for the Docker container.
- An AWS account. A personal account is fine; you do not need an organization.
- The purifier in normal mode, where BLE provisioning is enabled. A factory
  reset puts it back in that state. Factory mode has no BLE.
- For local control: a broker hostname the purifier can resolve after it joins
  your Wi-Fi, and a certificate valid for that name. The tool can generate both.
- For custom firmware: a UART flash dump if you ever want the stock image back,
  and a device that has already taken an official OTA.

## 1. Install

```bash
git clone https://github.com/kovapatrik/blueair-cloudcutter
cd blueair-cloudcutter
sudo ./blueair-cloudcutter.sh doctor
```

Docker is required. The wrapper pulls the image, or builds it from the checkout
when needed. The image ships `mosquitto`, `hostapd`, `dnsmasq`, `bleak`,
`boto3` and `scapy`.

With one wireless interface the wrapper picks it automatically. With several, it
asks or accepts `--iface`.

Docker on macOS cannot pass a host Wi-Fi or Bluetooth adapter, so use a Linux
host for the hardware steps.

## 2. Log in to AWS once

The tool creates the IoT policy, thing and certificates in your account. You
need the browser console once; no AWS CLI setup is required.

```bash
./blueair-cloudcutter.sh aws guide     # prints the steps and the CloudShell URL
./blueair-cloudcutter.sh aws login     # paste the setup code
```

In CloudShell, run the command that `aws guide` prints:

```bash
curl -fsSL https://raw.githubusercontent.com/kovapatrik/blueair-cloudcutter/main/scripts/aws-bootstrap.sh | bash
```

The script creates the `blueair-cloudcutter` IAM user, attaches the
`BlueAirCloudCutterOperator` policy, creates one access key, and prints a setup
code. `aws login` validates the code with STS and writes
`~/.aws/credentials` with mode 0600.

If your principal gets `AccessDenied`, create the managed policy from
[`deploy/operator-policy.json`](deploy/operator-policy.json) and attach it:

```bash
aws iam create-policy --policy-name BlueAirCloudCutterOperator \
  --policy-document file://deploy/operator-policy.json
```

If your organization uses IAM Identity Center, run
`./blueair-cloudcutter.sh aws login --sso` instead. Existing AWS profiles and
the usual environment variables also work.

## 3. Run the guided exploit

```bash
sudo ./blueair-cloudcutter.sh
```

With no arguments the wrapper picks a wireless interface, starts the container
and runs the guided exploit. It:

1. starts the `BlueAirCloudCutter` provisioning AP;
2. scans for the purifier over BLE and provisions it through the AP;
3. captures its client certificate from the TLS handshake;
4. registers it in your AWS account and learns its device ID (DID);
5. asks what you want to do next.

Answer the prompts:

| Prompt | What to enter |
|---|---|
| AP interface | The spare Wi-Fi adapter, for example `wld0`. The wrapper fills this in when it can. |
| What should happen after onboarding? | `1` local control, `2` custom firmware, `3` onboard only. |
| Broker hostname | Local control only. A DNS name, not an IP. |
| Home Wi-Fi SSID / password | The network the purifier should join after onboarding. |
| Reboot prompt | Power-cycle the purifier, wait until it is back in normal mode, then press Enter. |

Keep the purifier powered and close to the machine. Do not interrupt the first
run; it saves progress in `output/`, so a rerun resumes where it stopped.

### Skip the AP with a captured certificate

The AP exists only to capture the device's public client certificate from its
TLS handshake. If you already have that certificate, pass it and the tool skips
the AP and packet capture:

```bash
sudo ./blueair-cloudcutter.sh exploit --device-cert output/device.pem \
  --ssid "MyWiFi" --password "..."
```

The tool still registers the certificate in your AWS account and learns the DID
over MQTT, because the DID is only published on the broker. It moves the device
directly to your Wi-Fi and AWS endpoint over BLE. If the device is already
there, add `--skip-wifi-setup`.

PEM and DER are both accepted, so a raw Wireshark `.der` export works too. The
capture methods and the manual route are in
[`docs/client-certificate.md`](docs/client-certificate.md).

## 4. Local control

Local control keeps the stock firmware and moves the device to a broker you
run. The device validates the broker certificate against the root CA in
`db.c-r`; the tool plants your CA there, asks you to reboot the device, and then
provisions it back to your Wi-Fi and broker.

```bash
sudo ./blueair-cloudcutter.sh exploit --local-control \
  --local-broker broker.home --broker-ca output/my-broker-ca.pem \
  --ssid "MyWiFi" --password "..."
```

`--local-broker` is the DNS name the purifier dials. Use a name, not an IP: the
device needs a name for TLS. It must resolve on the device's network after it
joins your Wi-Fi, and the broker certificate must be valid for that name.

`--broker-ca` is the CA that signed your broker certificate. If you omit it, the
tool generates a CA and a broker certificate in `output/mqtt/` and plants that
CA instead. The folder is self-contained:

```bash
(cd output/mqtt && ./start.sh)
```

The generated broker allows anonymous clients and serves TLS on 8883. Add a DNS
record for the hostname you passed, pointing at the machine that runs the
broker.

The Docker wrapper only passes project files from `output/` and `firmwares/`.
Put the CA file under `output/`.

The tool cannot verify that the device connected. It prints the broker name it
provisioned and stops.

## 5. Custom firmware

The custom route writes an unsigned image into the passive OTA slot through the
factory HTTPS endpoint. Secure boot is off, so the bootloader runs it after the
reboot. The full exploit chain is in [`WRITEUP.md`](WRITEUP.md); you do not need
to understand it to use the tool.

Copy the image into `firmwares/` first. The container mounts that folder
read-only at `/firmwares`, so pass only the filename:

```bash
cp ~/Downloads/app.bin firmwares/
sudo ./blueair-cloudcutter.sh exploit --firmware app.bin \
  --ssid "MyWiFi" --password "..."
```

The exploit moves the device to your Wi-Fi first, plants the factory JWT over
MQTT, asks you to reboot the purifier to clear the BLE provisioning flags (this
is required every run, even when the device is already in normal mode), sends
`FactoryCmd`, serves the factory hello, and flashes through `provision/image`.
The factory server runs on this machine's LAN IP, so `--iface` is not needed
when the device is already onboarded.

The image boots in `PENDING_VERIFY`. It must call
`esp_ota_mark_app_valid_cancel_rollback()`, or the next reboot rolls back to the
signed slot.

After local control the device no longer trusts AWS. Pass `--local-broker` (and
`--broker-ca` if you used your own CA) to the firmware run so the exploit plants
the JWT over your broker instead. That assumes the broker allows anonymous
publish. If it requires a client certificate, use
`helpers mqtt plant-kjwt --ca ... --cert ... --key ...` and the manual factory
and flash helpers in [`docs/manual.md`](docs/manual.md).

### If the passive slot has no signed image

The factory chain expects a vendor-signed image in the passive slot. If the
device has never taken an official OTA, pass one with `--official`:

```bash
sudo ./blueair-cloudcutter.sh helpers flash --ip 192.168.1.50 --did <uuid> \
  --custom app.bin --official official-app.bin
```

### Restore the official image

Pass only `--official` to restore the official image and stop there. It is a
normal signed OTA upload with no STM32 manifest entry, so it does not flash or
suspend the MCU. It writes the signed image into the passive slot and reboots;
the running slot is already official, so both OTA slots end up signed:

```bash
sudo ./blueair-cloudcutter.sh helpers flash --ip <ip> --did <uuid> \
  --official blueair-1.0.6.ota.bin
```

Restoring the image does not undo `db.c-r`, `db.c-d`, `db.k-jwt` or factory
mode. `helpers liberate --restore-roots` writes the stock `c-r` back. For the
others, restore the values from your dump or reflash the stock image; see the
reset section in [`docs/manual.md`](docs/manual.md#reset-to-a-start-state).

## 6. Other ways to run it

Pass the goal explicitly instead of answering the menu:

```bash
sudo ./blueair-cloudcutter.sh exploit --local-control --ssid "MyWiFi" --password "..."
sudo ./blueair-cloudcutter.sh exploit --firmware app.bin --ssid "MyWiFi" --password "..."
sudo ./blueair-cloudcutter.sh exploit --onboard-only
```

`--iface` is only needed when the tool has to start the provisioning AP, which
means a new device that still needs onboarding and certificate capture. It is
not needed with `--device-cert`. After that, local control and firmware move the
device to your normal Wi-Fi over BLE, so `--ssid` and `--password` are required
for both routes. If the device is already onboarded, omit `--iface`.

With the normal capture flow, `--onboard-only` stops before the device is moved
to your Wi-Fi. It is left on the temporary `BlueAirCloudCutter` AP, which goes
away when the command exits. To continue later, run local control or firmware
with `--ssid` and `--password`; that flow moves the device to your Wi-Fi first.

With `--device-cert`, `--onboard-only` moves the device to your Wi-Fi and AWS
endpoint first, because the DID is learned over MQTT. Add `--skip-wifi-setup` if
the device is already there.

Local control and firmware move the device over BLE before the next step. If it
is already on that Wi-Fi, pass `--skip-wifi-setup` to skip the move. The SSID and
password are still used after the local-control reboot and in the firmware
`FactoryCmd`.

Multiple purifiers are stored separately. This lists them and picks one:

```bash
./blueair-cloudcutter.sh aws devices
sudo ./blueair-cloudcutter.sh exploit --device 2 --local-control \
  --ssid "MyWiFi" --password "..."
```

`--device` accepts a DID, certificate ID, BLE address or list index. `--did`
accepts the UUID. Without a selector, the exploit uses the only device or asks.

## If something goes wrong

- Run `sudo ./blueair-cloudcutter.sh doctor` to check wireless interfaces,
  Bluetooth access, ports and the AP tools.
- Logs are under `output/logs/`. `output/cleanup.sh` undoes the AP and NAT
  changes; the wrapper runs it even when the container was killed.
- Rerun the same command after a failure. Existing onboarding and the known DID
  are reused, and `output/state.json` records completed steps.
- If the purifier does not appear over BLE, reboot it and rerun. A device left in
  factory mode has no BLE; factory reset it.
- If the device did not join your Wi-Fi, check the SSID and password. If it is
  already on that network, use `--skip-wifi-setup`.
- See [`docs/troubleshooting.md`](docs/troubleshooting.md) for ports, firewall
  rules, Docker/Podman and BLE issues.
- See [`docs/manual.md`](docs/manual.md) for the individual helpers, factory mode
  without BLE and recovery. UART backup and restore are in
  [`docs/flash-access.md`](docs/flash-access.md).

Keep `output/` private. It contains the control keys that can publish to your
devices.
