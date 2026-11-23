# Manual routes and recovery

The exploit is the normal path. Use these commands when it cannot finish, or
when you want to run one step yourself.

## Command map

Old command | New command
---|---
`blueair-cloudcutter ble ...` | `blueair-cloudcutter helpers ble ...`
`blueair-cloudcutter capture ...` | `blueair-cloudcutter helpers capture ...`
`blueair-cloudcutter flash ...` | `blueair-cloudcutter helpers flash ...`
`blueair-cloudcutter liberate ...` | `blueair-cloudcutter helpers liberate ...`
`blueair-cloudcutter mqtt ...` | `blueair-cloudcutter helpers mqtt ...`
`blueair-cloudcutter serve ...` | `blueair-cloudcutter helpers serve ...`
`blueair-cloudcutter materials ...` | `blueair-cloudcutter helpers materials ...`
`blueair-cloudcutter config get|set` | `blueair-cloudcutter helpers mqtt --transport factory read|write`
`blueair-cloudcutter aws ...` | unchanged
`blueair-cloudcutter doctor` | unchanged
`blueair-cloudcutter menu` | removed; run `blueair-cloudcutter` for the guided exploit

## Old exploit flags

Flag | Replacement
---|---
`--no-ap` | No flag. The exploit starts the AP when it needs one. Use `blueair-cloudcutter helpers serve network` and `blueair-cloudcutter helpers ble` if you already have an AP.
`--no-provision` | Automatic when the device record has a DID. Pass `--reprovision` to force BLE provisioning.
`--device-cert PATH` | Supported again: `blueair-cloudcutter exploit --device-cert PATH` skips the AP and capture. The manual route is `blueair-cloudcutter aws onboard --device-cert PATH`, then provision and `aws discover`. See [`client-certificate.md`](client-certificate.md).
`--scan-timeout`, `--capture-timeout`, `--discover-timeout` | Defaults. The helper commands have their own timeouts.
`--thing`, `--policy`, `--control-name` | `blueair-cloudcutter aws onboard --thing ... --policy ... --control-name ...`
`--api`, `--auth` | `blueair-cloudcutter helpers ble provision --api ... --auth ...`, with `blueair-cloudcutter helpers serve fake-api` if you want the server to outlive the command.
`--no-fake-api`, `--fake-api-port`, `--fake-api-wait` | `blueair-cloudcutter helpers ble provision` flags.
`--kjwt-broker`, `--kjwt-port`, `--kjwt-ca` | `--local-broker` and `--broker-ca`, or `blueair-cloudcutter helpers mqtt plant-kjwt`.
`--skip-kjwt-plant` | `blueair-cloudcutter helpers mqtt plant-kjwt`, then the factory and flash helpers.
`--factory-ip`, `--factory-port`, `--factory-no-tls`, `--factory-wait`, `--factory-hello-timeout` | `blueair-cloudcutter helpers serve factory`, `blueair-cloudcutter helpers ble factory`, `blueair-cloudcutter helpers flash --ip`.
`--fw-version`, `--image-name`, `--header16` | `blueair-cloudcutter helpers flash` flags.
`--no-nat`, `--upstream` | No flag. The exploit always NATs. `blueair-cloudcutter helpers serve network` starts the AP without NAT; add masquerade and forward rules yourself.
`--dhcp-dns`, `--country` | `blueair-cloudcutter helpers serve network` flags.
`--pause`, `--no-pause` | Removed. The exploit prompts when it needs Enter.
`--wifi-events` | `blueair-cloudcutter helpers ble events`, or `blueair-cloudcutter helpers ble provision` without the flag.

## Preconditions

`blueair-cloudcutter helpers ble provision`

- The purifier is in normal mode. BLE provisioning is on by default; it is off
  only in factory mode.
- The host has a Bluetooth adapter and permission to use it.
- On Linux, `bluetoothd` runs and D-Bus is reachable.
- For a local broker, its CA must already be in `db.c-r`.

`blueair-cloudcutter helpers ble factory`

- The purifier was rebooted after the last BLE/config operation. The reboot
  clears the BLE provisioning flags, and a stale flag stops the next
  `FactoryCmd`; do this even when the device is already in normal mode.
- The purifier is in normal mode, so BLE is available to receive `FactoryCmd`.
  Factory mode itself has no BLE.
- `db.k-jwt` is your key from `blueair-cloudcutter helpers materials init`, or absent after an NVS
  wipe. Another key rejects the token.
- A factory server is reachable at the URL you pass.

`blueair-cloudcutter helpers liberate --transport factory`

- The device is in factory mode, so its HTTPS server listens on 443.
- You know its LAN IP and DID.
- The broker certificate chains to the CA being planted, and its SAN matches the
  name the device dials.

`blueair-cloudcutter helpers liberate --transport mqtt`

- The device is connected to a broker you can publish on.
- You have a client identity with publish and subscribe on `d/<did>/#`.

`blueair-cloudcutter helpers flash`

- Factory mode, device IP and DID.
- The passive OTA slot holds a signed image, or you pass `--official`.
- The custom image starts with `0xE9`.

## Onboarding with a captured certificate

If you captured the device's client certificate with Wireshark, a router or the
AP helper, the exploit can skip the AP and packet capture:

```bash
blueair-cloudcutter exploit --device-cert output/device.pem --onboard-only
```

It registers the certificate, moves the device to your Wi-Fi and AWS endpoint
over BLE, and learns the DID over MQTT. PEM and DER are both accepted. The
capture commands and the full explanation are in
[`client-certificate.md`](client-certificate.md).

Manual equivalent:

```bash
blueair-cloudcutter aws onboard --device-cert output/device.pem
blueair-cloudcutter aws show
blueair-cloudcutter helpers ble provision --broker <endpoint> --region <region> \
  --ssid "MyWiFi" --password "..."
blueair-cloudcutter aws discover --timeout 120
```

Skip the BLE step when the device already points at your endpoint.

## Manual local control

Factory transport. The device must be in factory mode. The helper plants the
generated CA from `output/materials/`, writes `output/mqtt/`, and sends
`provision/ssid`:

```bash
blueair-cloudcutter helpers materials init --san broker.home
blueair-cloudcutter helpers liberate --transport factory \
  --ip 192.168.1.50 --did <uuid> \
  --broker broker.home --broker-port 8883 \
  --ssid "MyWiFi" --wifi-password "..."
```

MQTT transport. The device is on a broker you can publish to, usually your AWS
IoT:

```bash
blueair-cloudcutter helpers liberate --transport mqtt --broker <current-broker> \
  --local-broker broker.home
```

This only plants the CA and writes the bundle. Point the device at the broker
with a BLE `ConfigCmd`, or bring it up in factory mode and run the factory
transport above.

The helper uses its own generated CA. To plant your existing broker's CA, use
the exploit with `--broker-ca`. The helper has no `--broker-ca` flag. The Docker
wrapper only mounts `output/` and `firmwares/`, so put the CA file under
`output/`.

Start the broker and control the device:

```bash
(cd output/mqtt && ./start.sh)
blueair-cloudcutter helpers mqtt control --broker broker.home --did <uuid> --actuator fsp0 --value 3
blueair-cloudcutter helpers mqtt control --broker broker.home --did <uuid> --actuator sb --value true --boolean
```

Restore the stock roots. On the broker the device is connected to:

```bash
blueair-cloudcutter helpers liberate --restore-roots --transport mqtt \
  --broker broker.home --ca output/mqtt/ca.pem --did <uuid>
```

In factory mode, over HTTPS:

```bash
blueair-cloudcutter helpers liberate --restore-roots --ip 192.168.1.50 --did <uuid>
```

## Manual firmware

Plant the factory JWT on the broker the device is on now:

```bash
blueair-cloudcutter helpers mqtt plant-kjwt --broker <current-broker> --did <uuid>
```

For a local broker, pass its CA, and a client certificate if it requires one:

```bash
blueair-cloudcutter helpers mqtt plant-kjwt --broker broker.home \
  --ca output/mqtt/ca.pem --cert client.pem --key client.key --did <uuid>
```

Put the device in factory mode. Start the factory server first, with a
certificate SAN matching the URL you will send:

```bash
blueair-cloudcutter helpers serve factory --cert-host 192.168.50.1
blueair-cloudcutter helpers ble factory --factory-url https://192.168.50.1:8443
```

Then flash:

```bash
blueair-cloudcutter helpers flash --ip <device-ip> --did <uuid> --custom app.bin
```

If the passive slot has no signed image, add
`--official official-app.bin`.

To restore the original firmware instead of installing a custom one, pass only
`--official`. That writes the signed image into the passive slot and reboots;
the slot that is already running stays official, so both OTA slots end up
holding a signed image:

```bash
blueair-cloudcutter helpers flash --ip <device-ip> --did <uuid> \
  --official blueair-1.0.6.ota.bin
```

The restore uploads only the ESP32 image; it does not add the STM32 manifest
entry, so it does not flash or suspend the MCU. The STM32 entry in the custom
flow exists only to keep the device up for the unsigned swap.

Restoring the image does not clear factory mode. Send `provision/ssid` (or
re-onboard) to set `fc.mode=0` and point the device back at your broker.

## Factory mode without BLE

The UART NVS wipe route is in [`flash-access.md`](flash-access.md). It erases
`certificates0`, which destroys the device's AWS identity. Use it only if you
have a dump.

After the wipe, the device falls back to `BAFactory` and
`factoryserver.blueair`. Bring up the AP and DNS:

```bash
blueair-cloudcutter helpers serve network --iface wld0 --ssid BAFactory \
  --psk 9102revreSyrotcaF --start
blueair-cloudcutter helpers serve factory
```

`serve network` does not add NAT. The device needs DNS and NTP before it starts
its factory HTTPS server. Add masquerade and forward rules for
`192.168.50.0/24` to the uplink, or use `exploit`.

## Read and write config

Over MQTT:

```bash
blueair-cloudcutter helpers mqtt read --type Full --save output/config.json
blueair-cloudcutter helpers mqtt write --set di.name=LivingRoom
```

Over the factory HTTPS endpoint:

```bash
blueair-cloudcutter helpers mqtt --ip 192.168.1.50 --did <uuid> --transport factory read --type Full
blueair-cloudcutter helpers mqtt --ip 192.168.1.50 --did <uuid> --transport factory write --set di.name=LivingRoom
```

`--set` takes `section.key=value`. `--json` takes an object. A write is a
`Diff`; no ack means nothing changed.

The tool refuses to write `db.c-cli` and `db.psk`. They are the device identity,
and overwriting them is irreversible.

## Reset to a start state

Delete local state:

```bash
rm -rf output/devices output/materials output/network output/logs output/mqtt
rm -f output/devices.json output/aws.json output/device.pem \
      output/state.json output/ap.json output/cleanup.sh output/*.pcap
```

Save `output/materials/ca.pem` first if you still need to restore a device.

AWS resources. The `aws` commands in this section are the AWS CLI, not
`blueair-cloudcutter aws`:

```bash
aws cloudformation delete-stack --stack-name blueair-cloudcutter
aws iam list-access-keys --user-name blueair-cloudcutter
aws iam delete-access-key --user-name blueair-cloudcutter --access-key-id <id>
aws iam detach-user-policy --user-name blueair-cloudcutter \
  --policy-arn arn:aws:iam::<account>:policy/BlueAirCloudCutterOperator
aws iam delete-user --user-name blueair-cloudcutter
```

Delete the IoT things (`blueair-device-<cert prefix>`,
`blueair-controller-<cert prefix>`), the certificates and `blueair-policy` in
the console. `aws iot list-things`, `aws iot list-certificates` and
`aws iot list-policies` show them.

Device:

1. Factory-reset the purifier. A factory reset returns it to normal mode, where
   BLE provisioning is on.
2. Provision it back to the stock broker and API (this is the stock in Europe, it varies between regions):

   ```bash
   blueair-cloudcutter helpers ble provision --address <MAC> \
     --broker a3ves2sigfa6tq-ats.iot.eu-west-1.amazonaws.com \
     --api https://hkgmr8v960.execute-api.eu-west-1.amazonaws.com/prod \
     --auth https://hkgmr8v960.execute-api.eu-west-1.amazonaws.com/prod/c/authenticate \
     --region eu-west-1 --ssid <wifi> --password '<wifi-password>'
   ```

   The device's own `c-b` certificate is stock and still registered with
   BlueAir. Deleting your copy in your account does not remove it.

3. A factory reset does not undo `c-r`, `c-d` or `k-jwt`. Restore them from your
   dump or reflash the stock image. Until then the device does not trust the
   stock broker.

If you deleted the AWS resources but still have `output/device.pem`, recreate
them:

```bash
blueair-cloudcutter aws onboard --device-cert output/device.pem --region eu-west-1
blueair-cloudcutter aws discover --timeout 120
```

## Irreversible writes

- `db.c-cli` and `db.psk`. The tool refuses.
- Wiping `certificates0` without a dump. That destroys the AWS identity.
- Writing a dump from another unit. Flash encryption is per device.

Everything else in the exploit paths can be restored by writing the stock
certificates back.
