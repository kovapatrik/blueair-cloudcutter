# BlueAir CloudCutter

Local control and custom firmware for BlueAir air purifiers that talk to AWS IoT.

> [!CAUTION]
> In the current stage, it's hardly advised to create a flash dump through UART!
> This has been only tested on only one device: Blue Pure 411i Max / Blue Max 3250i
> It's not guaranteed to work on other models, not even on another model of this very
> same type (although it should work.) The local control route is fairly low-risk, but 
> nothing is guaranteed. Use this at your own risk!

> [!WARNING]
> This tool writes firmware and configuration to hardware you own. It is not
> affiliated with or endorsed by BlueAir. A wrong write can leave the device
> unbootable until you restore a flash dump over UART. Make a dump first if you
> plan to flash custom firmware.

I'm fairly sure the local control part of this tool can be applied to any AWS based BlueAir device
but I cannot prove this until people report this.

## What it does

| Goal | What changes | Reversible |
|---|---|---|
| Local control | replace the broker trust anchor (`db.c-r`) and move the device to your MQTT broker | yes, write the stock root back |
| Custom firmware | write an unsigned image into the passive OTA slot through the factory HTTPS endpoint | yes, if you kept a flash dump |
| BLE provisioning | Wi-Fi, broker/API URLs, factory mode, events, filters, Wi-Fi scan | yes, configuration writes are atomic |
| Read/write config | the `CmConfig` document over MQTT or the factory HTTPS API | yes, atomic writes |

Local control keeps the stock firmware. The firmware route is for ESPHome and
other custom builds. Flashing custom firmware without a UART dump cannot be
undone.

## Requirements

- A Linux machine with Docker or Podman installed. If you already captured the
  device certificate with Wireshark or a router, pass `--device-cert` to skip
  the AP and capture. See
  [`docs/client-certificate.md`](docs/client-certificate.md).
- A spare Wi-Fi adapter for the provisioning AP, plus another connection for
  internet. Ethernet is recommended, because the AP adapter cannot be the
  default route. The adapter is not needed with `--device-cert`.
- A Bluetooth adapter on the machine.
- An AWS account and an IAM principal with IoT permissions.
- For local control: a broker with a certificate signed by the CA you plant, and
  a DNS name for it on the device's network.
- For custom firmware: a UART flash dump if you ever want the stock image back,
  and a device that has taken an official OTA. Stock units ship with older
  firmware, so most devices should already meet this.

## Quick start

```bash
git clone https://github.com/kovapatrik/blueair-cloudcutter
cd blueair-cloudcutter
sudo ./blueair-cloudcutter.sh
```

With no arguments the wrapper picks a wireless interface, starts the container
and runs the guided exploit. You need root for the AP and packet capture. With
`--device-cert` the AP and capture are skipped, but the container still needs
host networking for the fake provisioning API.

Read [`INSTRUCTIONS.md`](INSTRUCTIONS.md) before the first run. It covers the
AWS login, the prompts, local control, custom firmware and recovery. Run
`sudo ./blueair-cloudcutter.sh doctor` to check the host.

## Supported devices

Tested on a Blue Pure 411i Max / Blue Max 3250i (`di.hw = nb_l_1.0`), firmware
1.0.4 and 1.0.6, ESP32-D0WD-V3, ESP-IDF v4.2. Other `nb_*` models are expected
to behave the same, but have not been tested. Confirm the 16-byte image header
against a dump before flashing a different board.

## How it works

The provisioning protocol has no proof of possession, and the factory image
upload does not verify the image before writing it. The findings are in
[`docs/findings.md`](docs/findings.md); the full chain is in
[`WRITEUP.md`](WRITEUP.md).

## Files

- `firmwares/`: images for the container. Mounted read-only at `/firmwares`.
- `output/`: state, captured certificates, keys and logs.
- `output/aws.json`: the active device. `output/devices.json` lists all of them.
- `output/materials/`: the generated CA, broker certificate and k-jwt key.
- `output/mqtt/`: a self-contained mosquitto bundle, when generated.
- `output/cleanup.sh`: idempotent AP undo script. The wrapper runs it even if the
  container was killed.

Keep `output/` private. The control keys can publish to your devices.

## Documentation

- [`INSTRUCTIONS.md`](INSTRUCTIONS.md): step-by-step usage for normal users.
- [`docs/manual.md`](docs/manual.md): manual routes, the old flag map and recovery.
- [`docs/troubleshooting.md`](docs/troubleshooting.md): ports, firewall, Docker
  and BLE issues.
- [`docs/client-certificate.md`](docs/client-certificate.md): capture the device
  certificate with Wireshark or a router, and skip the AP with `--device-cert`.
- [`docs/protocol.md`](docs/protocol.md): BLE and MQTT protocols.
- [`docs/flash-access.md`](docs/flash-access.md): UART backup and restore.
- [`docs/findings.md`](docs/findings.md): the vulnerabilities and their status.
- [`WRITEUP.md`](WRITEUP.md): the full analysis.

## AI disclaimer

As written in the writeup as well, AI was heavily used in the reverse engineering of
the binary to find the actual exploit. Before that, I found the actual paths to going 
forward with the exploit. I also used AI to generate this tool.
I spent a lot of time figuring out the exploit and finding the holes, and I think
based on the concept, AI could write a better code than me. The writeup and part of 
the documentation was written by me.

## Acknowledgment

- [tuya-cloudcutter](https://github.com/tuya-cloudcutter/tuya-cloudcutter) for the
  project structure and naming conventions.

## Disclosure

Reported to `infosec@blueair.com` on 1 September 2026, with a follow-up on
1 October 2026. No acknowledgement was received.

All testing was performed on a single unit I purchased and own, on an isolated
network. No BlueAir infrastructure, customer device or customer data was
accessed.

## License

MIT. See [`LICENSE`](LICENSE).
