# Use a captured client certificate

The normal exploit starts a provisioning AP and captures the purifier's public
client certificate from the TLS handshake to AWS IoT. If you already have that
certificate, pass it with `--device-cert` and the tool skips the AP and packet
capture. It still registers the certificate in your AWS account and learns the
DID over MQTT, because the DID is only published on the broker.

Only the public certificate is needed. The private key never leaves the device.

You can capture the certificate with Wireshark on a laptop hotspot, with
`tcpdump` on a router, or with any other tool that can see the device's TLS
traffic. You do not need the AP in this repository.

## What you need

- The device client certificate in PEM or DER form.
- A Bluetooth adapter, so the exploit can move the device to your Wi-Fi and
  AWS IoT endpoint. You can skip Bluetooth when the device is already there and
  you use `--skip-wifi-setup`.
- An AWS account with the usual IoT permissions.
- The 2.4 GHz Wi-Fi SSID and password the device should use.

## Capture with Wireshark on a laptop hotspot

This works on Windows, macOS and Linux. The hotspot must carry the device's
traffic. The TLS handshake is still visible because it happens between the
device and AWS IoT.

1. Create a hotspot on the laptop. It must be 2.4 GHz, because the purifier has
   no 5 GHz radio:
   - Windows: Settings -> Network -> Mobile Hotspot.
   - macOS: System Settings -> General -> Sharing -> Internet Sharing.
   - Linux: use your desktop's hotspot feature, or NetworkManager.
2. Factory-reset the purifier so it goes through provisioning again. Start the
   Wireshark capture on the hotspot interface before you connect the device.
3. Provision the device onto the hotspot with the phone app or BLE. During the
   first connection it dials AWS IoT on TCP 8883.
4. Filter for the TLS client certificate message:

   ```text
   tls.handshake.type == 11
   ```

   You can also use `tcp port 8883` while capturing and add the display filter
   afterwards.
5. Pick the packet whose source is the device, usually a `192.168.x.x` or
   hotspot address, not AWS.
6. Expand `Transport Layer Security -> TLS 1.2 -> Certificate -> Certificates
   -> Certificate`.
7. Right-click the certificate, choose **Export Packet Bytes**, and save it as
   `cert.der`.
8. Convert it to PEM:

   ```bash
   openssl x509 -inform DER -in cert.der -out device.pem
   ```

If the handshake does not appear, reboot the device while the capture is
running. The device only sends the certificate when it opens a new MQTT
connection. TLS 1.2 exposes it; TLS 1.3 encrypts it.

## Capture with tcpdump on a router

Use this when the router can run `tcpdump` and the device is already on that
network. On OpenWrt, install it first with `opkg update && opkg install tcpdump`.

On the router:

```bash
ssh root@192.168.0.1 \
  "tcpdump -i br-lan -U -s0 -w - host DEVICE_IP and port 8883" \
  > blueair_tls.pcap
```

Reboot the device or reconnect it to the broker while the capture runs. Then
extract the certificate on a machine with `tshark`:

```bash
tshark -r blueair_tls.pcap \
  -Y "tls.handshake.type==11 && ip.src==DEVICE_IP" \
  -T fields \
  -e tls.handshake.certificate \
  | head -1 \
  | cut -d',' -f1 \
  > cert.hex
```

Convert the hex to DER and then PEM:

```bash
cat cert.hex | tr -d '[:space:]' | xxd -r -p > cert.der
openssl x509 -inform DER -in cert.der -out device.pem
```

Check what you captured:

```bash
openssl x509 -in device.pem -text -noout
```

The output should show a device certificate, not a server or CA certificate.
The device certificate is the one in the client's Certificate message
(`tls.handshake.type == 11`).

## Run the exploit without the AP

Put the certificate under `output/`, because the container only mounts
`output/` and `firmwares/`. Then run:

```bash
sudo ./blueair-cloudcutter.sh exploit --device-cert output/device.pem \
  --onboard-only
```

Add the goal you want:

```bash
sudo ./blueair-cloudcutter.sh exploit --device-cert output/device.pem \
  --local-control --local-broker broker.home \
  --ssid "MyWiFi" --password "..."

sudo ./blueair-cloudcutter.sh exploit --device-cert output/device.pem \
  --firmware app.bin --ssid "MyWiFi" --password "..."
```

The `--device-cert` path:

1. validates the certificate and registers it in your AWS account, creating the
   tool's control identity;
2. provisions the device over BLE directly to your home Wi-Fi and your AWS IoT
   endpoint, using the fake provisioning API on this machine's LAN address;
3. discovers the DID by listening on MQTT;
4. continues with local control, firmware, or stops after onboarding.

No AP, NAT or packet capture is started, so `--iface` is not needed. You still
need Bluetooth, and the fake provisioning API must be reachable from the device
on your LAN; the container therefore still needs host networking.

Add `--reprovision` to force the BLE move when a DID is already recorded for
this certificate.

If the device is already on your Wi-Fi and already points at your AWS IoT
endpoint, add `--skip-wifi-setup`. The DID is still learned over MQTT:

```bash
sudo ./blueair-cloudcutter.sh exploit --device-cert output/device.pem \
  --skip-wifi-setup --onboard-only
```

`--device-cert` accepts PEM or DER. A raw Wireshark `.der` export can be passed
directly; the tool normalizes it to `output/device.pem`.

## Manual route

The same steps are available as helpers:

```bash
./blueair-cloudcutter.sh aws onboard --device-cert output/device.pem
./blueair-cloudcutter.sh aws show
```

Use the endpoint from `aws show`, then provision the device directly to your
Wi-Fi. The helper starts a fake provisioning API on port 8000 by default:

```bash
./blueair-cloudcutter.sh helpers ble provision \
  --broker <endpoint> --region <region> \
  --ssid "MyWiFi" --password "..."
```

Finally learn the DID over MQTT:

```bash
./blueair-cloudcutter.sh aws discover --timeout 120
```

If the device is already on your endpoint and only the local record is missing,
`aws onboard` followed by `aws discover` is enough; skip the BLE step.
