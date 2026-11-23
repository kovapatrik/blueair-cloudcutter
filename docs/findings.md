# Findings

- Device: Blue Pure 411i Max / Blue Max 3250i
- Firmware: tested on 1.0.4 and 1.0.6
- Hardware tag `nb_l_1.0`
- ESP32-D0WD-V3, ESP-IDF v4.2 (`v4.2-nb-2-g699ffdb541`)

All work performed on a single unit owned by me, on an isolated network.

## F-01 - BLE provisioning runs without proof-of-possession

Provisioning is started with the proof-of-possession parameter set to `NULL`, so any client in Bluetooth range can complete a provisioning session against an unprovisioned unit.
Also, in the BLE provisioning, it's possible to overwrite the broker url to any AWS IoT broker url, redirecting the device to it.

## F-02 - `c/prov` MQTT topic writes are not authenticated

The `c/prov` MQTT topic's request envelope carries `_s.sig`, but it is never verified, an empty string is accepted. Anyone able to publish on a device's config topic (or reach the HTTPS endpoint in factory mode) can rewrite any of the seven whitelisted sections. This is the root enabler for most of the other findings. It permits replacing `db.c-r` (the TLS trust anchor used to validate the broker) and `db.k-jwt` (the certificate against which JWTs are verified when setting the device to factory mode using the BLE provisioning). With `c-r` replaced, the device can be moved to any broker permanently. Also, by overwriting the `db.c-d` certificate, it's possible to send an OTA update with valid signature.

## F-03 - Secure boot is disabled

This is not really a finding (and not possible to fix), but this makes the other findings possible. This also means that if there is an OTA primitive available some way and someone has physical access, they can flash arbitrary firmware.

## F-04 - `provision/image` accepts firmware without verifying its signature

The local HTTPS endpoint `/d/<did>/provision/image` (`provisionImagePostHandler`, available in factory mode) streams the uploaded image straight into the passive OTA partition. No signature is checked before or during the write, verification happens only later, at activation.

Two consequences:

- What I upload is written to flash and encrypted on-device with the real flash-encryption key, which is otherwise unavailable to me. That is what makes the content executable rather than merely present.
- The partition keeps that content after the activation fails, so anything that later selects the slot boots it.

This is the primitive the next two findings build on. Without it, neither the ordering issue nor the erase overflow leads anywhere.

The endpoint itself is only reachable in factory mode, entered over BLE with a JWT verified against `db.k-jwt` - a slot writable through F-02. It is not the only route, though: the cloud OTA path writes blocks to the partition before verifying them too (see the note at the end of "Chaining these").

## F-05 - Boot partition is committed before the handler finishes

In the `provisionImagePostHandler`, `esp_ota_set_boot_partition()` is called, and only afterwards does the handler enter the secondary (MCU) stage. That stage has an exit path which returns without rebooting and without erasing:

```c
esp_ota_set_boot_partition(part);          // boot pointer committed here
if (mcu_size == 0) { ...reboot...; }
mcu_buff = malloc(MCU_BUFF /* 1048832 */);
if (remaining_body <= MCU_BUFF) { goto mcu_receive_loop; }
log("MCU buff is too small!");
free(mcu_buff); cJSON_Delete(root);
return -1;                                  // no reboot, no erase
```

This way it's possible to point the boot pointer at a slot, but in the same session before the device reboots, rewrite the OTA partition's content with an unsigned firmware. This is the core of the chain.

To reproduce, declare a non-zero STM32 `size` in the manifest so the MCU stage is entered, and a `Content-Length` roughly 1 MB larger than the body actually sent. The comparison is made from the declared length before the data is read, so the handler bails on arithmetic.

## F-06 - Unvalidated manifest `size` reaches `esp_ota_begin` (integer overflow)

The `size` field of an image entry in the OTA manifest, passed to `esp_ota_begin()` without validation.

```c
if (size - 1U < 0xFFFFFFFE)
    esp_partition_erase_range(part, 0, (size + 0xFFF) & 0xFFFFF000);
else
    esp_partition_erase_range(part, 0, part->size);
```

With `size = -2` (`0xFFFFFFFE`), the round-up overflows: `0xFFFFFFFE + 0xFFF` truncates to `0x00000FFD`, and `& 0xFFFFF000` yields **0**. `esp_ota_begin` returns success having erased nothing.

Because of this, the previously OTA updated, correctly signed image remains in the partition. It then passes verification honestly, while I have an open write handle to that partition, removing the need to possess any vendor-signed image at all.

## F-07 - JWT verification fails open when `k-jwt` is absent

`http_server_jwt_verify` is used by `provision/image`, `provision/ssid`, `management/reset` and the BLE `FactoryCmd` handler. When `k-jwt` is empty or erased, verification passes with any token.

## F-08 - Factory Wi-Fi credentials are compiled into shipped firmware

The retail image contains a fixed factory SSID and pre-shared key, plus the factory server hostname, as compiled-in defaults in the `fc` section rather than provisioned values. They are therefore identical on every unit and recoverable from any firmware image.

A device with cleared NVS falls back to these defaults and will join a matching access point automatically, then announce itself to whatever answers that hostname. Combined with F-07, this means brief physical access is enough: clear NVS over UART, stand up the factory network, and flash arbitrary firmware with no credentials of any kind.

## Chaining these

By chaining these, they give persistent arbitrary code execution on the device **without possessing any BlueAir-signed firmware image**.

1. Write my own certificate into `db.k-jwt` over `c/prov` (F-02).
2. Mint a JWT the device now accepts, and use it in the BLE `FactoryCmd` to put the device into factory mode. This brings up the local HTTPS server and `provision/image`.
3. POST a manifest declaring the ESP32 image `size` as `-2`. The erase length overflows to zero (F-06), so `esp_ota_begin` succeeds having erased nothing, the previously installed, correctly signed image is still sitting in the partition. For this, an existing OTA update must have run before which sits in the other OTA partition, but I think this is the case with any device.
4. Send exactly 16 bytes of payload: the image header. `esp_ota_end` refuses to continue if nothing was written, and with flash encryption enabled the write only advances in whole 16-byte blocks. Those 16 bytes are a build constant, identical on every unit of this type, so writing them back over themselves is a no-op - flash encryption is deterministic, the same plaintext at the same address produces the same ciphertext.
5. `esp_ota_end` verifies the **partition**, not what I uploaded. It is still the vendor's signed image, so verification passes honestly and `esp_ota_set_boot_partition()` commits the boot pointer to that slot.
6. The same request's MCU stage then bails without rebooting and without erasing (F-05), so the device stays alive with the boot pointer already moved.
7. A second `provision/image` writes arbitrary unsigned firmware into that slot (F-04). Its signature check fails, but nothing erases it.
8. Reboot. Secure boot is disabled (F-03), so the bootloader loads it.

The device is now running my firmware, and it was encrypted on-device with the real flash-encryption key on the way in.
