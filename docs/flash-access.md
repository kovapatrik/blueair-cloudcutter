# Flash access (manual)

**This is deliberately not part of `blueair-cloudcutter`.** The library implements
the exploit over BLE / MQTT / HTTP. Reading or writing the raw flash is a
recovery procedure, not exploit logic, and it is done with `esptool` directly.

The device has flash encryption in RELEASE mode with the key read-protected.
That has two consequences:

- UART reads return **ciphertext**.
- UART writes must be **ciphertext that came from this same unit**. A plaintext
  `.bin` written over UART is not executable.

So the reliable way to switch between the original firmware and ESPHome is to
keep one full ciphertext dump of each state and write the one you want back.

## 1. Dump the current ESPHome state

Put the device into `DOWNLOAD_BOOT` (ground GPIO0, then reset), connect a 3.3 V
USB-serial adapter, and run:

```bash
esptool --before no-reset --after no-reset -p /dev/ttyUSB0 \
    read-flash 0 0x800000 esphome.bin
```

Verify it by reading it again and comparing:

```bash
esptool --before no-reset --after no-reset -p /dev/ttyUSB0 \
    read-flash 0 0x800000 esphome-verify.bin
sha256sum esphome.bin esphome-verify.bin
```

The hashes must be identical. If they are not, lower `--baud` (115200 is slow
but reliable) and redo it. **Keep `esphome.bin` and its hash**; this is the only
way back to ESPHome.

> The dump is encrypted with this unit's key. It is useless on any other device,
> and a dump from another unit will not boot here.

## 2. Restore the original firmware

Use the dump taken **before any custom firmware**, from this same unit, normally
`flash_1.0.6.bin` (or `flash_1.0.4.bin`). Do not use a `*_rooted.bin` if you
want stock trust anchors.

```bash
esptool --before no-reset --after no-reset -p /dev/ttyUSB0 \
    write-flash 0x0 flash_1.0.6.bin --force
```

That writes bootloader, partition table, both app slots, `otadata`, NVS and the
certificate partitions at their original offsets. Power-cycle and watch the UART
at 115200: you should see `BAapplication` and the version from the dump.

## 3. Go back to ESPHome

Put the device in `DOWNLOAD_BOOT` again:

```bash
esptool --before no-reset --after no-reset -p /dev/ttyUSB0 \
    write-flash 0x0 esphome.bin --force
```

Power-cycle. That is the round trip.

## Partial restores

If you know exactly what changed, you can write a slice instead of the whole
image. All offsets are from the 1.0.6 partition table:

| Region | Offset | Size |
|---|---|---|
| otadata (two sectors) | `0xa000` | `0x2000` |
| app0 | `0x20000` | `0x300000` |
| app1 | `0x320000` | `0x300000` |
| nvs | `0x640000` | `0x10000` |
| certificates0 | `0x650000` | `0x20000` |
| certificates1 | `0x670000` | `0x20000` |
| app0_config | `0x690000` | `0x38000` |
| app1_config | `0x6c8000` | `0x38000` |

Example: write one app slot from a dump:

```bash
dd if=flash_1.0.6.bin of=app1.bin bs=1 skip=$((0x320000)) count=$((0x300000))
esptool --before no-reset --after no-reset -p /dev/ttyUSB0 \
    write-flash 0x320000 app1.bin --force
```

Example: switch OTA slots by erasing `otadata`:

```bash
# erase the entry that selects app0 -> the bootloader uses app1
esptool --before no-reset --after no-reset -p /dev/ttyUSB0 \
    erase-region 0xa000 0x1000

# or the entry that selects app1 -> use app0
esptool --before no-reset --after no-reset -p /dev/ttyUSB0 \
    erase-region 0xb000 0x1000
```

Erasing needs no key. Writing a constructed plaintext `otadata` entry does not
work on retail hardware; restore the ciphertext slice from a dump instead.

Example: drop the device to factory mode (destroys the AWS identity):

```bash
# nvs, certificates0, certificates1, app0_config, app1_config are contiguous
esptool --before no-reset --after no-reset -p /dev/ttyUSB0 \
    erase-region 0x640000 0xC0000 --force
```

Do **not** erase `nvs_key` / `nvs_key_backup` at `0xd000` / `0xf000`; the
encrypted NVS partitions need them.

## 4. Dual-boot (optional)

If you want the original firmware in one OTA slot and ESPHome in the other,
switch with `otadata` rather than restoring the whole flash each time:

1. Restore the original full dump.
2. Boot the original firmware and put it in factory mode (BLE `FactoryCmd`, or
   the NVS wipe above).
3. Write the ESPHome image through the device's `provision/image` endpoint with
   `blueair-cloudcutter helpers flash --custom esphome.bin`. That path encrypts it on-device.
4. To return to the original, erase the `otadata` sector that selects ESPHome.

Caveats:

- If the original firmware set the ESPHome slot to `PENDING_VERIFY` and ESPHome
  does not call `esp_ota_mark_app_valid_cancel_rollback()`, the next reboot can
  roll back.
- The ESPHome image must fit the original 3 MB app slot and use the original
  partition layout.
- Both firmwares share the NVS partitions; ESPHome can overwrite the original's
  config. The full dumps restore it.

## What not to do

- Do not write a plaintext ESPHome or original `.bin` over UART.
- Do not restore a dump from another purifier.
- Do not mix an app slot from one dump with a bootloader/table/NVS from another.
- Do not use `--after hard-reset` with a read unless you want the device to boot
  immediately; `no-reset` plus a manual power-cycle is the safe default.
- Do not skip the read-back verification.
