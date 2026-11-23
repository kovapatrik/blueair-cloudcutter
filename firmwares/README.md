# Firmware files

Put ESPHome (or other ESP32 app) firmware here and pass **only the filename**:

```bash
cp ~/Downloads/esphome.bin firmwares/
./blueair-cloudcutter.sh exploit --iface wld0 --firmware esphome.bin ...
```

The folder is mounted read-only at `/firmwares` inside the container. `*.bin`
files are gitignored, so firmware is never committed by accident. YAML files are
tracked, so an example configuration can live here too.

Use the ESPHome **OTA update** binary, not the "Factory format" image. See
[`esphome-example.yaml`](esphome-example.yaml) for a placeholder configuration.
