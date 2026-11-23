# Protocol

BLE provisioning, the MQTT config protocol, the `nb_*` device registry and the
local provisioning API. Verified on a Blue Pure 411i Max / Blue Max 3250i
(`di.hw = nb_l_1.0`, firmware 1.0.6). Confirm other families before assuming.

## BLE provisioning

The device uses ESP-IDF's Wi-Fi provisioning transport plus BlueAir's custom
commands. The implementation is in `src/blueair_cloudcutter/ble/`. It covers
discovery, the Security 1 handshake, `ConfigCmd`, `FactoryCmd`, events, MAC and
filter access (which never worked for me), Wi-Fi scan and Wi-Fi connect.

### Commands

```bash
blueair-cloudcutter helpers ble scan
blueair-cloudcutter helpers ble provision --broker 192.168.1.10 --ssid "MyWiFi" --password "..."
blueair-cloudcutter helpers ble factory --factory-url https://192.168.1.10:8443
blueair-cloudcutter helpers ble events
blueair-cloudcutter helpers ble info
blueair-cloudcutter helpers ble wifi-scan
blueair-cloudcutter helpers ble filter --filter-type hepa
blueair-cloudcutter helpers ble filter --filter-type hepa --filter-value 42
```

`scan` lists every device and marks the ones that advertise the BlueAir service
with `*`. Pass `--address` or `--name` when there are several.

### Provision

`provision` connects, completes Security 1, sends `StartCmd`, then sends one
`ConfigCmd` for each non-empty field:

```bash
# Your own AWS IoT endpoint:
blueair-cloudcutter helpers ble provision \
  --broker a3xxxxxxxxxxxxxx-ats.iot.eu-west-1.amazonaws.com \
  --region eu-west-1 --ssid "MyWiFi" --password "..."

# A local broker, once its CA is planted:
blueair-cloudcutter helpers ble provision --broker broker.home \
  --ssid "MyWiFi" --password "..."
```

`--broker` is required. Pass a bare hostname or IP, matching the stock app. Do
not pass an `mqtts://` URL. The device needs a name, not an IP, for TLS.

`provision` starts the fake provisioning API by default and sends its
`api_url` and `auth_url`. It waits until the device has called both
`authenticate` and `register-device-hash`. To use another backend, pass both
`--api` and `--auth`. Passing only one is an error. `--fake-api-host` selects
the address the device dials, defaulting to this machine's LAN IP. Use
`--fake-api-host 192.168.50.1` when the device is on the provisioning AP.

`--random-text` and `--secure-random` default to fresh random values. Use
`--open-network` for an open Wi-Fi network.

To point the device at a local broker, the device must trust your CA in
`db.c-r`. The usual order is:

1. Provision to your own AWS IoT. The stock Amazon root is already trusted.
2. Capture and register the device certificate, then plant your CA over MQTT.
3. Provision again, this time to the local broker.

The exploit does this in one run with `--local-control`.

### Factory

Start the factory rendezvous first:

```bash
blueair-cloudcutter helpers serve factory
```

If `FactoryCmd` uses an IP URL, give the server a matching SAN:

```bash
blueair-cloudcutter helpers serve factory --cert-host 192.168.50.1
```

The purifier must be in normal mode, where BLE is on. Factory mode has no BLE;
`FactoryCmd` is what moves it there. Reboot the device before sending it, even
when it is already in normal mode: the reboot clears the BLE provisioning flags
left by the previous session, and a stale flag makes the next command fail.

Then send the command:

```bash
blueair-cloudcutter helpers ble factory --factory-url https://192.168.1.10:8443
```

`--factory-url` is the base URL. The device posts its hello to
`/fs/hello-message` under it. `--factory-token` is an RS256 JWT. If omitted, the
tool mints one from `output/materials/kjwt.key`, the key whose certificate you
planted into `db.k-jwt`. If `k-jwt` is absent after an NVS wipe, any token is
accepted. `--factory-ssid` and `--factory-password` default to the compiled-in
`BAFactory` credentials.

### Other actions

`events` reads and prints queued events until the device reports zero remaining,
with a 100-event safety limit. `info` reads the MAC and, best effort, the filter
value. `wifi-scan` starts a scan, polls until it finishes, then fetches the
results. `filter` reads a value, or writes one with `--filter-value`. The
`--filter-type` string is passed through unchanged.

### Characteristics

| name | UUID |
|---|---|
| service | `4772911e-d07c-4617-8241-f4d10948d6ae` |
| `prov-scan` | `4772ff50-d07c-4617-8241-f4d10948d6ae` |
| `prov-session` | `4772ff51-d07c-4617-8241-f4d10948d6ae` |
| `prov-config` | `4772ff52-d07c-4617-8241-f4d10948d6ae` |
| `proto-ver` | `4772ff53-d07c-4617-8241-f4d10948d6ae` |
| `custom-endpoint` | `4772ff54-d07c-4617-8241-f4d10948d6ae` |

### Security 1

1. `proto-ver`: write `ESP`, read the version. Not encrypted.
2. Session 0: send the client X25519 public key. The device replies with its
   public key, a 16-byte random nonce and a status.
3. Derive the shared secret. Use AES-256-CTR with the shared secret as the key
   and the device random as the initial counter.
4. Session 1: encrypt the device public key with the keystream and send it. The
   device replies with the encrypted client public key. A match proves the
   device holds the shared secret.
5. Every later request and response is XORed with the same continuous keystream,
   in order. One `SessionCrypto` instance per connection, shared by both
   directions.

The session uses a 32-bit big-endian counter (`Ctr32BE`). This implementation
uses `cryptography`'s 128-bit big-endian CTR, which is identical for these
message sizes and matches ESP-IDF's `mbedtls_aes_crypt_ctr`.

### Platform notes

- macOS: grant Bluetooth permission to the terminal app. Docker cannot access
  CoreBluetooth.
- Linux: BlueZ must run and the user must reach
  `/var/run/dbus/system_bus_socket`. The wrapper mounts it and uses host
  networking.
- Windows: bleak uses WinRT. Native Python only.
- If the device does not advertise the service UUID, `scan` still lists it by
  name. Pass `--address`.

## MQTT

How BlueAir's AWS IoT devices talk to their broker. The protocol appears shared
across the AWS IoT range. The registry, which names the sensors and actuators,
varies by model.

Throughout, `<DID>` is the device UUID.

### Transport

| | |
|---|---|
| Broker | AWS IoT Core, TLS 1.2, port 8883 |
| Client auth | X.509 client certificate, the device's `c-cli` / `psk` pair, provisioned at the factory |
| Server auth | the device validates the broker chain against the root CA in `db.c-r` (stock: Amazon Root CA 1) |
| Namespace | every topic is prefixed `d/<DID>/` |

The device only requires that the broker certificate chains to `db.c-r`. It
connects to any AWS IoT endpoint without modification because every endpoint
certificate chains to the stock Amazon root. Moving it to your own broker also
requires replacing that root.

### Topics

Request and response topics reply on the same topic with `-r` appended.
Subscribe to `d/<DID>/c/#` to capture both sides of a config conversation.

| topic | direction | purpose |
|---|---|---|
| `d/<DID>/c/read` | to device | request configuration |
| `d/<DID>/c/read-r` | from device | configuration document |
| `d/<DID>/c/prov` | to device | write configuration |
| `d/<DID>/c/prov-r` | from device | ack or error |
| `d/<DID>/s/<name>` | from device | sensor value |
| `d/<DID>/a/<name>` | to device | actuator command |
| `$aws/rules/<rule>/d/<DID>/s/batch/<name>` | from device | batched telemetry |

### Read: `c/read`

Publish `{"t": "State"}` to `d/<DID>/c/read`.

`t` accepts:

- `State`: current values only. Cheap.
- `Full`: the stored `CmConfig` document with every versioned field. This is the
  one worth capturing.
- `Diff`: fields changed since a version baseline. Requires `v` and `s.sig`, and
  forbids `r`.
- `Partial` and `Partial_Diff`: parsed, then rejected with `JSON rd-req t invalid`.

| `t` | rules |
|---|---|
| `Full` | `v` absent or zero, `s.sig` absent |
| `Diff` | `v` required and non-zero, `s.sig` required, `r` forbidden |
| `State` | no extra constraints |
| `Partial`, `Partial_Diff` | parsed, then rejected |

Optional fields: `id` (a 36-character UUID if present), `opaque` (boolean), `r`
(string array, `Full` only, narrows which roots are returned).

Certificates are never returned by `c/read`. The `db` section emits only
`o-cid`, `u-jwks` and `did`. The certificate slots are write-only. `opaque` is
parsed and echoed but does not change the output. Use a flash dump if you need
the trust material back.

The reply lands on `d/<DID>/c/read-r`. A `Full` read can take about a minute.
Silence is not failure.

Envelope:

```json
{
  "_ot": "CmConfig",
  "_it": "urn:blueair:openapi:version:blue:0.0.5",
  "_eid": "<endpoint uuid>",
  "_sc": "Instance",
  "_v": 1773254034,
  "di": {}, "db": {}, "ds": {},
  "da": {}, "dc": {}, "df": {}, "fc": {}
}
```

`_v` is the config version. A write needs it.

### Write: `c/prov`

Publish to `d/<DID>/c/prov`:

```json
{
  "_t": "Diff",
  "_id": "<DID>",
  "_eid": "<endpoint uuid, taken from a read>",
  "eid": "",
  "_it": "urn:blueair:openapi:version:blue:0.0.5",
  "_cas": 1773254034,
  "_v": 1773254035,
  "_s": { "sig": "" },
  "id": "<random uuid4>",
  "db": { "c-r": "-----BEGIN CERTIFICATE-----\n..." }
}
```

| field | meaning |
|---|---|
| `_t` | `Diff` for a partial update. Omit it and every field becomes mandatory. |
| `_cas` | compare-and-swap; must equal the current `_v`. On mismatch the device replies with the correct value and applies nothing. |
| `_v` | the new version, usually `_cas + 1` |
| `_s.sig` | not verified; an empty string is accepted |
| `id` | client correlation id, any UUID |

The reply on `d/<DID>/c/prov-r` carries an ack with an HTTP-style status. `200`
means applied. Writes are atomic, so no ack means nothing changed.

To enumerate the schema, send a write with no `_t`. Every field becomes
mandatory and the device replies naming each missing one.

### Sections

Seven sections are writable. Each is parsed by an index-driven whitelist, so
`c/prov` is not an arbitrary NVS write primitive. Unknown keys are ignored.

| section | contents |
|---|---|
| `di` | device info: SKU, hardware tag, serial, firmware versions, MAC, display name |
| `db` | trust anchors and credentials |
| `ds` | sensor definitions |
| `da` | actuator definitions |
| `dc` | dynamic-config rules binding sensors to actuators |
| `df` | filter configuration |
| `fc` | factory configuration: `ssid`, `bssid`, `url`, `pwd` |

`fc` has no `mode` field, so factory mode cannot be enabled through `c/prov`. It
is set over BLE with `FactoryCmd`, gated by a JWT verified against `k-jwt`.
`di.hw` is the tag the OTA path matches when deciding whether an image is meant
for this hardware.

### Certificate slots

| slot | role |
|---|---|
| `c-r` | active root CA; the broker chain is validated against it |
| `c-r2` | rotation slot with no effect on 1.0.6; do not use it to change the anchor |
| `c-b`, `c-b2` | broker certificate slots |
| `c-i` | image / OTA certificate slot |
| `c-cli`, `psk` | the device's own client identity |

Never write `c-cli` or `psk`. They are the AWS credentials, they are not
restorable without a flash dump, and overwriting them removes the device's
ability to reach any AWS IoT broker. Writing garbage into `c-b` soft-bricks
broker connectivity; recover it by reflashing a pre-damage encrypted dump over
UART.

Replacing `c-r` with your own CA and pointing the device at a local broker is
what moves it off BlueAir's cloud.

### Sensor and actuator payloads

Both directions use SenML (`tf: senml+json`):

```json
{ "n": "<name>", "v": 3, "t": 1773938177, "bn": "urn:dev:ow:<DID>:" }
```

| field | meaning |
|---|---|
| `n` | item name, matching the `ds` or `da` key |
| `v` | numeric value |
| `vb` | boolean value |
| `t` | timestamp |
| `bn` | base name, `urn:dev:ow:<DID>:` |

Integer items use `v`, booleans use `vb`. The item's `ot` in the registry says
which. Actuator writes act on running state. They are not configuration. The
matching `dc` default is what survives a reboot.

### Gotchas

- A `Full` read can take about a minute. That is normal.
- `_cas` must match. Read and write back to back. A stale value is rejected
  with the correct one in the reply.
- Writes are atomic. No ack means nothing was applied.
- `_s.sig` is decorative. Anyone who can reach the device as its broker can
  write configuration.
- Unknown config keys are dropped.

## Device registry (`nb_*`)

Model-specific names for the `nb_*` hardware family. Verified on Blue Max 3250i
/ Blue Pure 411i Max, `di.hw = nb_l_1.0`, firmware 1.0.6. The names come from
the firmware's own `CmConfig` schema. Other SKUs in the family likely differ.

### Device info (`di`)

| field | example | notes |
|---|---|---|
| `sku` | `109583`, `110085` | varies by model |
| `hw` | `nb_l_1.0` | the OTA hardware tag; the image name must contain `nb` |
| `ds` | `012345-012-012-0-01-0-0123456` | serial |
| `ofv`, `cfv`, `mfv` | `1.0.6` | OTA, current and MCU firmware versions (read-only) |
| `cma` | `xx:xx:xx:xx:xx:xx` | MAC (read-only) |
| `mt`, `name` | `1`, `Blue Pure` | writable |

### Sensors

Device to broker, topic `d/<DID>/s/<name>`, SenML payload.

| name | type (`ot`) | meaning | interval / ttl |
|---|---|---|---|
| `pm2_5` | `PM2_5` | PM2.5 particulate | 60 s, ttl 1200 |
| `fu0` | `FU` | filter usage | ttl -1 |
| `rssi` | `RSSI` | Wi-Fi signal strength | 60 s, ttl 600 |
| `fsp0` | `Fanspeed` | fan speed readback | |
| `ledb` | `Led` | LED brightness readback | |
| `chl` | `ChildLock` | child lock state | |
| `is` | `IonizerState` | ionizer state | |
| `am` | `AutoMode` | auto mode state | |
| `sb` | `Standby` | standby state | |
| `nm` | `NightMode` | night mode state | |
| `sp` | `SensorBoxPresense` | sensor box present (the firmware spelling) | |
| `rt1s` | `RT1s` | 1-second tick | topic `s/1s` |
| `rt5s` | `RT5s` | 5-second tick | topic `s/5s` |
| `rt5m` | `RT5m` | 5-minute tick | topic `s/5m` |
| `b5m` | `Batch5m` | telemetry batch | 300 s |

The PM2.5 field is `pm2_5` on the wire, in the topic and in the registry.
`pm25` does not appear in the firmware.

The `rt*` sensors publish to shortened topics: `s/1s`, `s/5s`, `s/5m`. `b5m`
publishes through an AWS IoT rule at
`$aws/rules/telemetry_ingest_rule/d/<DID>/s/batch/b5m`, carrying `pm2_5` and
`fsp0`.

### Actuators

Broker to device, topic `d/<DID>/a/<name>`, SenML payload. This is how you
control the unit.

| name | type (`ot`) | effect | value |
|---|---|---|---|
| `fsp0` | `Fanspeed` | fan speed | `v`: 0-11 |
| `ledb` | `LedBrightness` | LED brightness | `v`: 0-100 |
| `chl` | `ChildLock` | child lock | `vb` |
| `is` | `IonizerState` | ionizer | `vb` |
| `am` | `AutoMode` | auto mode | `vb` |
| `sb` | `Standby` | standby | `vb` |
| `nm` | `NightMode` | night mode | `vb` |
| `sflu` | `SensorFlush` | flush or recalibrate sensors | `vb` |
| `reboot` | `Reboot` | reboot the device | `vb` |
| `uitest` | `UiTest` | UI self-test | `vb` |
| `buttontest` | `ButtonTest` | button self-test | `vb` |

Set fan speed to 3:

```bash
mosquitto_pub -h <broker> -p 8883 --cafile ca.pem \
  -t 'd/<DID>/a/fsp0' \
  -m '{"n":"fsp0","v":3,"bn":"urn:dev:ow:<DID>:"}'
```

Enter standby:

```bash
mosquitto_pub -h <broker> -p 8883 --cafile ca.pem \
  -t 'd/<DID>/a/sb' \
  -m '{"n":"sb","vb":true,"bn":"urn:dev:ow:<DID>:"}'
```

The tool can do the same:

```bash
blueair-cloudcutter helpers mqtt control --broker <broker> --did <DID> \
  --actuator fsp0 --value 3
blueair-cloudcutter helpers mqtt control --broker <broker> --did <DID> \
  --actuator sb --value true --boolean
```

### Dynamic-config rules (`dc`)

Bindings between a sensor and an actuator, each with a default that survives a
reboot.

| name | type | sensor | actuator | default |
|---|---|---|---|---|
| `fanspeed` | integer | `fsp0` | `fsp0` | 11 |
| `brightness` | integer | `ledb` | `ledb` | 100 |
| `childlock` | boolean | `chl` | `chl` | false |
| `nightmode` | boolean | `nm` | `nm` | false |
| `automode` | boolean | `am` | `am` | false |
| `standby` | boolean | `sb` | `sb` | false |
| `filterusage` | integer | `fu0` | | 0 |
| `ofv` | integer | | | 0 |
| `cfv` | integer | | | 0 |
| `mfv` | integer | | | 0 |

Actuator writes change running state only. Change the `dc` default with
`c/prov` to make a setting persist.

### Filter config (`df`)

| field | value |
|---|---|
| `ot` | `B4Filter` |
| `alg` | `FilterAlg1` |
| `a` | `877` |
| `fsfc` | `7000000` to `12000000`, varies by unit |

### Types present but not instantiated

The firmware's registry is larger than this SKU uses. The batch defaults list
`pm1`, `pm2_5`, `pm10`, `th` and `tVOC`. The full compiled registry is:

- Sensors: `PM2_5`, `FU`, `RSSI`, `Fanspeed`, `Led`, `ChildLock`,
  `IonizerState`, `AutoMode`, `Standby`, `NightMode`, `SensorBoxPresense`,
  `RT1s`, `RT5s`, `RT5m`, `Batch5m`, plus `PM1`, `PM10`, `TH`, `TVOC`.
- Actuators: `Fanspeed`, `LedBrightness`, `ChildLock`, `IonizerState`,
  `AutoMode`, `Standby`, `NightMode`, `SensorFlush`, `Reboot`, `UiTest`,
  `ButtonTest`.
- Filter: `B4Filter` / `FilterAlg1`.

A `Full` config read on another model shows what it instantiates.

## Fake provisioning API

The device calls its `api_url` and `auth_url` before it connects to the broker.
Without valid answers it loops on those URLs and never reaches 8883.

The exploit and `blueair-cloudcutter helpers ble provision` start a local HTTP server with captured
valid responses and put its URLs into `ConfigCmd`:

```
api_url   http://192.168.50.1:443/prod
auth_url  http://192.168.50.1:443/prod/c/authenticate
```

The device accepts plain HTTP, so no TLS is needed. With these responses
onboarding completes without a power cycle.

The server tries 443 first because host firewalls usually allow it. If 443 is
taken the exploit falls back to 8000; open 8000 on the AP interface then.
`blueair-cloudcutter helpers ble provision` listens on 8000 by default; override it
with `--fake-api-port`. `--fake-api-host` selects the address the device dials,
and `--fake-api-wait` controls the wait. Use `--api` and `--auth` to point the
device at another backend.

Responses live in `src/blueair_cloudcutter/data/fake_backend/`:

- `auth_resp.json`: access, refresh and ID tokens, `ba_X-Amz-CustomAuthorizer-*`,
  `token_type`, `expires_in`.
- `register_resp.json`: `{"message": "The request was successfully Activated."}`

The checked-in auth response uses synthetic JWT-shaped tokens with a
far-future expiry. If the device validates the token contents, replace
`auth_resp.json` with your captured response and rebuild the image.

Paths:

- `POST .../authenticate` returns `auth_resp.json`
- `POST .../register-device-hash` returns `register_resp.json`
- anything else returns `{"message": "ok"}` for POST or `{"ok": true}` for GET

Run the server on its own with `blueair-cloudcutter helpers serve fake-api --api-port 8000`.

## Tests

`tests/test_ble_*.py` include a fake device that performs the same X25519
handshake and protobuf exchange. They cover the session, config, factory,
events, filters and Wi-Fi paths without hardware.
