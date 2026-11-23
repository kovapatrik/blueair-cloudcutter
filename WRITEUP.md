# BlueAir AWS device jailbreak

BlueAir produces some excellent air purifiers. The newer models (e.g mine is Blue Max 3250i / Blue Pure 411i Max) are connecting to AWS IoT and using MQTT for communication. This means it's not possible to control them from the local network only, it has to connect to this external provider all the time. This would also mean if BlueAir in the future stops providing their AWS IoT instance, the device won't be remotely controllable. 

In an attempt to be able to locally control the device, I went into the following jailbreak journey.

I would like to emphasize that this **cannot be used for malicious purposes** as the method needs BLE access and an AP to connect to. Also, an attacker wouldn't gain anything from this. If anything, I could compare this to the [tuya-cloudcutter](https://rb9.nl/posts/2022-03-29-light-jailbreaking-exploiting-tuya-iot-devices/) project.

## UART, flash

The first I did was hooking up the device UART pads. This way I could read the boot log, etc... where I could gain a lot of information. I could also put the device to `DOWNLOAD_BOOT` mode, by grounding the EN and GPIO0 pins. After reading the logs and the eFuses I gained this informations:

- Flash encryption is enabled (`FLASH_CRYPT_CNT`)
- Flash encryption is in RELEASE mode, which means it's not possible to change this (`FLASH_CRYPT_CNT` is set to `0b1111111`)
- Secure boot is not enabled (`ABS_DONE_0/ABS_DONE_1 = False, `)
- JTAG is disabled (`JTAG_DISABLE = True`)
- Reading out the flash encryption key is disabled (`RD_DIS = 1`)
- Flash decryption/encryption is disabled in DL mode (`DISABLE_DL_ENCRYPT/DISABLE_DL_DECRYPT = True`), which means reading out the flash in `DOWNLOAD_BOOT` will read out ciphertext, and writing in this mode must be also in ciphertext
- The firmware was built using `ESP-IDF v4.2`

So without knowing the flash encryption key it's not possible to decrypt the current firmware, or writing a custom firmware.

Nevertheless, I made a flash dump. I started this project in June of 2024, so this firmware was version `1.0.4`. At the time of this write-up, the latest version is `1.0.6`, and this is the version which was used in the whole process.

After this, I kept reading and saving the UART logs.

## Bluetooth provisioning

The official application using [ESP-IDF's provisioning protocol](https://docs.espressif.com/projects/esp-idf/en/v6.0.2/esp32/api-reference/provisioning/provisioning.html) to communicate with the device, alongside some custom commands. All the `.proto` files used in this provisioning were compiled in the official application, so after decompiling their APK I could use the custom commands as well. After making the handshake using ESP-IDF's Security 1 schema, the following commands are used:

1. `StartCmd` -> `StartResp`
2. `ConfigCmd:api_url` -> `ConfigResp`
3. `ConfigCmd:auth_url` -> `ConfigResp`
4. `ConfigCmd:broker_url` -> `ConfigResp`
5. `ConfigCmd:region` -> `ConfigResp`
6. `ConfigCmd:random_text` -> `ConfigResp`
7. `ConfigCmd:secure_random` -> `ConfigResp`
8. `WiFiConfigPayload:CmdSetConfig` -> `WiFiConfigPayload:RespSetConfig`
9. `WiFiConfigPayload:CmdApplyConfig` -> `WiFiConfigPayload:RespApplyConfig`

If everything goes right (sometimes I got `WiFi cmd apply errors`, after which I rebooted the device and tried again), the device connects to the given AP and sends a POST request to `auth_url` which returns access tokens, which will then used to call POST `/prod/c/register-device-hash` on the `api_url`. These are not really matter in this process, even more, after the configuration commands are sent, it's possible to just restart the device and it won't connect to these URLs ever again. But if these were not reachable by the device, it will be in a weird state, and won't push some messages to the broker.

## Broker

From this, a trivial way to control the device locally would be to just set the `broker_url` to a local URL, but the device pins AWS root certificate. But this means, that the device can be connected to any AWS IoT broker. After creating my own AWS IoT project, I set the `broker_url` to my AWS IoT broker url, but after that the device couldn't connect to it. It turned out that I must add the device's client certificate to my AWS to allow it to connect to it. This can be easily captured using Wireshark for example. 

After capturing it, and adding it to AWS, the device successfully connected to my broker.

## MQTT topic

The device posts status updates to the broker. Using this, it was easily reverse engineer-able the way the device can be controlled. So at this point, it was achieved that the device can be controlled through my own AWS broker, but the goal was to control it locally.

The device has it's own topic prefix, so each topic mentioned after this has to be appended after `d/<DEVICE_ID>/`. Device ID can be gained from the broker, either by looking on where the device subscribes (by looking at Cloudwatch logs) or by reading the JSON the device pushes to the topic each time it reboots.

## Config read/write

After trial and erroring a bit by connecting the device to the official broker and then connecting it to mine, I discovered the device posted a huge JSON to a topic called `read-r`. This made me think there must be a `read` topic as well, which was true. After posting an empty JSON to this topic, I got error messages on fields which were missing, so I could figure out the schema of the JSON. There is a field in the JSON called `t`, which I fuzzed and found the `State` and `Full` is accepted. `Full` gave me back the same response I was seeing on the first discovery on the `read-r` topic.

This also made me think that there must be a write topic as well. After fuzzing a lot, I found that there is a topic called `prov`. I could use the same trial and error schema as before to figure out the schema of the JSON to this topic. The topic can be invoked without a `_t` field, in which case every configuration parameter must be filled in. By using a `_t` value of `Diff`, it's possible to just partially update the device's configuration.

This topic also includes a `_cas`, which should be the current version of the configuration, but the device sends back the current version in case this is not correct. The JSON also includes an object like: 
```json
{
  // ...,
  "_s": {
    "_sig": ""
  } 
}
```
It turned out the device doesn't validate this signature at all.

Sending JSONs to the `prov` topic without setting `_t` to `Diff` will list all the possible fields, so this it's possible to figure out the exact configuration objects. But I also hooked up the device to UART, and the device validates all the configuration on boot, so I know what certificates/keys the device has, I just didn't know which one does what. 

## Local controlling the device

There is a certificate called `c-r`, which I thought will be the root certificate, so I tried to write it. I created my root certificate, issued an intermediate and a leaf certificate. Then I made a `mosquitto` server, which were using these certificates, and I overwrote the device's `c-r` certificate using the `prov` topic. After this, I re-provisioned it to my own local broker (by setting `broker_url` to a local hostname, like `broker.lan`). After this the device successfully connected to my local broker.

With this method **local control of the device was achieved**, the air purifier is liberated.

The detailed description on the controlling, config reading and writing MQTT topics can be found here.

But I wanted a bit more. I wanted to see if I can run ESPHome on this device (or any custom firmware).

## AWS OTA flow

In parallel to the previously explained broker liberation attempt, I also tried to see if the device accepts any OTAs. An OTA update is in plaintext, so the flash encryption key doesn't need to be known and any firmware could be flashed. The device is using the normal AWS OTA format. After sending a random firmware to device using OTA, it turned out it needs some kind of metadata or manifest JSON file in the OTA. The UART logs came handy, as the device logged out which fields were missing from the JSON. After fuzzing this multiple times, the format was known:

```json
{
  "version": "",
  "images": [
    {
      "size": 0,
      "targetHandler": "",
      "target": "",
      "image": "",
      "sid": 1,
      "signature": {
        "sig": "",
        "salg": ""
      }
    }
  ],
  "signature": {
    "sig": ""
  }
}
```

I just had to figure out what values should be set to each field. After fuzzing a lot again, the following things came out:

- strings cannot be empty strings
- the outer `sig` must be exactly 96 characters long
- the `target` field is an enum of some sort

Then I fuzzed the `target` field for possible values, and it came out that `ESP32` is accepted. After finding this out, I had a valid manifest JSON file, and the device has accepted it, but then it wanted to fetch stream ID 1. So it turned out that the OTA job must consists of a stream where the 1st file is the manifest JSON and the 2nd is the firmware itself. So a valid manifest looks like this, for example:

```json
{
  "version": "2.0.0",
  "images": [
    {
      "size": 1024,
      "targetHandler": "OTA_HANDLER",
      "target": "ESP32",
      "image": "fw_1024.bin",
      "sid": 1,
      "signature": {
        "sig": "MEUCIQC7qZ+OSKyym3M2ttrnE1hMgYtdiGgZOt49ouXQr2ssdwIgBycTZv2gb3LxhyivO4Ev7K3L8sYNUX6coTsIdI9fb/U=",
        "salg": "SHA256withECDSA"
      }
    }
  ],
  "signature": {
    "sig": "MEYCIQCDFwVmlsNGBXyLnCCnrq7UQb2goQAlotMZyQFKUNWI+AIhAOR1IL3NU/ZfgP0/njxABc0exh48iwVRMiiJMpOTQv4c"
  }
}
```

`SHA256withECDSA` was derived from what the device emits to the broker on every boot, and `OTA_HANDLER` were coming from the UART logs. 

After creating a proper OTA update, the process failed on the signature verification. Not surprising. 

But I noticed that the device still subscribes to the second stream topic, just before it cancels the job because of the failed signature verification. What if I don't let the device cancel the job?

## Serve the OTA job locally

I tried some policies in AWS which disables the device to push messages into topics. But by causing this, the OTA couldn't be forwarded to the device. 

So another idea was, what if I serve the whole OTA flow locally. After I create an OTA job in AWS, I delete the stream itself, and serve the files from a Python script. This way the device has no way to cancel anything.

By using this method, after the OTA fails on the signature verification, the firmware is still forwarded to the device, and I could read this on UART:
```
prvUpdateJobStatus] Published to job status topic
OTA: Got 11% ...[prvUpdateJobStatus] Published to job status topic
[prvUpdateJobStatus] Published to job status topic
OTA: Got 22% ...[prvUpdateJobStatus] Published to job status topic
OTA: Got 33% ...[prvUpdateJobStatus] Published to job status topic
[prvUpdateJobStatus] Published to job status topic
OTA: Got 44% ...[prvUpdateJobStatus] Published to job status topic
[prvUpdateJobStatus] Published to job status topic
OTA: Got 55% ...[prvUpdateJobStatus] Published to job status topic
OTA: Got 66% ...[prvUpdateJobStatus] Published to job status topic
[prvUpdateJobStatus] Published to job status topic
OTA: Got 77% ...[prvUpdateJobStatus] Published to job status topic
OTA: Got 88% ...[prvUpdateJobStatus] Published to job status topic
[prvUpdateJobStatus] Published to job status topic
OTA: Got 99% ...[prvIngestDataBlock] Received final expected block of file
[prvIngestDataBlock] Close file...
[Ba_PrintOut_OTA_FileContext]
	uint8_t* pucFilePath		[ESP32]		Local file pathname.
	uint32_t ulFileSize		[967312]		The size of the file in bytes.
	uint32_t ulBlocksRemaining	[0]		How many blocks remain to be received
	uint32_t ulFileAttributes	[0x00000000]		Flags specific to the file being received (e.g. secure, bundle, archive)
	uint32_t ulServerFileID		[1]		The file is referenced by this numeric ID in the OTA job.
	uint32_t ulRequestMomentum	[0]		Number of stream requests published before a response was received.
	uint8_t* pucStreamName		[blueair-stream-1784315856]		stream associated with this file from the OTA service.
	uint8_t* pucRxBlockBitmap	[-]		Bitmap of blocks received (for de-duping and missing block request).
	uint8_t* pucCertFilepath	[SHA256withECDSA]		Pathname of the certificate file used to validate the receive file
	uint32_t ulUpdaterVersion	[0]		Used by OTA self-test detection, the version of FW that did the update.
	bool_t xIsInSelfTest		[0]		True if the job is in self test mode.
[prvIngestDataBlock] Error (1:0x000000) closing OTA file
[Ba_prvOTAUpdateTask_recMsgTypeStream] Aborting due to IngestResult_t error -2
[prvUpdateJobStatus] Published to job status topic
Ba_getNextFileJob, there are no more job -> return kOTA_Err_NoActiveJob
[Ba_prvOTAUpdateTask_recMsgTypeStream] last file (fs1) done, shut down...
```

So the firmware successfully forwarded to the device, written to the partition, but yet again I have some signature verification issues.

After this I went into searching an exploit by fuzzing all the manifest fields, maybe there is an unhandled boundary check or something. I found nothing usable, but there was some time when I could cause an exception, which sometimes logged out the full file path which was used in their official project, like `/codebuild/output/src3821/src/git-codecommit.eu-central-1.amazonaws.com/v1/repos/fw.esp32/BAapplication/components/ota_aws_transport/aws-ota/src/aws_iot_ota_agent.c`. I searched for this file on the web, and this comes from the Amazon FreeRTOS repository. Using the help of AI and this file, I figured out that the firmware is written to the OTA partition, but then the activation fails because of the signature check, and then the partition is erased. 

So if I time plugging out the power cable from the device, I could set a state, where the OTA partition is not erased.

Then AI made a suggestion: I could try restoring the `otadata` region from one of my flash dumps, which could make the device boot up the other OTA partition. It cross-checked my older flash contents against the newer one to locate the `otadata` partition, and came back with `0xa000:0xc000`. I was running the older firmware at the time, so I extracted this slice from the newer dump and then wrote it back.

**After overwriting this region, the device booted up my custom firmware.**

## Analyzing the firmware

Now I had a way of running anything on the device. So AI created a minimal firmware which dumps out the whole flash in plaintext and even decrypts the NVS partitions (because it turned out the NVS partitions are encrypted). This way I can analyze the original firmware as it was still in the other OTA partition. I dumped both the `1.0.4` and the `1.0.6` firmware. Here is the partition table for future reference:

| Name           | Type | SubType  | Offset   | Size | Flags     |
|----------------|------|----------|----------|------|-----------|
| otadata        | data | ota      | 0xa000   | 8K   |           |
| phy_init       | data | phy      | 0xc000   | 4K   |           |
| nvs_key        | data | nvs_keys | 0xd000   | 8K   | encrypted |
| nvs_key_backup | data | nvs_keys | 0xf000   | 8K   | encrypted |
| app0           | app  | ota_0    | 0x20000  | 3M   | encrypted |
| app1           | app  | ota_1    | 0x320000 | 3M   | encrypted |
| coredump       | data | coredump | 0x620000 | 128K |           |
| nvs            | data | nvs      | 0x640000 | 64K  | encrypted |
| certificates0  | data | nvs      | 0x650000 | 128K | encrypted |
| certificates1  | data | nvs      | 0x670000 | 128K | encrypted |
| app0_config    | data | nvs      | 0x690000 | 224K | encrypted |
| app1_config    | data | nvs      | 0x6c8000 | 224K | encrypted |
| app0_mcu       | data | nvs      | 0x700000 | 512K | encrypted |
| app1_mcu       | data | nvs      | 0x780000 | 512K | encrypted |

I used [esp32knife](https://github.com/BlackVS/esp32knife) for dissecting the flash, and [Ghidra](https://github.com/NationalSecurityAgency/ghidra) for analyzing the firmare.

In this part AI take all the weight, as I have no history on how to disassemble a firmware in Ghidra. So I installed an MCP for Ghidra, which can be then used by AI. I wanted to find a way to be able to flash a custom firmware without UART access.

## Factory mode

In the BLE provision custom commands there is a `FactoryCmd` as well, which I tried to use before, but it always failed. The `FactoryCmd` has this structure:
```proto
message FactoryCmd {
  string url = 1;
  string ssid = 2;
  string pwd = 3;
  string token = 4;
}
```
Using the dumped firmware, I found the exact reason why it failed: there is a `k-jwt` field in the device's NVS, which validates the `token` field sent with the `FactoryCmd`. I have a way to overwrite the `k-jwt`, so I created a self-signed RSA key, and created a signed token with the payload of an empty JSON object. Then,I used this token in the `FactoryCmd` and then the device rebooted into factory mode.

In factory mode, the device connects to the given AP, and then the device sends a hello message to the `/fs/hello-message` path of the configured `url`. In this mode, there is also a REPL available in UART, but it also listens on HTTP endpoints. One of the endpoints is `/d/<DEVICE_ID>/provision/image`, which can be used to flash an image. From the decrypted firmware it was then derived how a firmware should be sent to this endpoint, and AI also found that the filename must include the device type. My device type is `nb_l_1.0` (readable using the `read` MQTT topic), and the firmware checks if the image name contains `nb`.

In factory mode, these is also the same manifest file as in the AWS OTA case, but *here the signatures are not verified*.

After sending the firmware in the correct format, I get the following error message in UART:
```bash
I (247745) Http/Server: OTA image is invalid (either not a valid app image, or - if secure boot is enabled - signature failed to verify.)
I (247780) Http/eventlogOTA: Error closing the wifi ota partition (100%)
```

Using this information, AI found out that the firmware also has a burned-in certificate, which validated the image's signature. This mechanism is a [software only secure boot](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/security/secure-boot-v1.html#signed-app-verification-without-hardware-secure-boot). This is a huge pain as this cannot be overwritten. Again, I reached a state, where I can write a custom firmware into the OTA partition, but it cannot be activated. 

But OTA updating through factory mode gave me a new thing: it doesn't erase the OTA partition. I just need to find a way to activate the other OTA partition, so the signature check could be skipped.

## Activate the inactive OTA partition

Flashing the official BlueAir firmware through the factory mode, of course, successes, which is then boots up the other OTA partition, so I have a way to flip to the other partition. I just need a way to flash a custom image after this flip happens.

Both the AWS OTA, and the factory mode image provisioning can take multiple images in the same request. The `target` field, which was fuzzed before, can be set to `STM32` as well. I guess some devices has a separate MCU next to the ESP32, which can be updated using this. AI found a "bug" in the `STM32` update branch, which is specific to the factory mode image provisioning: if the update fails with an `MCU buff is too small` error, the device is not restarting and not erasing anything. 

The device allocates a fixed buffer of `1048832` bytes for the MCU firmware, then checks whether the remaining request body still fits in it. Remaining means the declared `Content-Length` minus everything the ESP32 image already consumed. If it doesn't fit, the handler bails out and returns, without rebooting. In Ghidra this looked like this:

```c
esp_ota_set_boot_partition(part);                 // boot pointer already committed here

if (mcu_size == 0) { ...reboot...; }              // STM32 "size" from the manifest
mcu_buff = malloc(MCU_BUFF /* 1048832 */);
if (remaining_body <= MCU_BUFF) { goto mcu_receive_loop; }
log("MCU buff is too small!");
free(mcu_buff); cJSON_Delete(root);
return -1;                                        // no reboot, no erase
```

Those extra bytes never actually get sent. The comparison is made from the declared `Content-Length`, so the function exits at this arithmetic before it even tries to read any data.

So if we chain these together, we got this:
1. `provision/image` a manifest file which contains 2 images, in this order:
  - `ESP32` - Blueair official firmware
  - `STM32` - invalid `Content-Length` header, but the `size` field in the manifest has to be greater than 0
2. ESP32 path OTA successful, it writes the `otadata` partition to boot the other OTA partition
3. STM32 stage bails with `MCU buff is too small!`, no restart, no erase
4. `provision/image` a custom firmware, which fails at the signature checking
5. Reboot the device

This way, the official firmware sets which partition to boot, but before the device reboots, we can flash our custom firmware on the now active partition. 
**Flashing a custom firmware is achieved fully remotely.**

But the issue is that this need an official firmware dump, which can be only achieved by wiring up the device to UART. I wanted to find a way to do this fully remotely.

## Header only workaround

AI found a smart way to overcome having a firmware dump: the signature check runs on the OTA partition itself, not on the image I send in the OTA update. This is how ESP-IDF works, here is the [esp_ota_end](https://github.com/espressif/esp-idf/blob/5f8de192faeed79f8eacf6f1febaf1401ec8e24f/components/app_update/esp_ota_ops.c#L296) function in the `v4.2` ESP-IDF release. This means, if we write 16 bytes to the other OTA partition, which already contains a valid OTA (from a previous, official update), which is the header of the image, then the signature check will also pass. 16 bytes is needed, because if flash encryption is enabled, the image is written in 16 byte blocks into the partition. The exact 16 bytes is this: `e906023f18180840ee00000000000100`, and here is what it means:

| field                    | value              | varies with                           |
|--------------------------|--------------------|---------------------------------------|
| magic                    | 0xE9               | never                                 |
| segment_count            | 06                 | app memory layout                     |
| spi_mode                 | 02 (DIO)           | sdkconfig                             |
| spi_size/speed           | 3f (8 MB / 80 MHz) | flash size (a 4 MB model would be 2f) |
| entry_addr               | 0x40081818         | app IRAM layout                       |
| wp_pin, pin_drv, chip_id | ee, 000000, 0000   | fixed                                 |
| min_chip_rev             | 01                 | sdkconfig                             |


But there is a problem: `esp_ota_begin` erases the partition before writing anything. If it erases, the valid signed image I was relying on is gone, and the OTA will fail on the signature check. So a second bug is needed to stop the erase from happening.

The erase length is computed from the `size` field of the manifest, which is never validated:

```c
if (size - 1U < 0xFFFFFFFE)                                  // 1 <= size <= 0xFFFFFFFE
    esp_partition_erase_range(part, 0, (size + 0xFFF) & 0xFFFFF000);
else
    esp_partition_erase_range(part, 0, part->size);           // size 0 or -1 -> erase ALL
```

With size = `-2 (0xFFFFFFFE)`, the round-up to sector size overflows: `0xFFFFFFFE + 0xFFF = 0x1_00000FFD`, which truncates to `0x00000FFD`, and `0x00000FFD & 0xFFFFF000 = 0`. `esp_ota_begin` returns success having erased nothing, and the previous official image stays intact in the partition, which will be checked against the signature at the end of the OTA flow.

My first attempt was to write this as an unsigned value, `4294963201` (the same 32 bits as `-4095`), so it should overflow just fine, but it didn't work: the manifest is parsed by cJSON, and cJSON clamps `valueint` to `INT_MAX`. So it arrives as `0x7FFFFFFF`, which doesn't overflow, and `esp_partition_erase_range` rejects the resulting length:
```bash
I (82525) Http/Server: ESP32 image size 2147483647     <- clamped from 4294963201
I (82530) Http/Server: Error opening partition
```

Negative numbers pass through the parser untouched though, and the handler reads the value back as a `uint32_t`. So the same bits work perfectly well, I just have to send a negative number in the JSON. The usable range is `[-4095, -2]`, and I used `-2`. Setting a small size doesn't help either as the erase always rounds up to a full 4 KB sector, so `size = 16` still wipes the first 4096 bytes of the partition which contains the image header and the segment headers that follow it. Only the first 16 bytes are a build constant I can reconstruct without a dump. Because of this, the erase length has to be exactly zero.

Writing to an OTA partition that hasn't been erased would normally corrupt it, but flash encryption is deterministic: the same plaintext at the same address always produces the same ciphertext. So writing the image's own header back over itself changes nothing on the partition. This is the whole trick: the firmware already sitting in that partition has a valid signature, so by writing its own header back it gets accepted again, and the device flips which OTA partition to boot.

So the previous chain changes to:
1. `provision/image` a manifest file which contains 2 images, in this order:
  - `ESP32` - erase bug, then 16 bytes header write
  - `STM32` - invalid `Content-Length` header, but the `size` field in the manifest has to be greater than 0
2. ESP32 path OTA successful, it writes the `otadata` partition to boot the other OTA partition
3. STM32 stage bails with `MCU buff is too small!`, no restart, no erase
4. `provision/image` a custom firmware, which fails at the signature checking
5. Reboot the device

**A fully remote way of flashing a custom firmware has been achieved without the need of an official firmware dump.**

> [!IMPORTANT]  
> This header is valid for this type of device, I assume all `nb` devices. This needs to be tested for other types of devices as well.

## UART factory mode flashing (unpatchable?)

The above methods of changing the device's behaviour (by connecting it to a local broker, or by flashing a custom firmware) is patchable, and needs a previous OTA to be present in the other partition (which is not that big of a deal, I think all devices should have this). Having UART access though is not patchable, so as long as there is a primitive to send an OTA update (either in factory mode or in normal mode using AWS), the firmware can be overwritten.

> [!CAUTION]  
> Creating a flash dump here is more important than at previous steps, because the flash will be modified manually.

By analyzing the firmware more, it turned out that if `k-jwt` is not set, any JWT token is accepted, and also, if a specific flag is not set in the NVS, the device boots to factory mode. If all of the NVS partitions are erased, both is achieved, so by running this, while the device is in `DOWNLOAD_BOOT` mode, all NVS partitions are erased, and the device boots to factory mode with an empty `k-jwt`:
```bash
esptool --before no-reset --after no-reset -p /dev/tty.usbmodem erase-region 0x640000 0x88000 --force
```

After this, the device connects to a preset AP:
- SSID: `BAFactory`
- Password: `9102revreSyrotcaF`

Then, the device connects to the `https://factoryserver.blueair:8443` server, so a DNS rewrite is needed to connect it to my local server.

A custom firmware can be flashed using the `provision/image` endpoint, which then will fail on the signature check. After this, the device needs to be booted again to `DOWNLOAD_BOOT` mode. 

From here, there are 2 ways to go:
- either the current app partition must be corrupted
- or the `otadata` partition needs to be modified (which requires that the device got at least a single OTA update)

### app corruption

If the currently active OTA partition gets corrupted, the other partition gets booted automatically. So for example by erasing some bytes at the beginning of the `app0` or `app1` partition, it can be corrupted. 

> [!TIP]  
> It's advised to create another flash dump before this to be able to restore the state, where one of the partitions contains the custom firmware. Or it's also possible to just erase the magic byte header of the firmware, which can be copied from the other partition. If you accidentally erases a region of the partition which contains the custom firmware, and don't have a way to recover, you have to go through the custom image flashing process again.

app0:
```bash
esptool --before no-reset --after no-reset -p /dev/tty.usbmodem erase-region 0x20000 0x1
```

app1:
```bash
esptool --before no-reset --after no-reset -p /dev/tty.usbmodem erase-region 0x320000 0x1
```

As it's not known which partition is active, this need to be trial and errored. After the currently active OTA partition gets corrupted, the other partition will boot.

### `otadata` switch

The requirement here is the device had to be OTA updated at least once, so both part of the `otadata` partition is valid.
By erasing the parts of it which marks `app0` or `app1`, the other partition can be booted.

Erasing app0's `otadata`:
```bash
esptool --before no-reset --after no-reset -p /dev/tty.usbmodem erase-region 0xa000 0x1000
```

Erasing app1's `otadata`:
```bash
esptool --before no-reset --after no-reset -p /dev/tty.usbmodem erase-region 0xb000 0x1000
```

If after rebooting the official firmware boots again, then you have to restore the `otadata` from your dump, and erase the other app's region.

## Conclusion

In this write-up, I presented a few ways to liberate a BlueAir device. Some are not destructive and restorable (overwriting the root certificate of the device), some are non-restorable without a flash dump.

These methods are not usable for malicious purposes, there is no impact on average users. However, for home automation users, or users who would not want their device to be connected to a cloud provider all the time, this can be helpful.

I didn't include all the things I tried. I've spent more time than I should on trying to find any exploits in the firmware before I had access to it (fuzzing the provisioning part, the OTA process, etc,...), which there weren't any (props to the BlueAir developers!). Heap poisioning protection is also enabled in the firmware, so even when I found something, it was detected. Even after I had the decrypted firmware, there were no usable exploits which would for example give me an RCE to flip the `otadata` partition.

### AI assistant disclosure

I mentioned this many times in the write-up, but I've used AI several times on this process. Reverse engineering the decrypted firmware using Ghidra was done entirely by AI, and it helped me with fuzzing a few times. Without it, it would take me way much more time, or it wouldn't even be possible.
