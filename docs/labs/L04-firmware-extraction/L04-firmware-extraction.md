# L04: Firmware Extraction & Security Audit

## Goal
Audit the device's hardware security posture (secure boot, flash encryption, JTAG), extract the full firmware binary, analyze it for hardcoded secrets, generate an SBOM, and demonstrate what a properly encrypted firmware looks like.

## Background

After gaining debug access (UART/serial console) and understanding the device through logs, the next step is to assess whether the firmware can be extracted at all. On ESP32-S3, two hardware features protect firmware: **secure boot** (prevents running unsigned code) and **flash encryption** (prevents reading firmware from flash). If both are disabled - as they are on this device - the firmware is fully extractable and all embedded secrets are recoverable.

**What you're looking for:**
- Debug interfaces (UART bootloader, JTAG, SWD) that allow firmware extraction
- External flash/EEPROM chips that can be dumped directly or desoldered
- Hardcoded secrets (API keys, encryption keys, passwords)
- Vulnerable code patterns (buffer overflows, command injection)

**Why this happens:** ROM bootloaders are factory-burned and cannot be disabled. JTAG/SWD is often left enabled. No secure boot means the device doesn't verify firmware signatures. Physical access is rarely considered in threat models.

**On CoreS3**: ESP32-S3 provides multiple extraction methods:

**Method 1: ROM Bootloader (UART/USB Download Mode)**
- Factory-burned ROM bootloader, cannot be modified or disabled
- Activated by holding BOOT button during reset (or automatic via DTR/RTS)
- Provides unauthenticated flash read/write via esptool
- **Easiest method** - requires only USB cable

**Method 2: UART Shell Commands**
- Commands like `flashdump`, `partdump`, `memdump` leak firmware data
- No special tools needed - just serial access
- Limited to 4KB chunks

**Method 3: JTAG (Built-in USB JTAG)**
- Full memory access: flash, RAM, CPU registers
- Works via OpenOCD; no external debugger needed on ESP32-S3
- **Most powerful method** - can dump RAM, set breakpoints, single-step

**Finding debug interfaces on unknown IoT devices:**

1. **ROM Bootloader (Easiest):**
   - Look for BOOT/FLASH + RESET buttons
   - Look for UART headers, USB-to-UART chips (CP2102, CH340, FT232)
   - Try: Hold BOOT, press RESET, release BOOT
   - Run: `esptool --port /dev/ttyXXXX chip-id`

2. **JTAG (Most Powerful):**
   - 10-pin or 20-pin headers, test points labeled TDI/TDO/TCK/TMS
   - **SWD (ARM only)**: 2-pin SWDIO/SWCLK
   - Some chips have built-in USB JTAG (ESP32-S3, RP2040) - just plug in USB

3. **External Flash/EEPROM (Chip-off or In-Circuit):**
   - **SPI Flash**: 8-pin SOIC chips (W25Q, MX25L) - use flashrom, Bus Pirate, or CH341A
   - **I2C EEPROM**: 8-pin chips (24CXXX) - use Bus Pirate or logic analyzer
   - **Chip-off**: Desolder flash chip, read with external programmer (destructive but reliable)

**Correlating ESP32-S3 datasheet to CoreS3 hardware:**

1. **USB JTAG (Default - Enabled):**
   - Built-in USB Serial/JTAG controller on GPIO19/20 (USB D+/D-)
   - Appears as USB device `303a:1001` (Espressif USB JTAG/serial debug unit)
   - No external debugger needed

2. **Traditional JTAG Pins (Disabled by Default):**
   - GPIO39 (MTCK/TCK), GPIO40 (MTDO/TDO), GPIO41 (MTDI/TDI), GPIO42 (MTMS/TMS)
   - Enabling requires burning eFuses (permanent/irreversible)
   - On ESP32-S3 chip (QFN56, 0.5mm pitch), not on expansion header
   - During boot, JTAG signals briefly echo on these pins

3. **Which JTAG is active?**
   - Controlled by eFuse bits and GPIO3 strapping pin (see Datasheet Section 3.4)
   - **On CoreS3**: USB JTAG is active (eFuses not burned)

## Lab Walkthrough

### Step 1: Connect and Verify Communication

Connect via USB-C. The ROM bootloader provides unauthenticated flash access; esptool automatically enters bootloader mode via DTR/RTS.

```bash
# Verify communication
ls -l /dev/serial/by-id/
# Expected: usb-Espressif_USB_JTAG_serial_debug_unit_XX:XX:XX:XX:XX:XX-if00 -> ../../ttyACM0

esptool --port /dev/ttyACM0 chip-id

# Expected output:
esptool v5.1.0
Connected to ESP32-S3 on /dev/ttyACM0:
Chip type:          ESP32-S3 (QFN56) (revision v0.2)
Features:           Wi-Fi, BT 5 (LE), Dual Core + LP Core, 240MHz
Crystal frequency:  40MHz
USB mode:           USB-Serial/JTAG
MAC:                10:20:ba:26:ee:fc

Stub flasher running.

Warning: ESP32-S3 has no chip ID. Reading MAC address instead.
MAC:                10:20:ba:26:ee:fc

Hard resetting via RTS pin...
```

### Step 2: Audit Hardware Security (eFuses)

Before extracting firmware, check whether the device's hardware security features would prevent it. On ESP32-S3, three eFuse fields control security: `SECURE_BOOT_EN` (firmware signature verification), `SPI_BOOT_CRYPT_CNT` (flash encryption), and `DIS_USB_JTAG` (JTAG access). Read them with `espefuse.py`, which talks directly to the bootstrap interface - bypassing any firmware that might lie about its own security status.

```bash
# Read security-relevant eFuses
espefuse.py --port /dev/ttyACM0 summary | grep -iE "secure_boot|jtag|crypt|encrypt|key_purpose"

# Expected output:
# SECURE_BOOT_EN (BLOCK0)                          = False R/W (0x0)
# DIS_USB_JTAG (BLOCK0)                             = False R/W (0x0)
# DIS_DOWNLOAD_MANUAL_ENCRYPT (BLOCK0)              = False R/W (0x0)
# SPI_BOOT_CRYPT_CNT (BLOCK0)                       = 0x0 R/W (0b000)
# KEY_PURPOSE_0 (BLOCK0)                            = USER (0x0) R/W
```

**What this tells us:**
- `SECURE_BOOT_EN = False` - No firmware signature verification. Any binary can be flashed and will execute.
- `SPI_BOOT_CRYPT_CNT = 0b000` - Flash encryption disabled. The entire flash is readable in plaintext.
- `DIS_USB_JTAG = False` - JTAG debug port not disabled. Full memory access via OpenOCD.
- `KEY_PURPOSE_0 = USER` - No encryption or signing keys stored in eFuses.

All three protections are disabled. Firmware extraction will succeed via any method (esptool, JTAG, UART commands). On a secured production device, `SECURE_BOOT_EN = True` would prevent flashing unsigned code, `SPI_BOOT_CRYPT_CNT != 0` would encrypt flash contents, and `DIS_USB_JTAG = True` would block debug access.

### Step 3: Dump Entire Flash via ROM Bootloader

Extract complete flash memory containing all code, secrets, and configuration.

```bash
# Dump entire flash (takes ~5 minutes)
# CoreS3 has 16MB flash (board_build.flash_size = 16MB)
esptool --port /dev/ttyACM0 read-flash 0x0 0x1000000 firmware.bin

# Verify file size
ls -lh firmware.bin
# Expected: 16777216 bytes (16 MB)
```

### Step 4: Dump Specific Partitions (Faster)

Extract individual partitions - NVS contains secrets, app contains code.

```bash
# Bootloader (first 32KB at 0x0)
esptool --port /dev/ttyACM0 read-flash 0x0 0x8000 bootloader.bin

# Partition table (8KB at 0x8000)
esptool --port /dev/ttyACM0 read-flash 0x8000 0x2000 partitions.bin

# NVS (secrets - 20KB at 0x9000)
esptool --port /dev/ttyACM0 read-flash 0x9000 0x5000 nvs.bin

# Application firmware (3MB at 0x10000)
esptool --port /dev/ttyACM0 read-flash 0x10000 0x300000 app.bin
```

### Step 5: Dump Flash via UART Console Commands

Use the device's built-in shell commands to dump flash. Many IoT devices include debug commands that leak firmware data without special tools.

**Note:** `memdump`, `flashdump`, and `partdump` require admin mode. Unlock via `login <admin_pin>` first.

```bash
# Connect to serial console
pio device monitor -b 115200

# List available partitions
cores3-cam> part-list

=== Flash Partitions ===
Name             Type       SubType    Offset     Size
------------------------------------------------------------------------
nvs              data       nvs        0x00009000 0x00005000
otadata          data       ota        0x0000e000 0x00002000
factory          app        factory    0x00010000 0x00300000
ota_0            app        ota_0      0x00310000 0x00400000

Total Flash Size: 16777216 bytes (16 MB)

# Dump bootloader (first 64 bytes)
cores3-cam> flashdump 0x0 64

=== Flash Dump: 0x00000000 (64 bytes) ===
00000000: E9 03 02 3F D4 98 3C 40 EE 00 00 00 09 00 00 00  |...?..<@........|
00000010: 00 FF FF 00 00 00 00 01 08 38 CE 3F 4C 04 00 00  |.........8.?L...|
00000020: FF FF FF FF 1B 00 00 00 1B 00 00 00 1C 00 00 00  |................|
00000030: 1C 00 00 00 28 50 04 00 FF 64 00 00 01 00 00 00  |....(P...d......|

=== Dump Complete ===

# Dump NVS partition (contains secrets)
cores3-cam> partdump nvs

=== Partition Dump: nvs ===
Partition: nvs
Address:   0x00009000
Size:      0x00005000 (20480 bytes, 20 KB)
Warning: Only dumping first 4096 bytes (partition is 20480 bytes)
00009000: FC FF FF FF 00 00 00 00 FE FF FF FF FF FF FF FF  |................|
00009010: FF FF FF FF FF FF FF FF FF FF FF FF 84 2D BA B9  |.............-..|
...
000090A0: 02 21 02 FF 01 38 31 19 75 73 65 72 5F 70 69 6E  |.!...81.user_pin|
000090B0: 00 00 00 00 00 00 00 00 07 00 FF FF 74 ED 8D E1  |............t...|
000090C0: XX XX XX XX XX XX 00 FF FF FF FF FF FF FF FF FF  |XXXXXX..........|  <- User PIN (6 random digits)
...
000090E0: 02 21 02 FF D5 80 8C 38 61 64 6D 69 6E 5F 70 69  |.!.....8admin_pi|
000090F0: 6E 00 00 00 00 00 00 00 07 00 FF FF 87 CA E0 74  |n..............t|
00009100: YY YY YY YY YY YY 00 FF FF FF FF FF FF FF FF FF  |YYYYYY..........|  <- Admin PIN (6 random digits)

# Dump memory-mapped flash (0x3C000000 on ESP32-S3)
cores3-cam> memdump 0x3C000000 64

=== Memory Dump: 0x3C000000 (64 bytes) ===
3C000000: 0B 52 0C 07 20 55 10 0C 16 8D 07 50 86 93 80 50  |.R.. U.....P...P|
3C000010: 74 77 95 18 30 56 83 77 20 00 00 42 F8 78 16 00  |tw..0V.w ..B.x..|
3C000020: 34 C1 15 42 7C E2 CA 3F 39 78 1B 3C 20 01 17 3C  |4..B|..?9x.< ..<|
3C000030: 39 01 17 3C CB 94 17 3C 45 01 17 3C 4E 01 17 3C  |9..<...<E..<N..<|

=== Dump Complete ===
```

**Note:** `flashdump` and `partdump` are limited to 4KB per dump. For full extraction, use esptool or JTAG.

### Step 6: Dump Flash via JTAG (Alternative Method)

JTAG provides full debug access even if UART bootloader is disabled via eFuse. Also allows dumping RAM, setting breakpoints, and single-stepping code.

**USB JTAG vs Traditional JTAG:** The ESP32-S3 has two JTAG interfaces (only one active at a time):
- **USB Serial/JTAG Controller** (default) - Uses GPIO19/20 (USB D+/D-)
- **Traditional JTAG pins** - Uses GPIO39/40/41/42 (requires burning eFuses to enable)

**Note:** The USB-Serial/JTAG controller does serial OR JTAG, not both simultaneously. Running esptool (serial mode) disconnects any active OpenOCD JTAG session.

**Using Built-in USB JTAG:**

```bash
# Install OpenOCD with ESP32 support
sudo apt install openocd

# Verify USB JTAG detected
lsusb | grep 303a
# Expected: Bus 001 Device 010: ID 303a:1001 Espressif USB JTAG/serial debug unit
```

**Creating the OpenOCD Config:**

Stock OpenOCD (v0.12.0) includes `esp32s3-bridge.cfg` for external USB bridges (0x303a:0x1002), but NOT for the built-in USB JTAG (0x303a:0x1001). Create a custom config:

```bash
mkdir -p ~/.openocd

cat > ~/.openocd/esp32s3-builtin.cfg << 'EOF'
# ESP32-S3 Built-in USB JTAG Configuration
# For chips with integrated USB Serial/JTAG controller (VID:PID 0x303a:0x1001)

adapter driver esp_usb_jtag
espusbjtag vid_pid 0x303a 0x1001
espusbjtag caps_descriptor 0x2000
adapter speed 40000
source [find target/esp32s3.cfg]
EOF
```

**Start OpenOCD:**

```bash
openocd -f ~/.openocd/esp32s3-builtin.cfg
```

**Expected output:**
```
Info : esp_usb_jtag: Device found. Base speed 40000KHz, div range 1 to 255
Info : JTAG tap: esp32s3.cpu0 tap/device found: 0x120034e5 (mfg: 0x272 (Tensilica))
Info : JTAG tap: esp32s3.cpu1 tap/device found: 0x120034e5 (mfg: 0x272 (Tensilica))
Info : Listening on port 3333 for gdb connections
Info : Listening on port 4444 for telnet connections
```

**Dump Memory via Telnet:**

```bash
# Read memory words (16 words = 64 bytes)
echo -e "halt\nmdw 0x3C000000 16\nresume\nexit" | nc localhost 4444
```

**Expected output:**
```
0x3c000000: 070c520b 0c105520 50078d16 50809386 18957774 77835630 42000020 001678f8
0x3c000020: 4215c134 3fcae27c 3c1b7839 3c170120 3c170139 3c1794cb 3c170145 3c17014e
```

```bash
# Dump flash to file (256 bytes for test, increase for full dump)
echo -e "halt\ndump_image /tmp/jtag_dump.bin 0x3C000000 256\nresume\nexit" | nc localhost 4444

# Verify dump
xxd /tmp/jtag_dump.bin | head

# For full 16MB dump (takes ~10 minutes):
echo -e "halt\ndump_image firmware_jtag.bin 0x3C000000 0x1000000\nresume\nexit" | nc localhost 4444
```

**Using GDB:**

Install Espressif's standalone GDB (the PlatformIO-bundled GDB requires Python 2.7 which isn't available on modern Ubuntu):


**Note:** `xtensa-esp32s3-elf-*` tools are Xtensa cross-tools for ESP32-S3, not standard Linux binaries. See the main [labs README](../LABS.md) for installation instructions.

```bash
cd /tmp
wget https://github.com/espressif/binutils-gdb/releases/download/esp-gdb-v14.2_20240403/xtensa-esp-elf-gdb-14.2_20240403-x86_64-linux-gnu.tar.gz -O esp-gdb.tar.gz
tar xzf esp-gdb.tar.gz
mkdir -p ~/.local/opt ~/.local/bin
mv xtensa-esp-elf-gdb ~/.local/opt/
ln -sf ~/.local/opt/xtensa-esp-elf-gdb/bin/xtensa-esp32s3-elf-gdb ~/.local/bin/

echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

xtensa-esp32s3-elf-gdb --version
# Expected: GNU gdb (esp-gdb) 14.2_20240403
```

Connect with GDB:

```bash
xtensa-esp32s3-elf-gdb .pio/build/M5CoreS3/firmware.elf

(gdb) target remote :3333
(gdb) monitor halt
(gdb) dump binary memory flash_jtag.bin 0x3C000000 0x3C800000
(gdb) monitor resume
(gdb) quit
```

Note: Standard `gdb-multiarch` doesn't understand Xtensa architecture.

**Probing Traditional JTAG Pins (Advanced):**

Traditional JTAG pins are disabled by default, but during boot the ESP32-S3 briefly echoes JTAG signals on these pins for observation with a logic analyzer.

**JTAG Pin Mapping (on ESP32-S3 chip, NOT expansion header):**
```
Pin 44 - GPIO39 (MTCK) - JTAG Clock (TCK)
Pin 45 - GPIO40 (MTDO) - JTAG Data Out (TDO)
Pin 47 - GPIO41 (MTDI) - JTAG Data In (TDI)
Pin 48 - GPIO42 (MTMS) - JTAG Mode Select (TMS)
```

**Probing is very difficult** (0.5mm pitch QFN56 package) - use PCBite probes or solder 30 AWG wire. For firmware extraction, just use the built-in USB JTAG via USB-C.

### Step 7: Analyze Extracted Firmware

Extract secrets from the dumped firmware using `strings`:

```bash
# Search for strings in bootloader
strings bootloader.bin | grep -i "key\|secret\|password"

# Search in application firmware
strings app.bin | grep -i "pin\|password\|api\|key\|secret"

# Look for WiFi credentials
strings firmware.bin | grep -i "ssid\|wifi\|wpa"

# Expected findings:
# encryption_key: 0x1234567890abcdef
# secure_boot_key: disabled
# api_key=1234567890abcdef
```

### Step 8: Convert .bin to ELF for Disassembly

The raw `.bin` from `esptool` cannot be loaded directly into Ghidra or disassembled with `objdump` - it is a flat binary with an ESP32-specific header, not an ELF. You need to convert it to an ELF file that maps each firmware segment to the correct memory address.

The ESP32 `.bin` contains an image header (24 bytes) followed by multiple segments, each with a load address and size. The conversion script parses this header, extracts each segment, and wraps them in a proper ELF32 (Xtensa) with program and section headers.

**Convert using the provided tool:**

```bash
python3 tools/bin2elf.py app.bin firmware.elf
```

**Expected output (sizes vary slightly between builds):**
```
ESP32-S3 firmware: 2186240 bytes, 5 segments
Entry point: 0x40377854
  .flash.rodata: 0x3C190020 (435592 bytes)
  .dram0.data: 0x3FC99A10 (23144 bytes)
  .flash.text: 0x42000020 (1630620 bytes)
  .dram0.bss: 0x3FC9F478 (8192 bytes)
  .iram0.text: 0x40374000 (88592 bytes)

ELF written: firmware.elf
Load in Ghidra (Xtensa:LE:32:default) or use xtensa-esp32s3-elf-objdump -d
```

**What each segment is:**
- `.flash.text` (0x42000000 range): Application code - the main target for reverse engineering
- `.flash.rodata` (0x3C000000 range): Read-only data - strings, constants, lookup tables
- `.iram0.text` (0x40370000 range): Instruction RAM - interrupt handlers, time-critical code
- `.dram0.data` / `.dram0.bss` (0x3FC00000 range): Initialized/uninitialized RAM data

**Verify the ELF works with the Xtensa cross-tools:**

```bash
# Disassemble a section of code (requires xtensa tools on PATH, see main labs README)
xtensa-esp32s3-elf-objdump -d firmware.elf | head -30
# Should show Xtensa instructions (entry, movi, call8, retw, etc.)

# Search for function-like patterns (look for entry instructions)
xtensa-esp32s3-elf-objdump -d firmware.elf | grep "entry" | wc -l
# Shows how many functions the firmware contains
```

**Load into Ghidra:**
```
1. File -> Import File -> select firmware.elf
2. Ghidra auto-detects: Xtensa:LE:32:default (from the ELF header)
3. Click OK -> Yes to auto-analyze
4. The code browser shows disassembled functions at the correct addresses
```

**Note:** The recovered ELF has no symbol table (function names are lost in the .bin extraction). Ghidra's auto-analysis will recover function boundaries, but you will need to identify functions by their behavior (string references, call patterns) rather than by name. This is the standard workflow for reverse engineering firmware from devices in the field.

**Keep both files** - `app.bin` is needed for patching and reflashing (L05, L06), and `firmware.elf` is needed for disassembly and analysis (L06, L11, L18, L19, L20).

### Step 9: Software Bill of Materials (SBOM) Analysis

Generate an inventory of all third-party software components in the firmware, then check each against CVE databases. Modern firmware relies heavily on third-party libraries - each dependency is a potential attack surface. Regulations like US Executive Order 14028 and the EU Cyber Resilience Act increasingly require SBOMs for connected devices.

**The CoreS3 firmware depends on these third-party components:**

| Component | Version Spec | Namespace | License |
|-----------|-------------|-----------|---------|
| espressif32 (ESP-IDF) | 6.1.0 | espressif | Apache-2.0 |
| M5GFX | ^0.1.6 | m5stack | MIT |
| M5Unified | ^0.1.6 | m5stack | MIT |
| LVGL | ^8.3.4 | lvgl | MIT |
| esp32-camera | ^2.0.0 | espressif | Apache-2.0 |
| ArduinoJson | ^6.21.3 | bblanchon | MIT |

```bash
# Step 7a: Generate the SBOM from the project build file
cd tools/
python3 sbom_analyze.py --platformio-ini ../../../../platformio.ini --output sbom.json

# Expected output:
# [*] SBOM Analysis and CVE Check
# ======================================================================
# [*] Parsing dependencies from: ../../../../platformio.ini
#
# [*] Software Bill of Materials (SBOM)
# ======================================================================
#     Format:     CycloneDX 1.4
#     Components: 6
#
#     Component                 Version      Type       License
#     ------------------------------------------------------------------
#     espressif32               6.1.0        framework  Apache-2.0
#     M5GFX                     0.1.6        library    MIT
#     M5Unified                 0.1.6        library    MIT
#     lvgl                      8.3.4        library    MIT
#     esp32-camera              2.0.0        library    Apache-2.0
#     ArduinoJson               6.21.3       library    MIT
#
# [+] SBOM saved to: sbom.json

cat sbom.json | python3 -m json.tool | head -40
```

```bash
# Step 7b: Check dependencies against known CVEs
python3 sbom_analyze.py --platformio-ini ../../../../platformio.ini --check-cves

# Expected output includes a severity-ranked CVE report:
#
# [*] CVE Analysis Report
# ======================================================================
#
#     POTENTIALLY AFFECTED
#     ------------------------------------------------------------------
#
#     [HIGH] CVE-2023-0847 (CVSS 7.5)
#     Component:  espressif/esp32-camera @ 2.0.0
#     Affected:   < 2.0.3
#     Fixed in:   2.0.3
#     Summary:    esp32-camera JPEG decoder heap buffer overflow...
#
#     [MEDIUM] CVE-2023-32259 (CVSS 6.5)
#     Component:  lvgl/lvgl @ 8.3.4
#     Affected:   < 8.3.8
#     Fixed in:   8.3.8
#     ...
#
#     NOT AFFECTED (version is at or above fix)
#     ------------------------------------------------------------------
#     [OK] CVE-2022-0786    lvgl/lvgl (fixed in 8.3.0, have 8.3.4)
#     [OK] CVE-2023-0930    bblanchon/ArduinoJson (fixed in 6.21.0, have 6.21.3)
```

```bash
# Step 7c: Scan the extracted firmware binary for embedded version strings
python3 sbom_analyze.py --firmware ../firmware.bin
```

```bash
# Step 7d: Full combined analysis
python3 sbom_analyze.py \
    --platformio-ini ../../../../platformio.ini \
    --firmware ../firmware.bin \
    --check-cves \
    --output sbom.json

# Produces:
# 1. CycloneDX SBOM (sbom.json) for vulnerability management platforms
# 2. Version confirmation from the firmware binary
# 3. CVE risk assessment with severity ranking and remediation guidance
```

**Key findings from SBOM analysis:**
- Several dependencies have known CVEs (esp32-camera < 2.0.3, LVGL < 8.3.8)
- ESP-IDF bundles dozens of sub-components (FreeRTOS, lwIP, mbedTLS) with their own CVE exposure
- CycloneDX SBOM format enables automated continuous monitoring via tools like OWASP Dependency-Track

### Step 10: See What Encrypted Firmware Looks Like

Use `espsecure.py` to encrypt the firmware binary offline. This does NOT touch the device's eFuses - it runs entirely on your host machine to demonstrate what a properly encrypted flash image looks like vs the plaintext you just extracted.

```bash
# Generate a random 256-bit AES-XTS encryption key
espsecure.py generate-flash-encryption-key flash_key.bin

# Encrypt the firmware binary (same AES-XTS algorithm the ESP32-S3 hardware uses)
espsecure.py encrypt-flash-data \
  --aes-xts \
  --keyfile flash_key.bin \
  --address 0x10000 \
  --output app_encrypted.bin \
  .pio/build/M5CoreS3/firmware.bin

# Compare plaintext vs encrypted
echo "=== PLAINTEXT (first 64 bytes) ==="
xxd .pio/build/M5CoreS3/firmware.bin | head -4

echo "=== ENCRYPTED (first 64 bytes) ==="
xxd app_encrypted.bin | head -4

# Search for secrets in both
echo "=== Plaintext secrets ==="
strings .pio/build/M5CoreS3/firmware.bin | grep -c 'secret123\|admin_pin\|jwt'
# Expected: multiple matches

echo "=== Encrypted secrets ==="
strings app_encrypted.bin | grep -c 'secret123\|admin_pin\|jwt'
# Expected: 0 matches
```

The encrypted binary is the same size but contains zero readable strings. On a device with flash encryption enabled (`SPI_BOOT_CRYPT_CNT != 0`), `esptool read_flash` would return this encrypted data instead of plaintext. The AES key lives in write-protected eFuses and never leaves the silicon - the hardware AES engine decrypts on the fly during boot.

**Why this device doesn't use flash encryption:**
- eFuse burning is **irreversible** - once `SPI_BOOT_CRYPT_CNT` is set, there is no undo
- Development mode allows re-flashing but adds OTA complexity (firmware must be encrypted before upload)
- Release mode is permanent - the device can only ever boot encrypted firmware
- Most prototype/hobbyist devices skip it to avoid bricking during development

**Impact:**
- Confirmed no secure boot, no flash encryption, no JTAG protection via eFuse audit
- Entered ROM bootloader without authentication (esptool)
- Dumped flash via UART shell commands (flashdump, partdump)
- Dumped flash via JTAG (OpenOCD + GDB)
- Extracted all hardcoded secrets from plaintext firmware
- Identified third-party dependencies with known CVEs via SBOM analysis
- Demonstrated the difference between plaintext and encrypted firmware

## Restoring the Device

This lab is read-only - no firmware was modified on the device. If you need to restore to a clean state for any reason:

```bash
# Full erase and reflash
esptool --chip esp32s3 --port /dev/ttyACM0 erase_flash
pio run -e M5CoreS3 -t upload

# Verify
pio device monitor -b 115200
cores3-cam> status
# Should show: Firmware: 1.0.0
```

## References

- **ESP32-S3 Datasheet**: `/datasheets/esp32-s3_datasheet_en.pdf`
  - Section 2.1: Pin Layout (Figure 2-1)
  - Section 2.2: Pin Overview (Table 2-2)
  - Section 3.4: JTAG Signal Source Control
  - Pin 44: GPIO39 (MTCK), Pin 45: GPIO40 (MTDO), Pin 47: GPIO41 (MTDI), Pin 48: GPIO42 (MTMS)
- **esptool.py Documentation**: https://docs.espressif.com/projects/esptool/
- **OpenOCD ESP32 Documentation**: https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/
- **M5Stack CoreS3 Documentation**: https://docs.m5stack.com/en/core/CoreS3
- **CycloneDX SBOM Standard**: https://cyclonedx.org/
- **OWASP Dependency-Track**: https://dependencytrack.org/
- **NTIA Minimum Elements for SBOM**: https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf
- **Google OSV - Open Source Vulnerabilities**: https://osv.dev/
- **CWE-1104: Use of Unmaintained Third-Party Components**: https://cwe.mitre.org/data/definitions/1104.html
- **ESP32-S3 Secure Boot V2**: https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/security/secure-boot-v2.html
- **ESP32-S3 Flash Encryption**: https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/security/flash-encryption.html
- **ESP32 eFuse Documentation**: https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-reference/system/efuse.html
- **CWE-312: Cleartext Storage of Sensitive Information**: https://cwe.mitre.org/data/definitions/312.html
- **CWE-353: Missing Support for Integrity Check**: https://cwe.mitre.org/data/definitions/353.html
