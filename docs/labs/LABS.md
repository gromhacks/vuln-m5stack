# CoreS3 IoT Security Labs

Welcome to the CoreS3 IoT Security Platform! This hands-on lab environment teaches real-world IoT security vulnerabilities using an M5Stack CoreS3 device (ESP32-S3).

## Overview

This platform provides **32 security labs** covering the full spectrum of IoT penetration testing, from hardware reconnaissance to advanced side-channel attacks. Each lab includes:

- **Educational Background**: Learn the technology and why vulnerabilities exist
- **Real-World Context**: Understand how attacks apply to actual IoT devices
- **Hands-On Exploitation**: Step-by-step instructions with commands
- **Hardening Guidance**: Learn how to fix vulnerabilities
- **Cross-References**: Related labs and further reading

## Lab Philosophy

### Microcontroller vs Microprocessor

**Important**: The ESP32-S3 is a **microcontroller** (no Linux/Unix OS), not a microprocessor. This firmware does **not** have `/bin/sh` or a full filesystem, but it *does* expose its own maintenance shell (`cores3-cam>`) and a set of real HTTP endpoints and lab helpers. All labs in this repository are backed by **real behaviors in this firmware**; where we show Linux-style examples, they are clearly marked as conceptual background, not fake device features.

## Quick Start

### Prerequisites

- [M5Stack CoreS3 ESP32-S3](https://shop.m5stack.com/products/m5stack-cores3-esp32s3-iotdevelopment-kit) device
- USB-C cable
- Computer with PlatformIO (just install it with pip)
- Basic networking knowledge

### Setup

```bash
# Clone repository
git clone <repo-url>
cd vuln-m5stack

# Option A: Flash pre-built firmware (fastest, no toolchain needed)
pip install esptool
./firmware/flash.sh

# Option B: Build from source and flash
pip install platformio
pio run -e M5CoreS3 -t upload

# Monitor serial output
pio device monitor -b 115200
```

### Troubleshooting

- If the device is not reachable, connect your host to the device AP `CoreS3-CAM-XXXX` (AP mode), or if you configured WiFi, use the Station IP shown in serial logs.
- To force AP mode: open the serial shell and run `nvs-clear` then `reboot`. Note: `nvs-clear` requires admin mode (unlock via `login <admin_pin>` or on the touchscreen).

### Device Boot Flow

1. **Setup Mode** (first boot): Device creates Wi-Fi AP `CoreS3-CAM-XXXX` (open; no password)
2. **Web Configuration**: Connect and configure WiFi at http://192.168.4.1
3. **PIN Lock Screen**: Enter 6-digit PIN to unlock
4. **Camera View**: Access camera and web interface
5. **Admin Mode**: Enter admin PIN for advanced features

## Two Ways to Play

### Learning Mode (Labs)
The **32 lab walkthroughs** in this directory (`L00/` through `L31/`) are structured training material. Each lab explains the vulnerability class, walks you through exploitation step by step. Start here if you want to learn "basic" IoT security methodologies from the ground up.

### CTF Mode
If you already know your way around embedded devices and just want to find all the bugs yourself, see **[CTF.md](CTF.md)**. It gives you the rules, the scoring, and some cryptic hints - but no walkthroughs, no explanations, and no hand-holding. Treat the device like a real pentest target and see how many of the 32 vulnerabilities you can find.

---

## Lab Organization

Labs are numbered **L00-L31** following a **logical IoT penetration testing methodology**:

0. **Device Setup & Chip Recon** (L00): Hardware identification, credentials reference, device reset
1. **Reconnaissance & Initial Access** (L01-L04): Hardware debug interfaces, firmware extraction & security audit
2. **Firmware Analysis & Patching** (L05-L07): SD card bypass, binary patching, OTA attacks
3. **Remote Web/API Attacks** (L08-L17): Command injection, authentication bypass, memory corruption, CSRF
4. **Hardware Bus Attacks** (L18-L20): I2C/SPI/BLE buffer overflow exploitation
5. **Wireless Attacks** (L21-L24): BLE credential leak, WiFi rogue OTA, deauth, mDNS spoofing
6. **Wired Attacks** (L25-L27): DFU abuse, memory leaks, race conditions
7. **Cryptographic Attacks** (L28-L30): Weak RNG, key reuse, timing attacks
8. **Forensics** (L31): Data recovery from device storage

---

## Hints & Success Criteria (Quick Reference)

- L00 Device Setup - Hints: Connect serial, observe boot, identify chips; Success: Device boots, serial console works, web interface accessible.
- L01 UART Secrets Leak - Hints: Connect UART at 115200 and watch boot/runtime logs; Success: output contains "User PIN:" with the 6-digit PIN value.
- L02 I2C Sniffing - Hints: Probe Port.A GPIO2 (SDA) and GPIO1 (SCL) during boot; Success: capture I2C transaction to 0x50 containing "ADMINPIN=" in ASCII.
- L03 SPI Debug Logger Leak - Hints: Probe GPIO17 (SCK), GPIO8 (MOSI), GPIO18 (CS) during boot; Success: capture SPI transaction containing "admin_pin=" in ASCII on MOSI.
- L04 Firmware Extraction - Hints: Use esptool download mode or JTAG/OpenOCD; Success: marker "UART download mode allowed" or successful flash dump.
- L05 SD Card Bootloader Bypass - Hints: Place firmware.bin on SD card and reboot; Success: marker "Offline firmware update from SD completed (NO SIGNATURE OR VERSION CHECKS)".
- L06 Binary Patch & Reflash - Hints: Patch comparison branch and reflash; Success: marker "PIN check patched bypass".
- L07 Unsigned OTA Updates - Hints: Upload image without signature; Success: marker "Unsigned OTA accepted" or HTTP 502 from /ota endpoint (no signature verification).
- L08 Command Injection - Hints: Inject metacharacters into SSID and watch serial + shell output; Success: WiFi logs show a constructed command and the injected payload runs as a real `cores3-cam>` command.
- L09 Path Traversal - Hints: Try ../ patterns in name=; Success: response contains a real `admin_pin=` value from the firmware.
- L10 Weak JWT - Hints: Decode token and try weak secrets, then forge; Success: /admin returns 200 OK with forged token.
- L11 Buffer Overflow - Hints: Send 64+ byte exposure parameter to `/camera`; Success: `/admin` returns 200, `/status` shows `admin_mode:true`.
- L12 Format String - Hints: Include %x in HTTP parameters and watch serial output; Success: serial output shows leaked hex stack values.
- L13 Heap Overflow - Hints: Send 48 bytes padding + `ADMIN_TOKEN=granted` via POST /settings/profile; Success: output shows `admin_unlock: true` with both PINs dumped.
- L14 CSRF - Hints: POST to /apply without CSRF token from external origin; Success: device accepts the request, confirming no CSRF protection.
- L15 Unauth Config - Hints: GET /config without token; Success: shows Device Configuration with Admin/User PINs.
- L16 Camera Buffer Leak - Hints: GET `/camera/debug-frame`; Success: response shows stale frame buffer data with BB/AA byte patterns.
- L17 MJPEG No Auth - Hints: Use `/stream?noauth=1`; Success: HTTP 200 with `Content-Type: multipart/x-mixed-replace; boundary=frame`.
- L18 I2C Spoofing - Hints: Overflow I2C slave buffer (32 bytes + address) to hijack function pointer; Success: screen flashes GREEN with "ADMIN UNLOCKED", credentials dumped to serial.
- L19 SPI DMA Overflow - Hints: Overflow DMA buffer (64 bytes + address) to corrupt function pointer; Success: screen flashes RED with "DEBUG ENABLED", debug mode persisted to NVS.
- L20 BLE GATT Overflow - Hints: Overflow BLE GATT characteristic buffer (32 bytes + address); Success: screen flashes BLUE with "PIN BYPASSED", credentials dumped to serial.
- L21 BLE GATT Credential Leak - Hints: Connect via BLE and read the config characteristic; Success: output contains `user_pin=XXXXXX;admin_pin=YYYYYY`.
- L22 WiFi Rogue OTA - Hints: POST URL to `/ota`; Success: device fetches firmware over HTTP without TLS or signature check.
- L23 WiFi Deauth - Hints: Send deauth frames with aireplay-ng; Success: clients disconnect from AP, camera feed drops.
- L24 mDNS Spoofing - Hints: Spoof mDNS response for `cores3-cam.local`; Success: spoofed response redirects traffic to attacker IP.
- L25 Serial Firmware Update - Hints: Use `usb-dfu` serial command (admin required); Success: DFU accepts raw bytes without signature verification.
- L26 Uninitialized Memory Leak - Hints: Use `usb-memleak` (no auth required); Success: hex dump contains `er_pin=XXXXXX;admin_pin=YYYYYY;jwt=secret123`.
- L27 TOCTOU Auth Bypass - Hints: Use `usb-auth usbadmin` then race `usb-cmd` before 2s timeout; Success: command executes during TOCTOU window.
- L28 Weak RNG - Hints: Request 3+ tokens from `/api/token`; Success: tokens match ESP32 newlib 64-bit LCG with seed 12345.
- L29 Key Reuse - Hints: Crack JWT secret from L10, use same secret to forge admin tokens; Success: forged JWT accepted on all protected endpoints.
- L30 Timing Attack on PIN - Hints: Measure `/api/check_pin` response timing per digit; Success: correct digits take measurably longer (50ms/char delay visible in HTTP response time and serial [PINCHK] log).
- L31 Forensic Recovery - Hints: Trigger `forensics-snap` (admin required) and read `/logs/debug-exif.txt`; Success: EXIF-style text file contains `user_pin`, `admin_pin`, `wifi_ssid`.


## Phase 0: Device Setup & Chip Recon (L00)

**Goal**: Understand the hardware before attacking it

**ALWAYS START HERE**

### L00: Device Setup & Chip Reconnaissance
- **What you'll learn**: Hardware identification, chip recon, device boot flow, credentials
- **Tools**: Serial terminal, multimeter, datasheets
- **Time**: 30 minutes
- **Why start here**: Every pentest begins with recon - know your target

---

## Phase 1: Reconnaissance & Initial Access (L01-L04)

**Goal**: Gain low-level hardware access and extract firmware

### L01: UART Debug Console Secrets Leak
- **What you'll learn**: UART protocol, serial communication, debug interfaces
- **Tools**: USB-to-UART adapter, serial terminal
- **Time**: 30 minutes
- **Why start here**: Teaches fundamental hardware access that enables other labs

### L02: I2C Bus Sniffing for Secrets
- **What you'll learn**: I2C protocol, bus sniffing, logic analyzers, bit-banged signals
- **Tools**: Logic analyzer (>=2 MHz), sigrok/PulseView or Saleae Logic
- **Time**: 1 hour
- **Hardware**: Teaches bus protocol basics and passive sniffing techniques
- **Key technique**: Capture boot-time I2C transaction containing admin PIN and WiFi password

### L03: SPI Debug Logger Leak
- **What you'll learn**: SPI protocol, flash memory access, passive sniffing
- **Tools**: Logic analyzer (>=10 MHz), sigrok/PulseView or Saleae Logic
- **Time**: 1 hour
- **Hardware**: SPI bus analysis and multi-signal capture
- **Key technique**: Capture boot-time SPI transaction containing admin PIN, WiFi password, and API key

### L04: Firmware Extraction & Security Audit
- **What you'll learn**: ESP32 bootloader, download mode, JTAG, OpenOCD, firmware extraction, SBOM generation, CVE analysis
- **Tools**: esptool.py, OpenOCD, xtensa-esp32s3-elf-gdb
- **Time**: 1 hour
- **Prerequisite**: L01 (UART basics)
- **Why critical**: Foundation for all firmware analysis - teaches both UART and JTAG extraction methods

---

## Phase 2: Firmware Analysis & Patching (L05-L07)

**Goal**: Analyze and modify firmware

### L05: SD Card Bootloader Bypass
- **What you'll learn**: Offline firmware updates, physical access attacks, signature verification bypass
- **Tools**: SD card, FAT32 filesystem
- **Time**: 30 minutes
- **Impact**: Complete device compromise via brief physical access
- **Real-world**: Common in industrial IoT, medical devices, security cameras

### L06: Binary Patch & Reflash
- **What you'll learn**: Reverse engineering, binary patching, Ghidra
- **Tools**: Ghidra, hex editors, Python
- **Time**: 2 hours
- **Prerequisite**: L04 (firmware extraction)
- **Why advanced**: Enables persistent backdoors

### L07: Unsigned OTA Updates
- **What you'll learn**: OTA updates, code signing, firmware verification
- **Tools**: curl, custom firmware
- **Time**: 1 hour
- **Impact**: Complete remote device compromise with no signature checks

---

## Phase 3: Remote Web/API Attacks (L08-L17)

**Goal**: Exploit web vulnerabilities

**START HERE for web security focus**

### L08: Command Injection in WiFi Setup
- **What you'll learn**: Embedded-shell command injection, shell metacharacters, input validation
- **Tools**: curl, Burp Suite, serial console
- **Time**: 30 minutes
- **Note**: Real injection into the `cores3-cam>` maintenance shell via the WiFi setup handler

### L09: Path Traversal
- **What you'll learn**: Directory traversal, file access, path validation
- **Tools**: curl, browser
- **Time**: 30 minutes
- **Common vulnerability**: Found in many IoT devices

### L10: Weak JWT Secret
- **What you'll learn**: JWT format, HMAC-SHA256, secret brute-forcing, token forging
- **Tools**: Python, PyJWT, jwt.io, custom forging tool
- **Time**: 1 hour
- **Why critical**: Required for all other authenticated labs

### L11: Buffer Overflow - Function Pointer Hijack
- **What you'll learn**: Memory corruption, stack smashing, bounds checking
- **Tools**: curl, debugger
- **Time**: 1 hour
- **Advanced**: Requires understanding of memory layout

### L12: Format String Vulnerability
- **What you'll learn**: Printf format string attacks, stack reading, information disclosure
- **Tools**: curl, serial terminal
- **Time**: 45 minutes
- **Key technique**: Use %x format specifiers in HTTP parameters to leak stack memory via UART

### L13: Heap Buffer Overflow
- **What you'll learn**: Heap memory corruption, adjacent allocation overwrites
- **Tools**: Serial terminal
- **Time**: 45 minutes
- **Comparison**: Contrast with stack-based L11 buffer overflow

### L14: Cross-Site Request Forgery (CSRF)
- **What you'll learn**: CSRF attacks, token validation, same-origin policy
- **Tools**: Browser, HTML page, curl
- **Time**: 30 minutes
- **Chain**: Combine with L08 command injection for browser-based RCE

### L15: Unauthorized Configuration Access
- **What you'll learn**: Missing authentication, information disclosure
- **Tools**: curl, browser
- **Time**: 15 minutes
- **Why easiest**: No exploitation skills needed, just access unprotected endpoints

### L16: Camera Buffer Information Leak
- **What you'll learn**: Memory leaks, PSRAM, buffer reuse, image forensics
- **Tools**: curl, image analysis tools
- **Time**: 45 minutes
- **Forensics**: Extract data from leaked memory

### L17: MJPEG Stream Without Authentication
- **What you'll learn**: Authentication bypass, video streaming, MJPEG protocol
- **Tools**: curl, forged JWT from L10
- **Time**: 30 minutes
- **Prerequisite**: L10 (JWT forging)

---

## Phase 4: Hardware Bus Attacks (L18-L20)

**Goal**: Attack hardware communication buses

### L18: I2C Spoofing & Buffer Overflow - Function Pointer Hijack
- **What you'll learn**: I2C device spoofing, bus injection, active attacks
- **Tools**: Raspberry Pi Pico (MicroPython), I2C tools
- **Time**: 1.5 hours
- **Prerequisite**: L02 (I2C basics)

### L19: SPI DMA Buffer Overflow - Function Pointer Hijack
- **What you'll learn**: DMA, SPI transfers, buffer overflows
- **Tools**: Logic analyzer, debugger
- **Time**: 1.5 hours
- **Advanced**: Memory corruption via DMA


### L20: BLE GATT Buffer Overflow - Function Pointer Hijack
- **What you'll learn**: BLE protocol, GATT, buffer overflows
- **Tools**: nRF Connect, Wireshark
- **Time**: 1.5 hours
- **Wireless**: BLE basics

---

## Phase 5: Wireless Attacks (L21-L24)

**Goal**: Attack wireless communication channels

### L21: BLE GATT Credential Leak
- **What you'll learn**: BLE GATT services, characteristic reading, credential extraction
- **Tools**: bleak (Python), nRF Connect, or Pico W
- **Time**: 1 hour
- **Wireless**: BLE passive data extraction

### L22: WiFi Rogue OTA
- **What you'll learn**: MITM attacks, TLS, certificate validation
- **Tools**: mitmproxy, Wireshark
- **Time**: 1.5 hours
- **Advanced**: Requires network attack skills

### L23: WiFi Deauthentication Attack
- **What you'll learn**: 802.11 management frames, PMF, denial of service
- **Tools**: aircrack-ng suite, monitor mode adapter
- **Time**: 45 minutes
- **Wireless**: WiFi layer 2 attacks

### L24: mDNS Service Spoofing
- **What you'll learn**: mDNS protocol, service discovery, spoofing, MITM
- **Tools**: Python/scapy, avahi-browse, Wireshark
- **Time**: 1 hour
- **Network**: Zero-configuration networking attacks

---

## Phase 6: Serial Interface Attacks (L25-L27)

**Goal**: Attack serial console interfaces

### L25: Serial Firmware Update (Unsigned DFU)
- **What you'll learn**: Unsigned firmware updates via serial console, lack of signature verification
- **Tools**: Serial terminal, pyserial
- **Time**: 1 hour
- **Prerequisite**: Admin PIN (from earlier labs)

### L26: Uninitialized Memory Leak
- **What you'll learn**: Uninitialized buffer disclosure, memory residue, CWE-908
- **Tools**: Serial terminal, hex decoder
- **Time**: 1 hour
- **No auth required**: Hidden serial command

### L27: TOCTOU Authentication Bypass
- **What you'll learn**: TOCTOU race conditions, FreeRTOS concurrency, volatile vs mutex
- **Tools**: Python, pyserial
- **Time**: 1.5 hours
- **Advanced**: Requires understanding of concurrent task execution

---

## Phase 7: Cryptographic Attacks (L28-L30)

**Goal**: Break cryptographic implementations

### L28: Weak Random Number Generator
- **What you'll learn**: Random number generation, predictability, LCG weaknesses
- **Tools**: Python, statistical analysis
- **Time**: 1 hour
- **Cryptography**: Understanding of PRNGs

### L29: Cryptographic Key Reuse
- **What you'll learn**: Key management, key reuse attacks, nonce reuse
- **Tools**: Python, cryptanalysis tools
- **Time**: 45 minutes
- **Cryptography**: Understanding of symmetric encryption

### L30: Timing Attack on PIN Verification
- **What you'll learn**: Timing attacks, side channels, statistical analysis
- **Tools**: Python, timing measurement scripts
- **Time**: 1.5 hours
- **Advanced**: Requires statistical analysis skills

---

## Phase 8: Forensics (L31)

**Goal**: Recover data from device storage

### L31: Forensic Data Recovery
- **What you'll learn**: SD card forensics, deleted data recovery, EXIF metadata extraction
- **Tools**: binwalk, foremost, serial console
- **Time**: 1 hour
- **Forensics**: Data recovery techniques

---

## Tools & Resources

### Required Software
- **PlatformIO**: Build and flash firmware
- **Python 3**: Scripting and exploitation
- **esptool.py**: ESP32 firmware extraction and flashing (included with PlatformIO)
- **curl**: HTTP client for API testing
- **sigrok/PulseView**: Logic analyzer capture and decode
- **aircrack-ng**: WiFi monitor mode and deauth attacks
- **bleak** (Python): BLE scanning and GATT operations

### Required Hardware

You will need the CoreS3 board plus a handful of affordable tools. Any equivalent hardware works - these are just examples:

- **Logic analyzer** - USB Logic Analyzer, 8 CH 24MHz (FX2-based, works with sigrok/PulseView): https://a.co/d/0fW1Hutd
- **Raspberry Pi Pico** - Official RP2040 board with headers: https://a.co/d/05RSPcKR
- **Raspberry Pi Pico 2** - RP2350 (also works): https://a.co/d/0hWq2tjx
- **WiFi adapter** - Monitor mode capable (Atheros AR9271 or RTL8812AU chipset): https://a.co/d/0hQgr0Wu
- **Dupont wires** - Eiechip 120-pin jumper wire kit (M-M, M-F, F-F): https://a.co/d/0glzaPCu
- **Multimeter** - AstroAI TRMS 6000 or equivalent: https://a.co/d/0hyTI6IS or https://a.co/d/09mKE6xm
- **Soldering iron** - Any basic kit for header pins (or buy Picos with pre-soldered headers)
- **MicroSD card** - Any 16GB+ FAT32-formatted card, plus a USB card reader

No expensive tools like J-Link debuggers, oscilloscopes, Bus Pirates, or ChipWhisperers required.

### Firmware & Source Code

The full source code is available at the project root. You can read it directly, grep for patterns, or use it alongside Ghidra decompilation.

```
src/
+-- main.cpp                  # Entry point, wires CameraDevice + CameraApp + SerialShell
+-- CameraApp.cpp/.h          # Touchscreen UI (LVGL): PIN entry, camera view, admin, self-test
+-- CameraDevice.cpp/.h       # Core singleton: init(), loop(), device lifecycle
+-- CameraDevice_Camera.cpp   # Camera hardware init, JPEG frame capture
+-- CameraDevice_Audio.cpp    # Speaker and microphone hardware
+-- CameraDevice_Auth.cpp     # JWT signing/verification, PIN check, NVS settings
+-- CameraDevice_Web.cpp      # HTTP server: all routes and request handlers
+-- CameraDevice_Admin.cpp    # Admin panel endpoints (status, NVS, reboot, self-test)
+-- CameraDevice_Bus.cpp      # I2C/SPI/BLE bus operations and peripheral handlers
+-- CameraDevice_Diag.cpp     # Diagnostic hooks via run_diagnostic() (debug builds)
+-- CameraDevice_Internal.h   # Shared declarations between CameraDevice modules
+-- SerialShell.cpp/.h        # UART command-line interface (user and admin commands)

include/
+-- config.h                  # Hardware pin definitions, I2C addresses, GPIO assignments
+-- DualSerial.h              # Dual-output serial (USB CDC + debug UART on GPIO43/44)
+-- lv_conf.h                 # LVGL display library configuration

lib/
+-- BMI270-Sensor-API/        # Accelerometer/gyroscope driver (Bosch)
+-- BMM150-Sensor-API/        # Magnetometer driver (Bosch)
+-- lv_anim_label/            # LVGL animated label widget
+-- lv_ext/                   # LVGL extension widgets
+-- lv_poly_line/             # LVGL polyline drawing widget
+-- m5gfx_lvgl/               # M5GFX display driver bridge for LVGL
+-- PageManager/              # UI page/screen navigation manager
+-- ResourceManager/          # Asset and resource management
+-- libesp32-camera.a         # Pre-compiled ESP32 camera driver
```

After building (`pio run -e M5CoreS3`), the compiled firmware is at:

- `.pio/build/M5CoreS3/firmware.bin` - Raw binary (for flashing, `strings`, hex analysis)
- `.pio/build/M5CoreS3/firmware.elf` - ELF with debug symbols (for Ghidra, `nm`, `objdump`, GDB)

You can also dump firmware from a live device with `esptool.py read_flash` (see L04) and convert it to ELF with `docs/labs/L04-firmware-extraction/tools/bin2elf.py`. Ghidra with the Xtensa processor module is recommended for static reverse engineering.

### Xtensa Cross-Tools (required for L04, L06, L11, L18, L19, L20)

Several labs use the Xtensa cross-compilation tools (`xtensa-esp32s3-elf-nm`, `xtensa-esp32s3-elf-objdump`, `xtensa-esp32s3-elf-gdb`) to disassemble firmware, look up symbol addresses, and debug. These are NOT standard Linux tools - they are specific to the ESP32-S3's Xtensa LX7 architecture.

**Option A: PlatformIO (already installed if you can build firmware)**

PlatformIO installs the Xtensa toolchain automatically. The tools are in the PlatformIO packages directory but not on your PATH by default:

```bash
# Find where PlatformIO installed the toolchain
find ~/.platformio/packages -name "xtensa-esp32s3-elf-nm" 2>/dev/null
# Typical path: ~/.platformio/packages/toolchain-xtensa-esp32s3/bin/

# Add to PATH for the current session
export PATH="$HOME/.platformio/packages/toolchain-xtensa-esp32s3/bin:$PATH"

# Make it permanent (add to ~/.bashrc or ~/.zshrc)
echo 'export PATH="$HOME/.platformio/packages/toolchain-xtensa-esp32s3/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Verify
xtensa-esp32s3-elf-nm --version
```

**Option B: Espressif official toolchain (standalone install)**

Download the prebuilt toolchain directly from Espressif:

```bash
# Download the latest Xtensa ESP32-S3 toolchain for Linux x86_64
# Check https://github.com/espressif/crosstool-NG/releases for the latest version
wget https://github.com/espressif/crosstool-NG/releases/download/esp-13.2.0_20240530/xtensa-esp-elf-13.2.0_20240530-x86_64-linux-gnu.tar.xz

# Extract to /opt or ~/.local
sudo tar xf xtensa-esp-elf-13.2.0_20240530-x86_64-linux-gnu.tar.xz -C /opt/
# Or: tar xf xtensa-esp-elf-*.tar.xz -C ~/.local/opt/

# Add to PATH
export PATH="/opt/xtensa-esp-elf/bin:$PATH"
echo 'export PATH="/opt/xtensa-esp-elf/bin:$PATH"' >> ~/.bashrc

# Verify
xtensa-esp32s3-elf-nm --version
xtensa-esp32s3-elf-objdump --version
```

**Option C: ESP-IDF (full development framework)**

If you install ESP-IDF via `install.sh`, it includes the toolchain:

```bash
# See https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/get-started/
git clone --recursive https://github.com/espressif/esp-idf.git
cd esp-idf && ./install.sh esp32s3
source export.sh

# Tools are now on PATH
xtensa-esp32s3-elf-nm --version
```

### Raspberry Pi Pico Setup (required for L18, L19, L20)

Several hardware attack labs use a Raspberry Pi Pico (~$4) running MicroPython as the attacker board. This section covers initial setup - you only need to do this once.

**Step 1: Flash MicroPython onto the Pico**

```bash
# Download the latest MicroPython UF2 for Raspberry Pi Pico
wget https://micropython.org/download/RPI_PICO/RPI_PICO-latest.uf2

# Put the Pico into bootloader mode:
#   1. Hold the BOOTSEL button on the Pico
#   2. Plug in the USB cable (while still holding BOOTSEL)
#   3. Release BOOTSEL - the Pico mounts as a USB drive called "RPI-RP2"

# Copy the UF2 file to the drive
cp RPI_PICO-latest.uf2 /media/$USER/RPI-RP2/

# The Pico reboots automatically into MicroPython
# It now appears as a serial device (e.g., /dev/ttyACM1)
```

**Step 2: Install `mpremote` (command-line tool for managing MicroPython devices)**

```bash
pip install mpremote

# Verify connection
mpremote connect /dev/ttyACM1 exec "print('Pico ready')"
```

**Step 3: Copy a script to the Pico and run it**

```bash
# Copy a MicroPython script to the Pico's filesystem
mpremote connect /dev/ttyACM1 cp i2c_exploit.py :i2c_exploit.py

# Run it
mpremote connect /dev/ttyACM1 run i2c_exploit.py

# Or open an interactive REPL
mpremote connect /dev/ttyACM1 repl
```

**Alternative: Use Thonny IDE**

Thonny (https://thonny.org) provides a graphical MicroPython IDE with file management:

```bash
sudo apt install thonny
# Open Thonny -> Tools -> Options -> Interpreter -> MicroPython (Raspberry Pi Pico)
# Select port: /dev/ttyACM1
# Open your .py file -> click Run (F5)
# Use File -> Save As -> select "Raspberry Pi Pico" to save directly to the device
```

**Note on serial port numbering:** When both the CoreS3 and Pico are plugged in via USB, the CoreS3 is typically `/dev/ttyACM0` and the Pico is `/dev/ttyACM1`. Check with `ls /dev/ttyACM*` if unsure.

### Optional (But Useful) Software
- **Burp Suite**: Web application proxy and testing
- **Ghidra**: Firmware reverse engineering and disassembly
- **Wireshark**: Network and BLE protocol analysis
- **nRF Connect** (mobile app): BLE service browser
- **scapy** (Python): Low-level packet crafting (mDNS spoofing, deauth)
- **Thonny**: Graphical MicroPython IDE for Pico

### Provided Tools
- **`docs/labs/L10-weak-jwt/tools/forge_jwt.py`**: JWT token forging, decoding, and verification
- **`docs/labs/L04-firmware-extraction/tools/bin2elf.py`**: Convert ESP32 raw .bin to ELF for Ghidra/objdump

---

## Further Reading

- [OWASP IoT Top 10](https://owasp.org/www-project-internet-of-things/)
- [IoT Penetration Testing Cookbook](https://www.packtpub.com/product/iot-penetration-testing-cookbook/9781787280571)
- [Hardware Hacking Handbook](https://nostarch.com/hardwarehacking)
- [ESP32 Technical Reference](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf)

---

## License

This platform is for educational purposes only. Do not use these techniques on devices you don't own or have permission to test.
