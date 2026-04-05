# L01: UART Debug Console Secrets Leak

## Goal
Extract user PIN and device information from the UART debug console.

## Background

Many IoT devices include UART debug consoles that leak sensitive information through boot logs and status commands. Learning to find and exploit these is a fundamental hardware hacking skill.

**What you're looking for:**
- Debug consoles that output boot logs and diagnostic information
- Secrets leaked in plaintext (passwords, API keys, WiFi credentials)
- Unauthenticated access to device shell or command interface
- Hardware pins that expose UART signals (TX, RX, GND)

**Why this happens:** Debug consoles added during development are left enabled in production. UART provides early boot access before other interfaces are ready, and physical access is often ignored in threat models.

**On CoreS3**: The firmware leaks the user PIN, WiFi credentials, and device configuration during boot and via various commands. The same serial output is available via USB-C (primary) and the debug UART on GPIO43/TXD0 (expansion header pin 14). The expansion header UART is relevant when USB is physically sealed - a logic analyzer can passively sniff the TX line.

```cpp
// From CameraDevice.cpp - init() logs PIN to serial during boot
DualSerial.println("Loading settings...");
DualSerial.printf("User PIN: %s\n", userPIN.c_str());  // Plaintext PIN to UART!
DualSerial.printf("Admin PIN: ******\n");               // Admin masked, but user PIN leaked
```

**UART signals:**
- **TX** (Transmit) - Data output from device
- **RX** (Receive) - Data input to device
- **GND** (Ground) - Common ground reference
- Optional: VCC (power), RTS/CTS (flow control)

**Finding UART on unknown boards:**

1. **Visual inspection:**
   - Look for 3-4 pin headers labeled "UART", "DEBUG", "CONSOLE", "SERIAL"
   - Unpopulated headers near main chip, silkscreen labels: TX, RX, GND, VCC

2. **Multimeter - Voltage mode (POWER ON):**
   - **GND**: 0V (test against known ground like USB shield)
   - **VCC**: Constant voltage
   - **TX**: Fluctuates during boot (idle HIGH at VCC level or LOW at 0V depending on logic)
   - **RX**: Idle HIGH (pulled to VCC level) or LOW at 0V

3. **Oscilloscope/Logic Analyzer (POWER ON):**
   - **TX** shows square wave data bursts during boot
   - Measure baud rate by timing bit width

   **Common baud rates:**
   - **115,200** (8.68 us/bit) - Most common (ESP32, modern embedded)
   - **57,600** (17.4 us/bit) - Common fallback
   - **38,400** (26.0 us/bit) - Legacy systems
   - **19,200** (52.1 us/bit) - Older devices
   - **9,600** (104.2 us/bit) - Very old systems, some GPS modules
   - **31,250** (32 us/bit) - MIDI devices
   - **230,400** (4.34 us/bit) - High-speed applications
   - **250,000** (4.0 us/bit) - DMX512 stage lighting
   - Other rates: 300, 1200, 2400, 4800, 14400, 28800, 76800, 128000, 256000

   **UART voltage levels:**
   - **3.3V TTL/LVTTL** - Most common (ESP32, STM32, Raspberry Pi, ARM Cortex-M)
     - Logic HIGH: 2.0V - 3.3V / Logic LOW: 0V - 0.8V
   - **5V TTL** (Arduino Uno/Mega, older microcontrollers)
     - Logic HIGH: 2.0V - 5.0V / Logic LOW: 0V - 0.8V
   - **2.5V CMOS** (some FPGAs)
   - **1.8V CMOS** (low-power SoCs, mobile processors)
   - **RS-232** (long-distance, inverted logic)
     - Logic HIGH (Mark): -3V to -15V / Logic LOW (Space): +3V to +15V

   **Warning:** Never connect 5V UART to 3.3V devices without level shifters!

   **What UART looks like on a logic analyzer:**

   Example: sending `'A'` (0x41 = 0b01000001) at 115200 baud, LSB first. Each bit = 8.68us. Total frame ~87us.

   ```
        ______      _______________                   __________      __________
   TX        |    |               |                 |          |    |
   (idle     |____|    ___________| ________________|          |____|
    
    =HIGH)   START  D0=1  D1=0      D2-D5=0          D6=1  D7=0    STOP  IDLE
   ```

   | Field | Bits | Level | Duration |
   |-------|------|-------|----------|
   | Idle | - | HIGH (3.3V) | Until data sent |
   | Start | 1 | LOW | 8.68us |
   | D0-D7 | 8 (LSB first) | HIGH=1, LOW=0 | 8.68us each |
   | Stop | 1 | HIGH | 8.68us |

   **PulseView/Saleae decoder settings:** UART, 115200 baud, 8N1. Expected decoded output: `"ESP-ROM:esp32s3-20210327"`

4. **UART discovery tools:**
   - **JTAGulator** - Automated UART pin finder
   - **Bus Pirate** - Can scan for UART signals
   - **Logic analyzer** - Capture and decode (you still select settings)

5. **Trial and error:**
   - Connect USB-to-UART adapter (FTDI, CH340, CP2102)
   - Try common baud rates: 115200, 9600, 57600, 38400
   - Look for readable text; try commands: `help`, `?`, Enter key

**Correlating ESP32-S3 datasheet to CoreS3 hardware:**

1. **ESP32-S3 Serial Interfaces:**
   - **USB-Serial/JTAG Controller** - Built-in USB CDC via GPIO19/20 (USB D-/D+)
   - **Hardware UART0** - GPIO43 (U0TXD) / GPIO44 (U0RXD)
   - These are separate peripherals. The ROM bootloader echoes output to both.

2. **CoreS3 USB-Serial:**
   - USB-C connects to ESP32-S3's internal USB PHY (GPIO19/20)
   - Firmware uses `USBSerial` class (USB CDC-ACM) - appears as `/dev/ttyXXXX`
   - No external USB-UART chip - built into the ESP32-S3

3. **Debug UART on Expansion Header (secondary serial):**
   - **Pin 14 (GPIO43/TXD0)**: Debug UART TX - Echoes ALL serial output
   - **Pin 13 (GPIO44/RXD0)**: Debug UART RX - Receives commands
   - **Pin 1, 3, 5**: Ground
   - Baud rate: 115200, 8N1
   - Mirrors USB-C serial - useful when USB port is sealed

4. **Physical access points on CoreS3:**
   - **USB-C port**: Primary serial (USB CDC-ACM via internal USB PHY)
   - **Expansion header pins 13/14**: Debug UART (TX/RX)
   - **Port.A** (GPIO1/GPIO2): I2C
   - **Port.B** (GPIO8/GPIO9): Available on expansion header
   - **Port.C** (GPIO17/GPIO18): Available on expansion header

5. **Datasheet Section 5.3 - UART Characteristics:**
   - Default baud rate: **115200** (ROM bootloader), format: 8N1
   - Boot messages appear on USB-Serial immediately after power-on
   - ROM bootloader prints: "ESP-ROM:esp32s3-20210327"
   - Supports baud rates: 300 to 5,000,000 bps

6. **Finding Serial on CoreS3 in practice:**
   - Plug in USB-C cable
   - Linux: `ls -l /dev/serial/by-id/` -> look for `usb-Espressif_USB_JTAG_serial_debug_unit_*`
   - Device appears as `/dev/ttyACM0` (USB CDC-ACM)
   - Windows: Device Manager -> Ports (COM & LPT) -> `COM???`
   - Connect: `pio device monitor -b 115200` or `screen /dev/ttyACM0 115200`
   - Press RESET button -> see boot messages

## Lab Walkthrough

### Step 1: Connect to UART

Connect to the serial console to access the debug shell.

```bash
# Find device
ls /dev/ttyACM* /dev/ttyUSB*

# Connect (115200 baud)
pio device monitor -b 115200
# or
screen /dev/ttyACM0 115200

# Expected prompt...you may have to hit enter or type help:
cores3-cam>
```

### Step 2: Observe Boot Sequence

Watch serial output during device boot - boot logs often leak secrets during initialization.

```bash
# Press device reset button while monitoring serial
# Watch the boot output carefully for any leaked information
```

**Tip:** If you completed L00, the device is already configured. You can observe normal boot. To see setup mode boot, you'll need to factory reset (discover how via shell commands).

### Step 3: Enumerate Commands

List available commands to find ones that leak data.

```
cores3-cam> help

# Expected output:
# help, status, nvs-list, nvs-dump, reboot, ...
```

### Step 4: Extract Secrets from Status

Run `status` to see what it reveals.

```
cores3-cam> status

# Expected output:

=== App Status ===
User PIN: ******
Admin PIN: ******
WiFi Configured: No

```

The `status` command masks the PIN. But boot logs (Step 7) print the user PIN in plaintext during initialization - that boot-time leak is the real vulnerability.

### Step 5: Dump NVS Storage

Dump Non-Volatile Storage to check for exposed secrets.

```
cores3-cam> nvs-list

# Expected output:
cores3-cam> nvs-list

=== NVS Storage ===
wifi_ssid: (not set)
wifi_pass: (not set)
user_pin: ******
admin_pin: ******
```

Without authentication, `nvs-list` masks all PINs. The boot log leak (Step 7) is the way in.

### Step 6: Dump Raw NVS Data

Try `nvs-dump` for more detailed NVS contents.

```
cores3-cam> nvs-dump

=== NVS Dump (Key/Value Pairs) ===
ERROR: Admin privileges required.
```

### Step 7: Capture Boot Logs

Reboot and capture boot logs - initialization often leaks secrets in plaintext.

```bash
# Type reboot, watch serial output

cores3-cam> reboot
Rebooting...
ESP-ROM:esp32s3-20210327
Build:Mar 27 2021
rst:0xc (RTC_SW_CPU_RST),boot:0x28 (SPI_FAST_FLASH_BOOT)
Saved PC:0x421616d2
SPIWP:0xee
mode:DIO, clock div:1
load:0x3fce3808,len:0x44c
load:0x403c9700,len:0xbe4
load:0x403cc700,len:0x2a38
entry 0x403c98d4
E (361) esp_core_dump_flash: No core dump partition found!
E (361) esp_core_dump_flash: No core dump partition found!
[  1245][I][esp32-hal-psram.c:96] psramInit(): PSRAM enabled


=================================
CoreS3 IoT Camera Device
=================================

[  2260][I][M5GFX.cpp:553] init_impl(): [M5GFX] [Autodetect] load from NVS : board:10
[  2260][I][esp32-hal-i2c.c:75] i2cInit(): Initialising I2C Master: sda=12 scl=11 freq=100000
[  2269][W][M5GFX.cpp:1228] autodetect(): [M5GFX] [Autodetect] board_M5StackCoreS3
[  2393][I][esp32-hal-i2c.c:75] i2cInit(): Initialising I2C Master: sda=12 scl=11 freq=100000
[  2395][I][esp32-hal-i2c.c:75] i2cInit(): Initialising I2C Master: sda=12 scl=11 freq=100000
[  2402][W][Power_Class.cpp:422] setExtOutput(): [Power] setExtPower(true) is canceled.
[  2440][I][esp32-hal-i2c.c:75] i2cInit(): Initialising I2C Master: sda=12 scl=11 freq=100000
Initializing audio hardware...
...
User PIN: XXXXXX
Admin PIN: ******
```

**Impact:**
- Extracted User PIN: XXXXXX (from boot logs)

### Step 8: Sniff UART with Logic Analyzer

Capture UART traffic using a logic analyzer on the debug UART expansion header. In real-world scenarios, USB may be sealed or disabled, making expansion header UARTs the alternative access path.

**The vulnerability is the secrets in the serial output, not the UART port itself.** A UART debug console is standard engineering practice. The problem is that this firmware leaks credentials in its boot messages without sanitization. The expansion header mirrors USB serial output.

**Debug UART Pins on Expansion Header:**

```
UART Signal Mapping:
- TX (device output) -> GPIO43 (TXD0) - Pin 14 on expansion header
- RX (device input)  -> GPIO44 (RXD0) - Pin 13 on expansion header
- GND (ground)       -> Pin 1, 3, or 5 on expansion header

Expansion Header Pinout (30-pin, relevant section):
  FUNC      PIN     LEFT    RIGHT   PIN     FUNC
  ----      ---     ----    -----   ---     ----
  GND       1               2       G10     ADC
  ...
  RXD0      G44     13      14      G43     TXD0    <- UART pins here!
  ...

For sniffing (passive capture):
- Only TX (Pin 14) is needed - this carries all debug output from the device
- RX (Pin 13) receives input to the device - useful if you want to inject commands

For interactive access (bidirectional):
- Connect TX (Pin 14) to your USB-UART adapter's RX
- Connect RX (Pin 13) to your USB-UART adapter's TX
- Connect GND to GND
```

**Logic Analyzer Setup (Passive Sniffing):**

```
Connections:
- CH0 -> Pin 14 (GPIO43/TXD0) - Debug UART TX output
- GND -> Pin 1, 3, or 5 (Ground)

Decoder Settings (PulseView/Saleae):
- Protocol: UART / Async Serial
- Baud rate: 115200
- Data bits: 8
- Parity: None
- Stop bits: 1
- Bit order: LSB first
```

**USB-UART Adapter Setup (Interactive Access):**

```
Connections (directly to expansion header, alternative to USB-C):
- Adapter RX -> Pin 14 (GPIO43/TXD0) - Device transmits here
- Adapter TX -> Pin 13 (GPIO44/RXD0) - Device receives here
- Adapter GND -> Pin 1, 3, or 5 (Ground)

Terminal Settings:
- Baud: 115200
- Data bits: 8, Parity: None, Stop bits: 1 (8N1)
- Flow control: None
```

**Capture Procedure:**

1. Connect logic analyzer CH0 to pin 14 (GPIO43/TXD0) and GND to pin 1
2. Start capture at 1 MHz sample rate (minimum)
3. Reset the device (press reset button or power cycle)
4. Stop capture after boot messages appear
5. Apply UART decoder to channel 0
6. Look for leaked secrets in the decoded output

**Expected output during boot:**

```
=================================
CoreS3 IoT Camera Device
=================================
...
User PIN: XXXXXX    <- Leaked secret!
Admin PIN: ******
```

**Tools:**
- **Logic Analyzer**: Saleae Logic, DSLogic, cheap 24MHz analyzers ($10-20)
- **USB-UART Adapter**: FTDI FT232, CP2102, CH340 ($2-10)
- **Software**: PulseView (open source), Saleae Logic 2, pio device monitor
- **Probes**: Dupont jumper wires, test clips, PCBite probes

## References

- [ESP32-S3 Technical Reference Manual - UART](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf)
- [ESP32-S3 Datasheet - Pin Definitions](https://www.espressif.com/sites/default/files/documentation/esp32-s3_datasheet_en.pdf)
- [PulseView - Open Source Logic Analyzer Software](https://sigrok.org/wiki/PulseView)
- [Saleae Logic Analyzer](https://www.saleae.com/)
