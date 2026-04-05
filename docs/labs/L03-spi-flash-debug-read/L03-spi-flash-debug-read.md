# L03: SPI Debug Logger Leak

## Goal
Sniff debug SPI bus at boot to capture secrets transmitted to external debug logger.

## Background

Developers sometimes add external SPI loggers during development to capture boot diagnostics. These loggers can leak secrets if left enabled in production.

**What you're looking for:**
- Boot logs containing WiFi passwords or API keys
- Admin PINs or unlock codes in diagnostic messages
- Device secrets written to external SPI flash/EEPROM
- External SPI flash chips that can be dumped or modified

**Why this happens:** SPI has no built-in encryption or authentication. External SPI flash chips are easily accessible on PCBs. Debug logging to SPI is often left enabled in production builds.

**Beyond passive sniffing:** Active SPI attacks include firmware extraction (L04), firmware modification (L06), DMA buffer overflow (L19), command injection, chip-off attacks, and glitching during SPI reads.

**On CoreS3**: The firmware uses SPI to write debug logs containing the admin PIN and WiFi credentials during boot, capturable by sniffing the SPI bus.

```cpp
// From CameraDevice_Bus.cpp - emit_spi_boot_log()
String payload = String("admin_pin=") + adminPIN +
                 ";wifi_pass=" + wifiPass +
                 ";api_key=1234567890abcdef" +
                 ";extra_secret=" + extraSecret;
// Bit-banged SPI write to debug logger on GPIO8/17/18
digitalWrite(SPI_LOG_CS, LOW);
for (size_t i = 0; i < payload.length(); ++i) {
    sendByte(static_cast<uint8_t>(payload[i]));  // Secrets on MOSI
}
digitalWrite(SPI_LOG_CS, HIGH);
```

**SPI signals:**
- **MOSI** (Master Out, Slave In) - Data from MCU to flash
- **MISO** (Master In, Slave Out) - Data from flash to MCU
- **SCK** (Serial Clock) - Clock signal
- **CS** (Chip Select) - Activates flash chip (active LOW)

**Finding SPI devices on unknown boards:**

1. **Chip identification:**
   - Look for 8-pin SOIC/WSON chip near main processor
   - **SPI Flash/EEPROM**: W25QXXX, GD25QXXX, MX25LXXX, AT25DFXXX, S25FLXXX, 25LCXXX
   - **SPI-to-UART bridges**: MAX3100, SC16IS750, SC16IS752
   - **SPI GPIO expanders**: MCP23S08, MCP23S17
   - Search chip marking + "datasheet" for pinout

2. **Visual PCB tracing:**
   - Debug chips usually near test points or debug headers
   - Look for test points labeled MOSI/MISO/SCK/CS, DEBUG, LOG, DIAG
   - Check for unpopulated footprints (debug chips removed before production)

3. **Multimeter - Voltage mode (POWER ON):**
   - Pin 1 (CS): Idle HIGH (3.3V), pulses LOW during access
   - Pin 2 (MISO): Varies during communication
   - Pin 5 (MOSI): Varies during communication
   - Pin 6 (SCK): Idle LOW or HIGH, pulses during access
   - Pin 8 (VCC): 3.3V constant
   - Pin 4 (GND): 0V constant

4. **Oscilloscope/Logic Analyzer (POWER ON):**
   - SCK: fast square wave (1-80 MHz)
   - CS goes LOW before each transaction
   - MOSI/MISO show data synchronized with SCK

   **What SPI looks like on a logic analyzer:**
   SPI read transaction (command 0x03, address 0x000000, Mode 0):

   ```
   CS   ~~\__________________________________/~~   (LOW = active)
   SCK  ____/~\/~\/~\/~\/~\/~\/~\/~\/~\/~\/~\__   (clock pulses)
   MOSI ====< 0x03 >< 0x00  0x00  0x00 >========   (master sends cmd+addr)
   MISO ====< ---- don't care ---- >< 0xE9 ... >   (slave returns data)
              command    address       response
   ```

   | Phase | MOSI sends | MISO returns | Clocks |
   |-------|-----------|-------------|--------|
   | Command | 0x03 (READ) | ignored | 8 |
   | Address | 0x00 0x00 0x00 | ignored | 24 |
   | Data | don't care | 0xE9 0x08 ... (flash contents) | continuous |

   CS goes LOW to start, HIGH to end. Data clocked on SCK rising edge (Mode 0: CPOL=0, CPHA=0).

   **PulseView/Saleae decoder:** SPI, CLK=CH0(GPIO17), MOSI=CH1(GPIO8), MISO=CH2(GPIO9), CS=CH3(GPIO18), Mode 0, MSB first.

   **Common SPI flash commands:** 0x03 Read, 0x0B Fast Read, 0x9F Read JEDEC ID, 0x05 Read Status.

   **Timing:** Standard SPI up to 50 MHz. CoreS3 debug SPI (bit-banged): ~333 kHz (3us/bit).

5. **Standard SPI flash pinout (8-pin SOIC):**
   - Pin 1: /CS, Pin 2: DO (MISO), Pin 3: /WP, Pin 4: GND
   - Pin 5: DI (MOSI), Pin 6: CLK (SCK), Pin 7: /HOLD, Pin 8: VCC

**Correlating ESP32-S3 datasheet to CoreS3 hardware:**

1. **ESP32-S3 SPI Interfaces:**
   - **SPI0/SPI1**: Main flash interface (GPIO27-33, inside module, not accessible)
   - **SPI2/SPI3**: General-purpose SPI (any GPIO via GPIO Matrix)

2. **Debug SPI Logger on CoreS3:**
   - Main flash: **16MB** inside ESP32-S3 (not accessible without desoldering)
   - Debug SPI logger: bit-banged on Port.B (GPIO8/9) and Port.C (GPIO17/18)
   - Simulates a developer's SPI logger left enabled in production

3. **Debug SPI Logger Pins:**
   - **GPIO17 (Port.C) -> DEBUG_SPI_SCK**: ~333 kHz clock
   - **GPIO8 (Port.B) -> DEBUG_SPI_MOSI**: Data from MCU (contains secrets!)
   - **GPIO9 (Port.B) -> DEBUG_SPI_MISO**: Unused (write-only logger)
   - **GPIO18 (Port.C) -> DEBUG_SPI_CS**: Chip select (active LOW)
   - Single SPI transaction emitted at boot (~2.7 seconds after reset)
   - Bit-banging avoids conflicts with SD card SPI bus (also uses SPI2)

4. **Why developers add SPI loggers:**
   - Higher throughput than UART for verbose debug logs
   - UART already in use by another peripheral
   - Persistent logs to external SPI flash for post-mortem crash analysis
   - Convenient during development, forgotten in production

5. **Finding debug SPI on CoreS3 in practice:**
   - Connect logic analyzer to GPIO17 (SCK), GPIO8 (MOSI), GPIO9 (MISO), GPIO18 (CS)
   - Power on device -> capture boot sequence (~2.7 seconds after reset)
   - Decode with PulseView/Saleae (SPI mode 0: CPOL=0, CPHA=0)
   - Payload format: `admin_pin=XXXXXX;wifi_pass=;api_key=1234567890abcdef;extra_secret=<REDACTED>` (PIN is random per device)

## Lab Walkthrough

### Step 1: Identify Debug SPI Logger Pins

Locate debug SPI logger signals for logic analyzer connection.

```bash
# On CoreS3:
# GPIO17: DEBUG_SPI_SCK  (SPI clock, ~333 kHz)
# GPIO8:  DEBUG_SPI_MOSI (SPI data out - contains boot diagnostics + secrets!)
# GPIO9:  DEBUG_SPI_MISO (SPI data in - unused, write-only logger)
# GPIO18: DEBUG_SPI_CS   (SPI chip select - active LOW)
```

**Physical pin locations:** Port.B and Port.C Grove connectors are only accessible with the **DIN Base** attached. Without DIN Base, use the **expansion header** (bottom of CoreS3).

```
Without DIN Base: Access via expansion header (bottom of CoreS3)
+-------------------------------------+
|  GPIO8  -> DEBUG_SPI_MOSI <- SECRETS! |
|  GPIO9  -> DEBUG_SPI_MISO            |
|  GPIO17 -> DEBUG_SPI_SCK             |
|  GPIO18 -> DEBUG_SPI_CS              |
|  GND    -> Logic analyzer ground     |
+-------------------------------------+
```

**Connect logic analyzer:**
- **GPIO8** -> MOSI (contains secrets!)
- **GPIO9** -> MISO (unused)
- **GPIO17** -> SCK (clock)
- **GPIO18** -> CS (active LOW)
- **GND** -> Logic analyzer GND

### Step 2: Connect Logic Analyzer

```bash
# Connect logic analyzer to CoreS3:
# With DIN Base: Use Port.B (GPIO8/9) and Port.C (GPIO17/18) Grove connectors
# Without DIN Base: Probe expansion header (bottom of CoreS3)

# CH0 -> GPIO17 (SCK)
# CH1 -> GPIO8  (MOSI) <- Secrets are here!
# CH2 -> GPIO9  (MISO)
# CH3 -> GPIO18 (CS)
# GND -> GND

# Logic analyzer settings:
# Sample rate: 4 MHz minimum (bit-banged SPI at ~333 kHz)
# Trigger: CS falling edge (CH3)
# Capture: 1M samples
# Protocol: SPI Mode 0 (CPOL=0, CPHA=0)
```

### Step 3: Capture Boot Traffic

Record SPI traffic during device boot when secrets are transmitted.

```bash
# Start logic analyzer capture
# Press reset button on CoreS3 or type reboot into uart console on CoreS3
# Wait for capture to complete (~4.7 seconds after boot)

# Expected: Single SPI transaction with CS LOW
# Duration: ~80 bytes at ~333 kHz = ~1.9 milliseconds (exact count varies with WiFi password length)

# In PulseView/Saleae Logic:
# Add SPI decoder:
# - CLK: CH0 (GPIO17)
# - MOSI: CH1 (GPIO8)
# - MISO: CH2 (GPIO9)
# - CS: CH3 (GPIO18)
# - Mode: SPI Mode 0 (CPOL=0, CPHA=0)
```

**Using UART as a timing reference:**

The SPI transaction happens ~2 seconds after the I2C emission during boot. Finding it by scrolling through a long capture can be tedious. Instead, capture the debug UART (GPIO43) alongside SPI - the UART log tells you exactly when the SPI write occurs.

```bash
# Multi-channel capture setup:
# CH0 -> GPIO17 (SPI SCK)
# CH1 -> GPIO8  (SPI MOSI)
# CH2 -> GPIO9  (SPI MISO)
# CH3 -> GPIO18 (SPI CS)
# CH4 -> GPIO43 (Debug UART TX, 115200 8N1)
# GND -> GND

# In PulseView/Saleae:
# Add SPI decoder on CH0-CH3 (Mode 0, MSB first)
# Add UART decoder on CH4 (115200, 8N1)
#
# On the UART channel, look for:
#   "[SPI-LOG] Sending NN bytes to external SPI logger (CS=GPIO18, SCK=GPIO17, MOSI=GPIO8, MISO=GPIO9)"
#
# The SPI transaction (CS goes LOW) starts immediately after that UART message.
# Jump to that timestamp on CH3 to see CS fall, then decode MOSI for the secret payload.
```

### Step 4: Extract Secrets from Capture

Decode SPI traffic to extract admin PIN, WiFi password, and API key.

```bash
# In PulseView/Saleae Logic:
# Look for SPI transaction (CS LOW period)

# Expected findings in MOSI data:
# Payload format: "admin_pin=YYYYYY;wifi_pass=;api_key=1234567890abcdef;extra_secret=<REDACTED>"
#                          ^^^^^^ random per device
# - admin_pin: 6-digit admin PIN from NVS
# - wifi_pass: WiFi password from NVS (empty if not configured)
# - api_key: Static API key (1234567890abcdef)
# - extra_secret: Additional secret value

# Export decoded SPI data to CSV:
# File -> Export -> CSV
# Look for ASCII characters in MOSI column
```

**What you'll see in the capture:**
1. **CS goes LOW** (transaction start)
2. **MOSI data** (at ~333 kHz):
   - ASCII: `admin_pin=YYYYYY;wifi_pass=;api_key=1234567890abcdef;extra_secret=<REDACTED>`
   - Hex: `0x61 0x64 0x6D 0x69 0x6E 0x5F 0x70 0x69 0x6E 0x3D ...`
3. **CS goes HIGH** (transaction end)

**Impact:**
- Captured boot-time SPI traffic containing admin PIN, WiFi password, and API key
- Demonstrated that debug SPI loggers left in production leak secrets to anyone with a logic analyzer

## References

- [SPI Protocol Overview](https://www.analog.com/en/analog-dialogue/articles/introduction-to-spi-interface.html)
- [ESP32-S3 Technical Reference Manual - SPI](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf)
- [PulseView - Open Source Logic Analyzer Software](https://sigrok.org/wiki/PulseView)
- [Saleae Logic Analyzer](https://www.saleae.com/)
