# L02: I2C Bus Sniffing for Secrets

## Goal
Sniff I2C bus at boot to capture secrets transmitted between MCU and peripherals.

## Background

I2C is a common chip-to-chip protocol with no encryption, so secrets transmitted over I2C can be captured with a logic analyzer.

**What you're looking for:**
- Encryption keys stored in or read from I2C EEPROM
- Authentication tokens exchanged with secure elements
- WiFi passwords or device secrets in I2C traffic
- I2C peripherals that accept data without validation

**Why this happens:** I2C (designed in 1982) has no built-in encryption. Developers assume physical access means compromise. I2C pins are often exposed on PCBs for debugging and factory programming, and firmware rarely validates I2C data from "trusted" peripherals.

**Beyond passive sniffing:** Once you understand I2C traffic, active attacks include device spoofing (L18), buffer overflow injection (L18), fuzzing, and data injection.

**On CoreS3**: The device has **two separate I2C buses**:

- **Internal I2C bus (GPIO11 SCL / GPIO12 SDA)**: Heavy background traffic from AXP2101, BM8563, AW9523, AW88298. Probing here produces noisy captures.
- **Port.A I2C bus (GPIO1 SCL / GPIO2 SDA)**: Dedicated external bus with no other peripherals. The firmware writes the admin PIN and WiFi password to an external EEPROM (address 0x50) on this bus during boot and via the `bus-diag` command.

**Your target is Port.A (GPIO1/GPIO2)** - clean capture with only the secret transaction visible.

```cpp
// From CameraDevice_Bus.cpp - emit_i2c_diagnostics()
String secretStr = String("ADMINPIN=") + adminPIN + String(" WIFIPASS=") + wifiPass;
// Bit-banged I2C WRITE to address 0x50 on Port.A (GPIO1=SCL, GPIO2=SDA)
// Full secret payload transmitted as plaintext bytes on the bus
sendByte(0xA0);    // Address: 0x50 << 1 | WRITE
sendByte(0x00);    // Register: 0x00
for (int i = 0; i < len; i++) {
    sendByte(data[i]);  // Secret bytes visible on SDA with a logic analyzer
}
```

**I2C signals:**
- **SDA** (Serial Data) - Bidirectional data line
- **SCL** (Serial Clock) - Clock signal from master
- Both use pull-up resistors (typically 4.7kohm) to 3.3V/5V

**Finding I2C on unknown boards:**

1. **Chip identification:**
   - Look for EEPROM chips: 24CXXX, AT24CXXX (8-pin DIP/SOIC)
   - Sensors: BME280, BMP280, DS1307 (RTC)
   - Check chip markings and search datasheets for I2C pins

2. **Multimeter - Resistance mode (POWER OFF):**
   - I2C pins show ~4.7kohm to VCC (pull-up resistor)
   - Non-I2C pins show open circuit (>1Mohm) or 0ohm (direct connection)

3. **Multimeter - Voltage mode (POWER ON):**
   - I2C pins idle at 3.3V or 5V (pulled HIGH)

4. **Oscilloscope/Logic Analyzer (POWER ON):**
   - SCL: regular square wave at 100kHz or 400kHz
   - SDA: changes synchronized with SCL
   - START condition: SDA falls while SCL HIGH
   - STOP condition: SDA rises while SCL HIGH

   **What I2C looks like on a logic analyzer:**

   ```
   START: SDA falls while SCL HIGH    STOP: SDA rises while SCL HIGH

   SCL ____~~~~~~____                 SCL ____~~~~~~____
   SDA ____~~\___                     SDA ________/~~~~~
              ^START                           ^STOP
   ```

   Data transfer - address byte 0xA0 (0x50 shifted left | WRITE), then ACK:

   ```
   SCL  _/~\_/~\_/~\_/~\_/~\_/~\_/~\_/~\_/~\_   (9 clock pulses)
   SDA  ==1==0==1==0==0==0==0==0==0==            (8 data + 1 ACK)
         B7  B6  B5  B4  B3  B2  B1  B0  ACK
   ```

   SDA is sampled on the rising edge of SCL. Data is MSB first.

   | Condition | SCL | SDA | Meaning |
   |-----------|-----|-----|---------|
   | START | HIGH | Falls | Begin transaction |
   | Data=1 | Rising edge | HIGH | Bit is 1 |
   | Data=0 | Rising edge | LOW | Bit is 0 |
   | ACK | Rising edge | LOW (by receiver) | Byte received OK |
   | STOP | HIGH | Rises | End transaction |

   **Decoded transaction in PulseView/Saleae:**
   ```
   START | ADDR: 0x50 W | ACK | REG: 0x00 | ACK | DATA: 0x41 ... | STOP
   ```

   **Timing at 100kHz I2C:** 10us per bit, 90us per byte+ACK. Bit-banged secrets at ~2.5kHz.

5. **Continuity test (POWER OFF):**
   - Trace connections from microcontroller GPIO to peripheral chips
   - Pull-up resistors prevent direct continuity (will show ~4.7kohm)

**Correlating ESP32-S3 datasheet to CoreS3 hardware:**

1. **ESP32-S3 Datasheet (Section 2.2 - Pin Definitions):**
   - **Pin 16 - GPIO11**: I2C0_SCL (default I2C0 clock line)
   - **Pin 17 - GPIO12**: I2C0_SDA (default I2C0 data line)
   - Any GPIO can be configured as I2C via IO MUX
   - Internal pull-ups available (weak ~45kohm, external 4.7kohm recommended)

2. **CoreS3 Schematic (I2C Bus):**
   - **I2C0 Bus (internal)**: GPIO11 (SCL), GPIO12 (SDA)
     - Devices: **AXP2101** (0x34), **BM8563** (0x51), **AW9523** (0x58), **AW88298** (0x36)
     - Pull-ups: 4.7kohm to 3.3V (R23, R24)
   - **I2C1 Bus (Port.A)**: GPIO1 (SCL), GPIO2 (SDA)
     - External I2C port for sensors/peripherals
     - Pull-ups: 4.7kohm to 3.3V (R25, R26)

3. **Physical access points:**
   - **Internal I2C** (GPIO11/GPIO12): Expansion header (bottom of CoreS3)
   - **Port.A** (GPIO1/GPIO2): Grove connector (with DIN Base) or expansion header

4. **I2C secrets behavior:**
   - **Target**: External EEPROM at address 0x50 on **Port.A** (GPIO1/GPIO2)
   - Firmware uses **bit-banging** on Port.A to write secrets at boot
   - **What's transmitted**: Complete admin PIN and WiFi password in a single I2C WRITE transaction (byte count varies with WiFi password length; ~25 bytes with empty password, ~41 bytes with a 16-character password)
   - **Real-world equivalent**: Devices that write secrets to external EEPROM during provisioning/boot

5. **Finding I2C secrets in practice:**
   - Connect logic analyzer to **GPIO1 (SCL)** and **GPIO2 (SDA)** on Port.A
   - Power on device -> capture boot sequence (~2.7 seconds after reset)
   - Look for I2C WRITE to address **0x50**, register **0x00**
   - Decode with PulseView/Saleae -> full admin PIN and WiFi password in ASCII

6. **Datasheet Section 7.3.1 - I2C Timing:**
   - Standard mode: 100 kHz (10us period)
   - Fast mode: 400 kHz (2.5us period)
   - I2C secrets pattern uses: **~2.5 kHz** (bit-banged at 200us half-period for reliable capture)

## Lab Walkthrough

### Step 1: Identify I2C Pins

Locate Port.A I2C signals on the expansion header for logic analyzer connection.

```bash
# On CoreS3 (Port.A on Expansion Header):
GPIO1: I2C_SCL (clock)  - Port.A pin 0
GPIO2: I2C_SDA (data)   - Port.A pin 1

# These GPIOs emit the EEPROM secret write at boot (clean, no other traffic)
```

**Connect logic analyzer:**
- **GPIO1** -> SCL (clock)
- **GPIO2** -> SDA (data - contains secrets!)
- **GND** -> Logic analyzer GND

Port.A is a dedicated external I2C bus with no other peripherals - the capture shows only the EEPROM secret transaction.

### Step 2: Connect Logic Analyzer

Attach logic analyzer to I2C pins on expansion header.

```bash
# Connect logic analyzer to Port.A on CoreS3 expansion header (bottom):
# CH0 -> GPIO1 (SCL) - Port.A pin 0
# CH1 -> GPIO2 (SDA) - Port.A pin 1 <- Secrets are here!
# GND -> GND

# Logic analyzer settings:
# Sample rate: 1 MHz (minimum for 100kHz I2C)
# Trigger: SCL falling edge (CH0)
# Capture: 100k samples
```

### Step 3: Capture Boot Traffic

Record I2C traffic during device boot when secrets are transmitted.

```bash
# Start logic analyzer capture, then trigger the I2C secrets:

# Option A: Reboot the device (secrets are emitted during boot)
# Press reset button or type "reboot" into the serial console

# Option B: Re-trigger without rebooting (requires admin mode)
# Use admin PIN from boot capture, L09 path traversal, or L15 unauth config:
cores3-cam> login <admin_pin>
Admin mode unlocked.
cores3-cam> bus-diag
# Expected output:
# Re-emitting I2C diagnostics on Port.A...
# [I2C] Writing NN bytes to external EEPROM (0x50) reg 0x00 on Port.A (SCL=GPIO1, SDA=GPIO2)
# [I2C] NN bytes transmitted to external EEPROM
# [I2C] I2C transmission complete
#
# I2C emission complete.
#
# Without admin mode:
# [BUS-DIAG] Admin privileges required.

# In PulseView/Saleae Logic:
# Add I2C decoder:
# - SCL: CH0 (GPIO1)
# - SDA: CH1 (GPIO2)
```

**Using UART as a timing reference:**

The device echoes all serial output to a debug UART on GPIO43 (TX). By capturing UART alongside I2C, you can correlate the UART log messages with bus activity to find the exact moment secrets are transmitted.

```bash
# Multi-channel capture setup:
# CH0 -> GPIO1  (I2C SCL)
# CH1 -> GPIO2  (I2C SDA)
# CH2 -> GPIO43 (Debug UART TX, 115200 8N1)
# GND -> GND

# In PulseView/Saleae:
# Add I2C decoder on CH0 (SCL) + CH1 (SDA)
# Add UART decoder on CH2 (115200, 8N1)
#
# On the UART channel, look for:
#   "[I2C] Writing NN bytes to external EEPROM (0x50) reg 0x00 on Port.A (SCL=GPIO1, SDA=GPIO2)"
#
# The I2C transaction starts immediately after that UART message completes.
# Jump to that timestamp on CH0/CH1 to see the I2C START condition
# followed by the secret payload.
```

### Step 4: Extract Secrets from Capture

Decode I2C traffic to extract the admin PIN and WiFi password.

```bash
# In PulseView/Saleae Logic:
# Look for I2C WRITE transaction to address 0x50 (external EEPROM)

# Expected findings:
# Address: 0x50 (external EEPROM - doesn't exist on real hardware - Note if you're using ASCII mode it will show as a "P")
# WRITE to register 0x00: Burst write (byte count varies with WiFi password length)
# Data format: "ADMINPIN=YYYYYY WIFIPASS=MyPassword" (ASCII)

# Export decoded I2C data to CSV:
# File -> Export -> CSV
# grep "0x50" i2c_capture.csv
```

**WiFi password in the capture:**

The `WIFIPASS=` field contains the WiFi STA password from NVS. On a fresh device, **this field will be empty**. To see a WiFi password, first configure the device:

```bash
curl -X POST "http://192.168.4.1/apply" \
  -d "ssid=YourWiFiNetwork&pass=YourWiFiPassword"

# Now reboot and capture I2C traffic again.
# The capture will show: ADMINPIN=YYYYYY WIFIPASS=YourWiFiPassword
```

The admin PIN is always present (randomly generated on first boot). The WiFi password appears only after STA mode is configured.

**What you'll see in the capture:**
1. **START condition** (SDA falls while SCL HIGH)
2. **Address byte**: 0xA0 (0x50 << 1 | WRITE bit)
3. **Register address**: 0x00
4. **Data bytes** (varies with WiFi password length; ~25 bytes with empty password):
   - `ADMINPIN=YYYYYY WIFIPASS=MyPassword` (ASCII characters)
   - Example hex: `0x41 0x44 0x4D 0x49 0x4E 0x50 0x49 0x4E 0x3D [6 PIN bytes] 0x20 0x57 0x49 0x46 0x49 0x50 0x41 0x53 0x53 0x3D ...`
5. **STOP condition** (SDA rises while SCL HIGH)

**Impact:**
- Captured boot-time I2C traffic containing admin PIN and WiFi password from Port.A (GPIO1/GPIO2)
- Demonstrated that unencrypted I2C bus traffic can be sniffed with a logic analyzer

## References

- [I2C Protocol Specification](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [ESP32-S3 Technical Reference Manual - I2C](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf)
- [PulseView - Open Source Logic Analyzer Software](https://sigrok.org/wiki/PulseView)
- [Saleae Logic Analyzer](https://www.saleae.com/)
