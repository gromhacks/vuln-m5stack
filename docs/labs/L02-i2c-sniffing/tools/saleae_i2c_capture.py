#!/usr/bin/env python3
"""
Saleae Logic 2 I2C Capture Script

Automates I2C capture on the CoreS3 Port.A bus (GPIO1=SCL, GPIO2=SDA)
using the Saleae Logic 2 automation API. Triggers the device to emit
I2C secrets via serial reboot or bus-diag command, captures the
transaction, decodes it, and displays extracted secrets.

Requirements:
  - Saleae Logic 2 running with automation server enabled (port 10430)
    Logic 2 -> Preferences -> Enable automation server
  - pip install logic2-automation
  - Saleae connected: CH0=GPIO1(SCL), CH1=GPIO2(SDA), GND=GND

Usage:
  # Capture during bus-diag command (no reboot):
  python3 saleae_i2c_capture.py --trigger bus-diag --serial-port /dev/ttyACM0

  # Capture during reboot:
  python3 saleae_i2c_capture.py --trigger reboot --serial-port /dev/ttyACM0

  # Capture only (trigger manually):
  python3 saleae_i2c_capture.py --trigger manual

  # Use simulation device (no hardware):
  python3 saleae_i2c_capture.py --simulate
"""

import argparse
import csv
import io
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
        DataTableExportConfiguration,
    )
except ImportError:
    print("ERROR: saleae automation library not found.")
    print("Install with: pip install logic2-automation")
    print("Also ensure Logic 2 is running with automation enabled.")
    sys.exit(1)

try:
    import serial
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False

SALEAE_PORT = 10430
I2C_SCL_CHANNEL = 0  # CH0 = GPIO1 (SCL)
I2C_SDA_CHANNEL = 1  # CH1 = GPIO2 (SDA)
SAMPLE_RATE_HZ = 2_000_000  # 2 MHz (20x oversampling for 100kHz I2C)
CAPTURE_DURATION_S = 5.0  # 5 seconds covers boot I2C transaction
EEPROM_ADDRESS = 0x50


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


def find_device(manager, simulate=False):
    """Find the connected Saleae device."""
    devices = manager.get_devices(include_simulation_devices=simulate)
    if not devices:
        print("ERROR: No Saleae devices found.")
        if not simulate:
            print("Try --simulate to use a simulation device for testing.")
        sys.exit(1)

    for d in devices:
        print(f"  Device: {d.device_type} (ID: {d.device_id})")

    # Prefer physical devices over simulation
    physical = [d for d in devices if "SIMULATION" not in str(d.device_type)]
    if physical:
        device = physical[0]
    else:
        device = devices[0]

    print(f"Using device: {device.device_type} (ID: {device.device_id})")
    return device


def trigger_bus_diag(serial_port, baud=115200):
    """Send bus-diag command over serial to trigger I2C emission."""
    if not HAS_SERIAL:
        print("ERROR: pyserial not installed. Install with: pip install pyserial")
        print("Or use --trigger manual and type 'bus-diag' into serial console.")
        return False

    print(f"Sending 'bus-diag' via {serial_port}...")
    try:
        ser = serial.Serial(serial_port, baud, timeout=2)
        time.sleep(0.5)
        ser.write(b"\r\n")
        time.sleep(0.2)
        ser.write(b"bus-diag\r\n")
        time.sleep(1.0)
        # Read response
        response = ser.read(ser.in_waiting or 1024).decode("utf-8", errors="replace")
        ser.close()
        if "I2C" in response or "EEPROM" in response or "bus" in response.lower():
            print("  bus-diag triggered successfully")
        else:
            print(f"  Sent command (response: {response[:200]})")
        return True
    except Exception as e:
        print(f"  WARNING: Serial error: {e}")
        return False


def trigger_reboot(serial_port, baud=115200):
    """Send reboot command over serial."""
    if not HAS_SERIAL:
        print("ERROR: pyserial not installed.")
        return False

    print(f"Sending 'reboot' via {serial_port}...")
    try:
        ser = serial.Serial(serial_port, baud, timeout=2)
        time.sleep(0.5)
        ser.write(b"\r\n")
        time.sleep(0.2)
        ser.write(b"reboot\r\n")
        time.sleep(0.5)
        ser.close()
        print("  Reboot command sent. Device will restart in ~3 seconds.")
        return True
    except Exception as e:
        print(f"  WARNING: Serial error: {e}")
        return False


def capture_i2c(manager, device, duration=CAPTURE_DURATION_S):
    """Start I2C capture on CH0 (SCL) and CH1 (SDA)."""
    print(f"Starting capture ({duration}s, {SAMPLE_RATE_HZ/1e6:.0f} MHz)...")
    print(f"  CH{I2C_SCL_CHANNEL} = SCL (GPIO1)")
    print(f"  CH{I2C_SDA_CHANNEL} = SDA (GPIO2)")

    device_config = LogicDeviceConfiguration(
        enabled_digital_channels=[I2C_SCL_CHANNEL, I2C_SDA_CHANNEL],
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


def decode_i2c_export(csv_path):
    """Parse exported I2C analyzer CSV and extract secrets.

    Saleae Logic 2 exports I2C data with columns:
      name, type, start_time, duration, data, read, error, address, ack

    The 'type' field is: start, address, data, stop.
    The 'address' column contains the 7-bit address as an ASCII character
    (e.g., 'P' = 0x50). The 'data' column contains data bytes as ASCII
    characters. The 'read' column is 'true'/'false' for direction.
    Null bytes appear as the literal string '\\0'.
    """
    transactions = []
    current_data = []
    current_addr = None
    current_dir = None

    with open(csv_path, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            event_type = row.get("type", "").strip().lower()

            if event_type == "start":
                if current_data and current_addr is not None:
                    transactions.append({
                        "address": current_addr,
                        "direction": current_dir,
                        "data": list(current_data),
                    })
                current_data = []
                current_addr = None
                current_dir = None

            elif event_type == "address":
                # Address is exported as ASCII char (e.g., 'P' = 0x50)
                addr_str = row.get("address", "").strip()
                if addr_str and len(addr_str) == 1:
                    current_addr = ord(addr_str)
                elif addr_str:
                    try:
                        current_addr = int(addr_str.replace("0x", ""), 16)
                    except ValueError:
                        current_addr = None

                read_flag = row.get("read", "").strip().lower()
                current_dir = "read" if read_flag == "true" else "write"

            elif event_type == "data":
                # Do NOT strip - space characters are valid data
                data_str = row.get("data", "")
                # Remove surrounding quotes if present from CSV parsing
                if data_str.startswith('"') and data_str.endswith('"'):
                    data_str = data_str[1:-1]
                if data_str == "\\0":
                    current_data.append(0)
                elif len(data_str) == 1:
                    current_data.append(ord(data_str))
                elif data_str.startswith("0x"):
                    try:
                        current_data.append(int(data_str, 16))
                    except ValueError:
                        pass

            elif event_type == "stop":
                if current_data and current_addr is not None:
                    transactions.append({
                        "address": current_addr,
                        "direction": current_dir,
                        "data": list(current_data),
                    })
                current_data = []
                current_addr = None

    # Handle trailing data without stop
    if current_data and current_addr is not None:
        transactions.append({
            "address": current_addr,
            "direction": current_dir,
            "data": list(current_data),
        })

    return transactions


def display_results(transactions):
    """Display decoded I2C transactions and extract secrets."""
    if not transactions:
        print("\nNo I2C transactions captured.")
        print("Check wiring: CH0=GPIO1(SCL), CH1=GPIO2(SDA), GND=GND")
        return False

    print(f"\nCaptured {len(transactions)} I2C transaction(s)")
    print("-" * 60)

    secrets_found = False
    for i, txn in enumerate(transactions):
        addr = txn["address"]
        direction = txn["direction"] or "unknown"
        data = txn["data"]
        hex_str = " ".join(f"{b:02X}" for b in data)
        ascii_str = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in data)

        addr_str = f"0x{addr:02X}" if addr is not None else "????"
        print(f"\n[{i+1}] Address: {addr_str} ({direction})")
        print(f"  Length: {len(data)} bytes")
        print(f"  Hex:   {hex_str}")
        print(f"  ASCII: {ascii_str}")

        # Check for secrets
        if addr == EEPROM_ADDRESS and direction == "write":
            # Skip first byte (register address 0x00)
            payload = data[1:] if data else data
            text = "".join(chr(b) if 0x20 <= b <= 0x7E else "" for b in payload)

            if "ADMINPIN=" in text or "WIFIPASS=" in text:
                secrets_found = True
                print()
                print("  *** SECRETS FOUND ***")
                parts = text.split()
                for part in parts:
                    if "=" in part:
                        key, _, value = part.partition("=")
                        print(f"  {key}: {value}")

    print("\n" + "-" * 60)

    if secrets_found:
        print("\nSUCCESS: Extracted secrets from I2C EEPROM write!")
        print("The admin PIN and WiFi password were transmitted in plaintext")
        print("over the I2C bus and captured by the logic analyzer.")
    else:
        eeprom_txns = [t for t in transactions if t["address"] == EEPROM_ADDRESS]
        if not eeprom_txns:
            print(f"\nNo transactions to EEPROM address 0x{EEPROM_ADDRESS:02X} found.")
            addrs = set(t["address"] for t in transactions if t["address"] is not None)
            if addrs:
                print("Addresses seen: " + ", ".join(f"0x{a:02X}" for a in sorted(addrs)))
            print("Try re-triggering with 'bus-diag' or rebooting the device.")
        else:
            print(f"\nFound {len(eeprom_txns)} EEPROM transaction(s) but no secrets pattern.")
            print("Check if the device has been configured with a WiFi password.")

    return secrets_found


def main():
    parser = argparse.ArgumentParser(
        description="Capture I2C secrets from CoreS3 using Saleae Logic 2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Wiring:
  Saleae CH0 -> GPIO1 (SCL, Port.A pin 0)
  Saleae CH1 -> GPIO2 (SDA, Port.A pin 1)
  Saleae GND -> GND (Pin 1 on expansion header)

Examples:
  %(prog)s --trigger bus-diag --serial-port /dev/ttyACM0
  %(prog)s --trigger reboot --serial-port /dev/ttyACM0
  %(prog)s --trigger manual
  %(prog)s --simulate
""")
    parser.add_argument("--trigger", choices=["bus-diag", "reboot", "manual"],
                        default="bus-diag",
                        help="How to trigger I2C emission (default: bus-diag)")
    parser.add_argument("--serial-port", default="/dev/ttyACM0",
                        help="Serial port for device (default: /dev/ttyACM0)")
    parser.add_argument("--baud", type=int, default=115200,
                        help="Serial baud rate (default: 115200)")
    parser.add_argument("--duration", type=float, default=CAPTURE_DURATION_S,
                        help=f"Capture duration in seconds (default: {CAPTURE_DURATION_S})")
    parser.add_argument("--port", type=int, default=SALEAE_PORT,
                        help=f"Logic 2 automation port (default: {SALEAE_PORT})")
    parser.add_argument("--simulate", action="store_true",
                        help="Use simulation device (no physical Saleae needed)")
    parser.add_argument("--output", "-o",
                        help="Save raw CSV export to this file")

    args = parser.parse_args()

    # Connect to Logic 2
    manager = connect_logic2(port=args.port)

    try:
        # Find device
        device = find_device(manager, simulate=args.simulate)

        # Start capture
        capture = capture_i2c(manager, device, duration=args.duration)

        # Trigger I2C emission after capture starts
        if args.trigger == "reboot":
            time.sleep(0.5)  # Let capture stabilize
            trigger_reboot(args.serial_port, args.baud)
            print("Waiting for device to reboot and emit I2C secrets...")
        elif args.trigger == "bus-diag":
            time.sleep(0.5)
            trigger_bus_diag(args.serial_port, args.baud)
        else:
            print()
            print("MANUAL MODE: Trigger I2C emission now!")
            print("  Option 1: Type 'bus-diag' into serial console")
            print("  Option 2: Press reset button on device")
            print(f"  Capture will run for {args.duration} seconds...")

        # Wait for capture to complete
        print("Capturing...")
        capture.wait()
        print("Capture complete.")

        # Add I2C analyzer
        print("Adding I2C protocol decoder...")
        i2c_analyzer = capture.add_analyzer(
            "I2C",
            label="I2C EEPROM Sniff",
            settings={
                "SDA": I2C_SDA_CHANNEL,
                "SCL": I2C_SCL_CHANNEL,
            }
        )

        # Export decoded data
        csv_path = args.output or os.path.join(
            tempfile.mkdtemp(), "i2c_capture.csv"
        )
        print(f"Exporting decoded I2C data to {csv_path}...")
        capture.export_data_table(
            filepath=csv_path,
            analyzers=[i2c_analyzer],
        )

        # Parse and display results
        transactions = decode_i2c_export(csv_path)
        display_results(transactions)

        # Clean up temp file if not saving
        if not args.output and os.path.exists(csv_path):
            print(f"\nRaw CSV saved at: {csv_path}")

    finally:
        manager.close()


if __name__ == "__main__":
    main()
