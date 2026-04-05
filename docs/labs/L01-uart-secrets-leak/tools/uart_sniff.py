#!/usr/bin/env python3
"""
UART Capture Tool for IoT Device Debug Output

Connect to the device serial port and capture boot output for manual
analysis. Displays all received data in real time and reports a summary
of the capture session.
"""

import argparse
import sys
import time


def capture_serial(port, baud, duration):
    """Capture serial output for the given duration and return lines."""
    try:
        import serial
    except ImportError:
        print("ERROR: pyserial is required. Install with: pip install pyserial",
              file=sys.stderr)
        sys.exit(1)

    print(f"Opening {port} at {baud} baud...")
    try:
        ser = serial.Serial(port, baud, timeout=1)
    except serial.SerialException as e:
        print(f"ERROR: Could not open serial port: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Capturing for {duration} seconds (Ctrl+C to stop early)...")
    print("-" * 60)

    lines = []
    start = time.time()
    try:
        while time.time() - start < duration:
            raw = ser.readline()
            if raw:
                try:
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                except Exception:
                    line = raw.hex()
                print(line)
                lines.append(line)
    except KeyboardInterrupt:
        print("\n[Capture interrupted by user]")
    finally:
        ser.close()

    return lines


def main():
    parser = argparse.ArgumentParser(
        description="UART capture tool - capture serial boot output for manual analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
      Capture from /dev/ttyACM0 at 115200 baud for 30 seconds

  %(prog)s --duration 60
      Capture for 60 seconds

  %(prog)s --port /dev/ttyUSB0 --baud 9600 --duration 10
      Use a different port and baud rate

  %(prog)s --file boot_log.txt
      Display a previously captured log file

Tips:
  - Reset the device during capture to catch boot-time output
  - The debug UART on GPIO43 (expansion header pin 14) echoes all output
  - Try both /dev/ttyACM0 (USB CDC) and /dev/ttyACM1 if available
""")
    parser.add_argument("--port", "-p", default="/dev/ttyACM0",
                        help="Serial port (default: /dev/ttyACM0)")
    parser.add_argument("--baud", "-b", type=int, default=115200,
                        help="Baud rate (default: 115200)")
    parser.add_argument("--duration", "-d", type=int, default=30,
                        help="Capture duration in seconds (default: 30)")
    parser.add_argument("--file", "-f",
                        help="Display a saved log file instead of live capture")

    args = parser.parse_args()

    if args.file:
        print(f"Reading saved log file: {args.file}")
        print("-" * 60)
        try:
            with open(args.file, "r", errors="replace") as f:
                lines = [line.rstrip("\r\n") for line in f]
        except FileNotFoundError:
            print(f"ERROR: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        for line in lines:
            print(line)
    else:
        lines = capture_serial(args.port, args.baud, args.duration)

    print("-" * 60)
    print(f"\n[SUMMARY] Captured {len(lines)} line(s) of output.")


if __name__ == "__main__":
    main()
