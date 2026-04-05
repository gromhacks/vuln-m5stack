#!/usr/bin/env python3
"""
Firmware Extraction Tool for L04 - Firmware Extraction via Debug Interfaces

Wrapper around esptool.py to extract firmware from an ESP32-S3 device,
then run strings extraction and search for hardcoded secrets.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile


DEFAULT_FLASH_SIZE = 0x800000  # 8MB
DEFAULT_OFFSET = 0x0

# Common secret patterns to search for in firmware binary
SECRET_PATTERNS = [
    (r"admin_pin=(\S+)", "Admin PIN"),
    (r"user_pin=(\S+)", "User PIN"),
    (r"wifi_password=(\S+)", "WiFi Password"),
    (r"jwt_secret=(\S+)", "JWT Secret"),
    (r"api_key=(\S+)", "API Key"),
    (r"secret\d*=(\S+)", "Secret"),
    (r"password=(\S+)", "Password"),
    (r"[Ss]ecret:\s*(\S+)", "Secret"),
    (r"BEGIN\s+(RSA|EC|PRIVATE)\s+KEY", "Private Key Header"),
]

# Interesting strings patterns (broader search)
INTERESTING_PATTERNS = [
    r"http://\S+",
    r"https://\S+",
    r"/api/\S+",
    r"/admin\b",
    r"root:.*:",
    r"[A-Za-z0-9+/]{20,}={0,2}",  # Base64-like strings
]


def run_esptool(port, offset, size, output):
    """Run esptool.py to dump flash contents."""
    cmd = [
        "esptool.py",
        "--port", port,
        "--baud", "921600",
        "read_flash",
        str(offset),
        str(size),
        output,
    ]

    print(f"Running: {' '.join(cmd)}")
    print(f"Dumping {size} bytes (0x{size:X}) from offset 0x{offset:X}...")
    print("This may take a few minutes for a full flash dump.")
    print()

    try:
        result = subprocess.run(cmd, capture_output=False, text=True)
        if result.returncode != 0:
            print(f"ERROR: esptool.py exited with code {result.returncode}",
                  file=sys.stderr)
            return False
    except FileNotFoundError:
        print("ERROR: esptool.py not found. Install with: pip install esptool",
              file=sys.stderr)
        return False

    return True


def extract_strings(filepath, min_length=6):
    """Extract printable ASCII strings from a binary file."""
    strings = []
    current = []

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            for byte in chunk:
                if 0x20 <= byte <= 0x7E:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_length:
                        strings.append("".join(current))
                    current = []

    if len(current) >= min_length:
        strings.append("".join(current))

    return strings


def search_secrets(strings_list):
    """Search extracted strings for secret patterns."""
    findings = []

    for s in strings_list:
        for pattern, label in SECRET_PATTERNS:
            match = re.search(pattern, s)
            if match:
                value = match.group(1) if match.lastindex else match.group(0)
                findings.append((label, value, s))

    return findings


def search_interesting(strings_list):
    """Search for other interesting strings (URLs, paths, etc.)."""
    findings = []
    seen = set()

    for s in strings_list:
        for pattern in INTERESTING_PATTERNS:
            match = re.search(pattern, s)
            if match:
                val = match.group(0)
                if val not in seen and len(val) < 200:
                    seen.add(val)
                    findings.append(val)

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Firmware extraction and secrets search tool. Dumps flash "
                    "from ESP32-S3 via esptool and searches for hardcoded secrets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
      Dump full 8MB flash and search for secrets

  %(prog)s --output firmware.bin
      Save flash dump to firmware.bin

  %(prog)s --offset 0x10000 --size 0x300000
      Dump only the application partition

  %(prog)s --search-secrets firmware.bin
      Search an existing firmware dump for secrets (no device needed)

  %(prog)s --port /dev/ttyUSB0 --output dump.bin
      Use a different serial port

Partition layout (CoreS3 8MB flash):
  0x000000 - 0x008000  Bootloader (32KB)
  0x008000 - 0x009000  Partition table (4KB)
  0x009000 - 0x00E000  NVS (20KB)
  0x00E000 - 0x010000  OTA data (8KB)
  0x010000 - 0x310000  Factory app partition (3MB)
  0x310000 - 0x710000  OTA_0 app partition (4MB)

Tips:
  - Put device in download mode: hold BOOT button, press RESET, release BOOT
  - For faster dumps, use --baud 921600 (default)
  - Use --search-secrets to analyze a previously dumped binary
""")
    parser.add_argument("--port", "-p", default="/dev/ttyACM0",
                        help="Serial port (default: /dev/ttyACM0)")
    parser.add_argument("--output", "-o",
                        help="Output file for flash dump (default: auto-generated)")
    parser.add_argument("--offset", type=lambda x: int(x, 0),
                        default=DEFAULT_OFFSET,
                        help="Flash read offset in bytes (default: 0x0)")
    parser.add_argument("--size", type=lambda x: int(x, 0),
                        default=DEFAULT_FLASH_SIZE,
                        help="Number of bytes to read (default: 0x800000 / 8MB)")
    parser.add_argument("--search-secrets", "-s", metavar="FILE",
                        help="Search an existing binary file for secrets "
                             "(skip flash dump)")
    parser.add_argument("--min-string-length", type=int, default=6,
                        help="Minimum string length for extraction (default: 6)")

    args = parser.parse_args()

    # If analyzing existing file, skip dump
    if args.search_secrets:
        firmware_path = args.search_secrets
        if not os.path.isfile(firmware_path):
            print(f"ERROR: File not found: {firmware_path}", file=sys.stderr)
            sys.exit(1)
        print(f"Analyzing existing firmware: {firmware_path}")
        print(f"File size: {os.path.getsize(firmware_path)} bytes")
    else:
        # Determine output path
        if args.output:
            firmware_path = args.output
        else:
            firmware_path = "flash_dump_0x{:X}_0x{:X}.bin".format(
                args.offset, args.size)

        if not run_esptool(args.port, args.offset, args.size, firmware_path):
            sys.exit(1)

        print(f"\nFlash dump saved to: {firmware_path}")
        print(f"File size: {os.path.getsize(firmware_path)} bytes")

    # Extract strings
    print("\nExtracting strings (min length: {})...".format(args.min_string_length))
    strings = extract_strings(firmware_path, args.min_string_length)
    print(f"Found {len(strings)} strings")

    # Search for secrets
    print("\n" + "=" * 60)
    print("SECRET SEARCH RESULTS")
    print("=" * 60)

    secrets = search_secrets(strings)
    if secrets:
        print(f"\nFound {len(secrets)} potential secret(s):\n")
        for label, value, context in secrets:
            print(f"  [{label}]")
            print(f"    Value:   {value}")
            print(f"    Context: {context[:100]}")
            print()
    else:
        print("\nNo secrets found matching known patterns.")

    # Search for interesting strings
    interesting = search_interesting(strings)
    if interesting:
        print("-" * 60)
        print(f"Other interesting strings ({len(interesting)}):\n")
        for s in interesting[:50]:
            print(f"  {s}")
        if len(interesting) > 50:
            print(f"  ... and {len(interesting) - 50} more")

    print("\n" + "=" * 60)
    print(f"Firmware dump: {firmware_path}")
    if secrets:
        print(f"Secrets found: {len(secrets)}")
    print("Done.")


if __name__ == "__main__":
    main()
