#!/usr/bin/env python3
"""
SD Card Firmware Extractor for L05 - SD Card Bootloader Bypass

Mount an SD card, search for firmware binaries, and extract strings
and secrets from firmware files found on the card.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile


# File extensions that may contain firmware
FIRMWARE_EXTENSIONS = {".bin", ".img", ".fw", ".hex", ".elf", ".rom"}

# Secret patterns to search for
SECRET_PATTERNS = [
    (r"admin_pin=(\S+)", "Admin PIN"),
    (r"user_pin=(\S+)", "User PIN"),
    (r"wifi_password=(\S+)", "WiFi Password"),
    (r"jwt_secret=(\S+)", "JWT Secret"),
    (r"api_key=(\S+)", "API Key"),
    (r"secret\d*=(\S+)", "Secret"),
    (r"password=(\S+)", "Password"),
    (r"[Ss]ecret:\s*(\S+)", "Secret"),
    (r"secret123", "Hardcoded JWT Secret"),
]


def find_firmware_files(mount_point, firmware_name=None):
    """Search mount point for firmware files."""
    found = []

    if firmware_name:
        target = os.path.join(mount_point, firmware_name)
        if os.path.isfile(target):
            found.append(target)
        # Also check subdirectories
        for root, dirs, files in os.walk(mount_point):
            for f in files:
                if f == firmware_name:
                    path = os.path.join(root, f)
                    if path not in found:
                        found.append(path)
        return found

    # Search for any firmware-like files
    for root, dirs, files in os.walk(mount_point):
        for f in files:
            _, ext = os.path.splitext(f.lower())
            if ext in FIRMWARE_EXTENSIONS:
                found.append(os.path.join(root, f))

    return found


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


def mount_device(device, mount_point):
    """Mount the SD card device."""
    if not os.path.exists(mount_point):
        print(f"Creating mount point: {mount_point}")
        try:
            os.makedirs(mount_point, exist_ok=True)
        except PermissionError:
            print(f"ERROR: Permission denied creating {mount_point}. Try with sudo.",
                  file=sys.stderr)
            return False

    cmd = ["mount", device, mount_point]
    print(f"Mounting {device} at {mount_point}...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            stderr = result.stderr.strip()
            print(f"ERROR: Mount failed: {stderr}", file=sys.stderr)
            if "permission denied" in stderr.lower() or "not permitted" in stderr.lower():
                print("  Try running with sudo.", file=sys.stderr)
            return False
    except FileNotFoundError:
        print("ERROR: 'mount' command not found.", file=sys.stderr)
        return False

    print(f"Mounted successfully.")
    return True


def unmount_device(mount_point):
    """Unmount the SD card."""
    cmd = ["umount", mount_point]
    try:
        subprocess.run(cmd, capture_output=True, text=True)
        print(f"Unmounted {mount_point}")
    except Exception:
        pass


def analyze_firmware(filepath, search_secrets_flag):
    """Analyze a single firmware file."""
    size = os.path.getsize(filepath)
    print(f"\n{'=' * 60}")
    print(f"Firmware: {filepath}")
    print(f"Size:     {size} bytes ({size / 1024:.1f} KB)")
    print(f"{'=' * 60}")

    # Basic file info
    try:
        result = subprocess.run(["file", filepath], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"Type:     {result.stdout.strip().split(':', 1)[-1].strip()}")
    except FileNotFoundError:
        pass

    # Extract strings
    print(f"\nExtracting strings...")
    strings = extract_strings(filepath)
    print(f"Found {len(strings)} strings (min 6 chars)")

    if search_secrets_flag:
        secrets = search_secrets(strings)
        if secrets:
            print(f"\n[RESULTS] Found {len(secrets)} potential secret(s):\n")
            for label, value, context in secrets:
                print(f"  [{label}]")
                print(f"    Value:   {value}")
                print(f"    Context: {context[:100]}")
                print()
        else:
            print("\n[RESULTS] No secrets found matching known patterns.")

    # Show some interesting strings
    print("Notable strings found:")
    keywords = ["pin", "pass", "secret", "key", "token", "admin",
                 "wifi", "ssid", "http", "api", "root", "firmware",
                 "version", "debug", "config"]
    notable = []
    for s in strings:
        lower = s.lower()
        if any(kw in lower for kw in keywords) and len(s) < 200:
            notable.append(s)

    if notable:
        seen = set()
        for s in notable[:30]:
            if s not in seen:
                seen.add(s)
                print(f"  {s}")
        if len(notable) > 30:
            print(f"  ... and {len(notable) - 30} more")
    else:
        print("  (none matching keyword filter)")

    return strings


def main():
    parser = argparse.ArgumentParser(
        description="SD card firmware extractor - mount SD card, find firmware "
                    "files, and extract secrets from binaries.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --device /dev/sdb1
      Mount SD card and search for firmware files

  %(prog)s --device /dev/mmcblk0p1 --search-secrets
      Mount SD card and search firmware for hardcoded secrets

  %(prog)s --mount-point /media/sdcard --firmware-name firmware.bin
      Use existing mount point, look for specific firmware file

  %(prog)s --mount-point /mnt/sd --search-secrets
      Analyze firmware on already-mounted SD card

  %(prog)s --file firmware.bin --search-secrets
      Analyze a firmware file directly (no SD card needed)

The CoreS3 device looks for /firmware.bin on the SD card at boot
and flashes it without signature verification. This tool helps
analyze what firmware is on the SD card and extract secrets from it.

Tips:
  - The default firmware filename is 'firmware.bin'
  - Run with sudo if mount requires elevated privileges
  - Use --file to analyze a firmware binary directly
  - Use --no-unmount to keep the SD card mounted after analysis
""")
    parser.add_argument("--device", "-d",
                        help="SD card block device (e.g., /dev/sdb1, /dev/mmcblk0p1)")
    parser.add_argument("--mount-point", "-m", default="/mnt/sdcard",
                        help="Mount point directory (default: /mnt/sdcard)")
    parser.add_argument("--firmware-name", "-n", default="firmware.bin",
                        help="Firmware filename to search for (default: firmware.bin)")
    parser.add_argument("--search-secrets", "-s", action="store_true",
                        help="Search firmware binaries for hardcoded secrets")
    parser.add_argument("--file", "-f",
                        help="Analyze a firmware file directly (no SD card needed)")
    parser.add_argument("--no-unmount", action="store_true",
                        help="Do not unmount SD card after analysis")

    args = parser.parse_args()

    # Direct file analysis mode
    if args.file:
        if not os.path.isfile(args.file):
            print(f"ERROR: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        analyze_firmware(args.file, args.search_secrets)
        sys.exit(0)

    # SD card mode
    did_mount = False

    if args.device:
        if not os.path.exists(args.device):
            print(f"ERROR: Device not found: {args.device}", file=sys.stderr)
            sys.exit(1)
        if not mount_device(args.device, args.mount_point):
            sys.exit(1)
        did_mount = True
    else:
        # Check if mount point already has content
        if not os.path.isdir(args.mount_point):
            print(f"ERROR: Mount point does not exist: {args.mount_point}",
                  file=sys.stderr)
            print("  Specify --device to mount an SD card, or --file to analyze "
                  "a firmware binary directly.", file=sys.stderr)
            sys.exit(1)

    try:
        # List SD card contents
        print(f"\nSD card contents at {args.mount_point}:")
        print("-" * 40)
        try:
            for item in sorted(os.listdir(args.mount_point)):
                full_path = os.path.join(args.mount_point, item)
                if os.path.isfile(full_path):
                    size = os.path.getsize(full_path)
                    print(f"  {item:30s}  {size:>10d} bytes")
                elif os.path.isdir(full_path):
                    print(f"  {item:30s}  <dir>")
        except PermissionError:
            print("  ERROR: Permission denied reading directory.", file=sys.stderr)

        # Search for firmware files
        print(f"\nSearching for firmware files...")
        firmware_files = find_firmware_files(args.mount_point, args.firmware_name)

        if not firmware_files:
            print(f"No firmware files found.")
            print(f"  Searched for: {args.firmware_name}")
            print(f"  Also checked extensions: {', '.join(sorted(FIRMWARE_EXTENSIONS))}")

            # Check if any files exist at all
            all_files = find_firmware_files(args.mount_point, firmware_name=None)
            if all_files:
                print(f"\n  Other binary files found:")
                for f in all_files:
                    print(f"    {f}")
        else:
            print(f"Found {len(firmware_files)} firmware file(s):")
            for f in firmware_files:
                print(f"  {f}")

            for fw in firmware_files:
                analyze_firmware(fw, args.search_secrets)

    finally:
        if did_mount and not args.no_unmount:
            unmount_device(args.mount_point)

    print("\nDone.")


if __name__ == "__main__":
    main()
