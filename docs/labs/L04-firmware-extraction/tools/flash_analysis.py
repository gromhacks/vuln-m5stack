#!/usr/bin/env python3
"""
ESP32-S3 Flash Encryption Analysis and Secret Extraction

Checks the flash encryption status of an ESP32-S3 device via espefuse.py,
extracts the firmware binary in plaintext via esptool.py, and searches for
hardcoded secrets using strings extraction and pattern matching.

The tool reports all found credentials, keys, endpoints, and other sensitive
data embedded in the firmware binary. On the CoreS3 IoT camera, expected
findings include the JWT signing secret, admin password, USB auth password,
BLE pairing keys, and API endpoint paths.

Usage examples:

  # Check flash encryption status and extract secrets
  ./flash_analysis.py --port /dev/ttyACM0

  # Extract firmware and save to file
  ./flash_analysis.py --port /dev/ttyACM0 --output firmware.bin

  # Search with additional custom patterns
  ./flash_analysis.py --port /dev/ttyACM0 --patterns "api_key" "auth_token" "private"

  # Analyze a previously extracted firmware file (no device needed)
  ./flash_analysis.py --firmware firmware.bin

  # Verbose output with all matched strings
  ./flash_analysis.py --port /dev/ttyACM0 --verbose
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile


# Default patterns to search for in firmware binary
DEFAULT_PATTERNS = [
    # Credentials and secrets
    r"secret\d*",
    r"password",
    r"passwd",
    r"pin[=:]",
    r"user_pin",
    r"admin_pin",
    r"jwt",
    r"hmac",
    r"token",
    # WiFi
    r"ssid",
    r"wifi",
    r"wpa",
    r"CoreS3",
    # Keys and crypto
    r"[Kk]ey[=:]",
    r"[Aa]es",
    r"encrypt",
    r"[Pp]rivate",
    r"[Ss]igning",
    # URLs and endpoints
    r"http://",
    r"https://",
    r"/api/",
    r"/admin",
    r"/login",
    r"/stream",
    r"/ota",
    r"/config",
    r"/file",
    r"/diag",
    # BLE
    r"[Bb]le",
    r"[Ll]tk",
    r"[Ii]rk",
    # Common hardcoded values
    r"usbadmin",
    r"Admin_2024",
    r"User_2024",
    r"changeme",
    r"default",
]

# Patterns that indicate high-value secrets (highlighted in output)
HIGH_VALUE_PATTERNS = [
    r"secret123",
    r"CoreS3_Admin",
    r"CoreS3_User",
    r"usbadmin",
    r"[0-9A-Fa-f]{32}",  # Hex patterns (keys, UUIDs)
    r"password\s*=",
    r"pin\s*=\s*\d+",
]


def check_flash_encryption(port, verbose=False):
    """Check flash encryption eFuse status via espefuse.py.

    Returns a dict with encryption status information.
    """
    cmd = ["espefuse.py", "--port", port, "summary"]

    if verbose:
        print("[*] Running: %s" % " ".join(cmd))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        print("[ERROR] espefuse.py not found. Install with: pip install esptool")
        return None
    except subprocess.TimeoutExpired:
        print("[ERROR] espefuse.py timed out.")
        return None

    output = result.stdout or ""
    status = {
        "spi_boot_crypt_cnt": None,
        "encrypted": False,
        "key_purpose_0": None,
        "key_purpose_1": None,
        "raw_output": output,
    }

    # Parse SPI_BOOT_CRYPT_CNT
    match = re.search(r"SPI_BOOT_CRYPT_CNT\s+.*?=\s+(\S+)", output)
    if match:
        status["spi_boot_crypt_cnt"] = match.group(1)
        # Encryption is enabled if odd number of bits set
        val = match.group(1)
        if val not in ("0x0", "0b000", "False", "0"):
            status["encrypted"] = True

    # Parse CRYPT_CNT (alternative name)
    if status["spi_boot_crypt_cnt"] is None:
        match = re.search(r"CRYPT_CNT\s+.*?=\s+(\S+)", output)
        if match:
            status["spi_boot_crypt_cnt"] = match.group(1)

    # Parse KEY_PURPOSE registers
    for i in range(2):
        pattern = r"KEY_PURPOSE_%d\s+.*?=\s+(\S+)" % i
        match = re.search(pattern, output)
        if match:
            status["key_purpose_%d" % i] = match.group(1)

    return status


def extract_firmware(port, output_file, offset=0x10000, size=0x300000, verbose=False):
    """Extract firmware from flash using esptool.py.

    Returns the path to the extracted file, or None on failure.
    """
    cmd = [
        "esptool.py", "--port", port,
        "read_flash", hex(offset), hex(size), output_file,
    ]

    if verbose:
        print("[*] Running: %s" % " ".join(cmd))

    print("[*] Extracting firmware: offset=0x%X size=0x%X (%d KB)..." % (
        offset, size, size // 1024
    ))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        print("[ERROR] esptool.py not found. Install with: pip install esptool")
        return None
    except subprocess.TimeoutExpired:
        print("[ERROR] esptool.py timed out during firmware extraction.")
        return None

    if result.returncode != 0:
        print("[ERROR] Firmware extraction failed (code %d)" % result.returncode)
        if verbose and result.stderr:
            print("[ERROR] %s" % result.stderr.strip())
        return None

    if os.path.exists(output_file):
        file_size = os.path.getsize(output_file)
        print("[+] Extracted %d bytes (%.1f KB) to %s" % (
            file_size, file_size / 1024, output_file
        ))
        return output_file
    return None


def extract_strings(firmware_path, min_length=4):
    """Extract printable ASCII strings from a binary file.

    Returns a list of (offset, string) tuples.
    """
    try:
        result = subprocess.run(
            ["strings", "-t", "x", "-n", str(min_length), firmware_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        entries = []
        for line in result.stdout.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                try:
                    offset = int(parts[0], 16)
                    entries.append((offset, parts[1]))
                except ValueError:
                    entries.append((0, line.strip()))
        return entries
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Fallback: read binary and extract strings manually
        print("[*] 'strings' command not available, using Python fallback")
        entries = []
        with open(firmware_path, "rb") as f:
            data = f.read()
        current = []
        start_offset = 0
        for i, byte in enumerate(data):
            if 32 <= byte <= 126:
                if not current:
                    start_offset = i
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    entries.append((start_offset, "".join(current)))
                current = []
        if len(current) >= min_length:
            entries.append((start_offset, "".join(current)))
        return entries


def search_secrets(strings_list, patterns, custom_patterns=None, verbose=False):
    """Search extracted strings for patterns matching secrets and credentials.

    Returns a categorized dict of findings.
    """
    all_patterns = list(patterns)
    if custom_patterns:
        all_patterns.extend(custom_patterns)

    findings = {
        "credentials": [],
        "crypto_keys": [],
        "endpoints": [],
        "wifi": [],
        "ble": [],
        "other": [],
    }

    seen = set()

    for offset, s in strings_list:
        for pattern in all_patterns:
            try:
                match = re.search(pattern, s, re.IGNORECASE)
            except re.error:
                continue

            if match:
                if s not in seen:
                    seen.add(s)

                    # Categorize the finding
                    entry = {"offset": offset, "string": s, "pattern": pattern}

                    lower = s.lower()
                    if any(kw in lower for kw in [
                        "pin", "password", "passwd", "secret", "admin", "usbadmin",
                    ]):
                        findings["credentials"].append(entry)
                    elif any(kw in lower for kw in [
                        "key", "aes", "hmac", "jwt", "encrypt", "signing", "token",
                    ]):
                        findings["crypto_keys"].append(entry)
                    elif any(kw in lower for kw in [
                        "http", "/api", "/admin", "/login", "/stream", "/ota",
                        "/config", "/file", "/diag",
                    ]):
                        findings["endpoints"].append(entry)
                    elif any(kw in lower for kw in ["wifi", "ssid", "wpa"]):
                        findings["wifi"].append(entry)
                    elif any(kw in lower for kw in ["ble", "ltk", "irk"]):
                        findings["ble"].append(entry)
                    else:
                        findings["other"].append(entry)
                break  # Only match once per string
    return findings


def check_high_value(s):
    """Check if a string matches a high-value secret pattern."""
    for pattern in HIGH_VALUE_PATTERNS:
        if re.search(pattern, s, re.IGNORECASE):
            return True
    return False


def print_findings(findings, verbose=False):
    """Print categorized findings in a readable format."""
    total = sum(len(v) for v in findings.values())

    print()
    print("[*] Secret Extraction Results")
    print("=" * 70)
    print("[*] Total unique findings: %d" % total)
    print()

    categories = [
        ("credentials", "Credentials and Passwords"),
        ("crypto_keys", "Cryptographic Keys and Tokens"),
        ("endpoints", "API Endpoints and URLs"),
        ("wifi", "WiFi Configuration"),
        ("ble", "BLE Pairing Data"),
        ("other", "Other Sensitive Strings"),
    ]

    for key, label in categories:
        items = findings[key]
        if not items:
            continue

        print("[*] %s (%d found)" % (label, len(items)))
        print("-" * 50)
        for entry in items:
            marker = " <<<" if check_high_value(entry["string"]) else ""
            if verbose:
                print("    [0x%06X] %s%s" % (entry["offset"], entry["string"], marker))
            else:
                print("    %s%s" % (entry["string"], marker))
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Analyze ESP32-S3 flash encryption status and extract secrets "
                    "from plaintext firmware. Checks eFuse configuration via "
                    "espefuse.py, reads firmware via esptool.py, and searches for "
                    "hardcoded credentials, keys, and endpoints using pattern matching.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s --port /dev/ttyACM0
  %(prog)s --port /dev/ttyACM0 --output firmware.bin
  %(prog)s --firmware firmware.bin
  %(prog)s --port /dev/ttyACM0 --patterns "api_key" "auth_token"
  %(prog)s --port /dev/ttyACM0 --verbose

expected findings on CoreS3:
  secret123            (JWT signing secret)
  CoreS3_Admin_2024!   (admin password)
  usbadmin             (USB auth password)
  /login, /admin, /ota (API endpoints)
  BLE service UUIDs and credential patterns
""",
    )

    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--port",
        default="/dev/ttyACM0",
        help="Serial port for the ESP32-S3 device (default: /dev/ttyACM0)",
    )
    source.add_argument(
        "--firmware",
        metavar="FILE",
        help="Analyze a previously extracted firmware binary (no device needed)",
    )

    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Save extracted firmware to this file",
    )
    parser.add_argument(
        "--patterns",
        nargs="+",
        metavar="PATTERN",
        help="Additional regex patterns to search for in the firmware",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed output including string offsets and raw tool output",
    )

    args = parser.parse_args()

    print("[*] ESP32-S3 Flash Encryption Analysis and Secret Extraction")
    print("=" * 70)

    firmware_path = None
    temp_file = None

    try:
        if args.firmware:
            # Analyze existing firmware file
            if not os.path.exists(args.firmware):
                print("[ERROR] Firmware file not found: %s" % args.firmware)
                sys.exit(1)
            firmware_path = args.firmware
            print("[*] Analyzing firmware file: %s" % firmware_path)
            print("[*] Skipping eFuse check (no device connection)")

        else:
            # Step 1: Check flash encryption eFuse
            print("[*] Target port: %s" % args.port)
            print()
            print("[*] Checking flash encryption eFuses...")

            status = check_flash_encryption(args.port, verbose=args.verbose)

            if status is not None:
                print()
                print("[*] Flash Encryption Status")
                print("-" * 50)
                print("    SPI_BOOT_CRYPT_CNT: %s" % (
                    status["spi_boot_crypt_cnt"] or "(not found)"
                ))
                print("    Encryption enabled: %s" % status["encrypted"])
                print("    KEY_PURPOSE_0:      %s" % (status["key_purpose_0"] or "(not found)"))
                print("    KEY_PURPOSE_1:      %s" % (status["key_purpose_1"] or "(not found)"))

                if status["encrypted"]:
                    print()
                    print("[*] Flash encryption appears to be ENABLED.")
                    print("[*] Firmware extraction will return encrypted data.")
                    print("[*] Strings extraction is unlikely to find readable secrets.")
                else:
                    print()
                    print("[+] Flash encryption is DISABLED.")
                    print("[+] Firmware can be read in plaintext.")
            else:
                print("[WARNING] Could not determine flash encryption status.")
                print("[WARNING] Proceeding with firmware extraction anyway.")

            # Step 2: Extract firmware
            if args.output:
                firmware_path = args.output
            else:
                temp_file = tempfile.NamedTemporaryFile(
                    suffix=".bin", prefix="firmware_", delete=False
                )
                firmware_path = temp_file.name
                temp_file.close()

            print()
            extracted = extract_firmware(
                args.port, firmware_path, verbose=args.verbose
            )

            if extracted is None:
                print("[ERROR] Firmware extraction failed.")
                print("[*] The device may need to be in download mode:")
                print("[*]   Hold G0 button -> Press Reset -> Release G0")
                sys.exit(1)

        # Step 3: Extract strings
        print()
        print("[*] Extracting strings from firmware binary...")
        strings_list = extract_strings(firmware_path)
        print("[*] Found %d strings (4+ characters)" % len(strings_list))

        # Step 4: Search for secrets
        findings = search_secrets(
            strings_list,
            DEFAULT_PATTERNS,
            custom_patterns=args.patterns,
            verbose=args.verbose,
        )

        print_findings(findings, verbose=args.verbose)

        # Step 5: Summary
        total = sum(len(v) for v in findings.values())
        creds = len(findings["credentials"])
        keys = len(findings["crypto_keys"])

        print("=" * 70)
        if total > 0:
            print("[+] RESULT: %d sensitive strings found in firmware" % total)
            print("[+] %d credentials, %d crypto keys/tokens" % (creds, keys))
            if not args.firmware:
                print("[+] Flash encryption is disabled - all secrets are exposed")
        else:
            print("[*] No sensitive strings found matching search patterns.")
            print("[*] Firmware may be encrypted, or patterns need adjustment.")

    finally:
        # Clean up temp file
        if temp_file and not args.output and os.path.exists(firmware_path):
            os.unlink(firmware_path)

    print()
    print("[*] Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
