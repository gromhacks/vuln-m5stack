#!/usr/bin/env python3
"""
ESP32-S3 Secure Boot Status Checker

Checks the secure boot configuration of an ESP32-S3 device by reading
eFuse values via espefuse.py. Reports the status of all security-relevant
eFuses including SECURE_BOOT_EN, DIS_USB_JTAG, DIS_USB_SERIAL_JTAG,
and key purpose registers.

Also attempts firmware extraction via esptool.py to prove that flash
contents are readable without authentication (confirming secure boot
is not enforced).

Usage examples:

  # Check secure boot status on default port
  ./secureboot_check.py

  # Check on a specific serial port
  ./secureboot_check.py --port /dev/ttyUSB0

  # Also attempt firmware extraction to prove flash is readable
  ./secureboot_check.py --port /dev/ttyACM0 --extract bootloader.bin

  # Verbose output showing raw espefuse.py response
  ./secureboot_check.py --port /dev/ttyACM0 --verbose
"""

import argparse
import os
import re
import subprocess
import sys


# eFuses relevant to secure boot and debug security on ESP32-S3
SECURITY_EFUSES = [
    {
        "name": "SECURE_BOOT_EN",
        "description": "Secure Boot V2 enable - when True, boot ROM verifies "
                       "bootloader signature before execution",
        "secure_value": "True",
    },
    {
        "name": "SECURE_BOOT_AGGRESSIVE_REVOKE",
        "description": "Aggressive key revocation - when True, revokes keys on "
                       "any signature verification failure",
        "secure_value": "True",
    },
    {
        "name": "DIS_USB_JTAG",
        "description": "Disable USB JTAG - when True, permanently disables JTAG "
                       "debug access via the USB interface",
        "secure_value": "True",
    },
    {
        "name": "DIS_USB_SERIAL_JTAG",
        "description": "Disable USB Serial JTAG - when True, disables the USB "
                       "Serial/JTAG peripheral entirely",
        "secure_value": "True",
    },
    {
        "name": "DIS_PAD_JTAG",
        "description": "Disable pad JTAG - when True, disables JTAG access via "
                       "GPIO pads (alternative JTAG pins)",
        "secure_value": "True",
    },
    {
        "name": "DIS_DOWNLOAD_MANUAL_ENCRYPT",
        "description": "Disable download mode manual encryption - when True, "
                       "prevents writing plaintext to encrypted flash in download mode",
        "secure_value": "True",
    },
    {
        "name": "DIS_DIRECT_BOOT",
        "description": "Disable direct boot - when True, prevents booting without "
                       "the second-stage bootloader",
        "secure_value": "True",
    },
    {
        "name": "KEY_PURPOSE_0",
        "description": "Key block 0 purpose - should be SECURE_BOOT_DIGEST0 for "
                       "secure boot key storage",
        "secure_value": "SECURE_BOOT_DIGEST",
    },
    {
        "name": "KEY_PURPOSE_1",
        "description": "Key block 1 purpose - may hold additional secure boot "
                       "keys or flash encryption key",
        "secure_value": None,  # Varies
    },
]


def run_espefuse_summary(port, verbose=False):
    """Run espefuse.py summary and return the output.

    Returns the raw text output, or None if the command fails.
    """
    cmd = ["espefuse.py", "--port", port, "summary"]

    if verbose:
        print("[*] Running: %s" % " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        print("[ERROR] espefuse.py not found.")
        print("[*] Install with: pip install esptool")
        return None
    except subprocess.TimeoutExpired:
        print("[ERROR] espefuse.py timed out after 30 seconds.")
        print("[*] The device may need to be in download mode:")
        print("[*]   Hold G0 button -> Press Reset -> Release G0")
        return None

    if result.returncode != 0:
        if verbose:
            print("[WARNING] espefuse.py returned error code %d" % result.returncode)
            if result.stderr:
                print("[WARNING] stderr: %s" % result.stderr.strip())
        # Still try to parse stdout - some errors are non-fatal
        if not result.stdout:
            return None

    return result.stdout


def parse_efuse_value(summary_text, efuse_name):
    """Parse the value of a specific eFuse from the summary output.

    Returns the value string, or None if not found.
    """
    # Pattern: EFUSE_NAME (BLOCK0) ... = <value> R/W (0x...)
    pattern = r"%s\s+.*?=\s+(.+?)(?:\s+R/?W|\s+R/-)" % re.escape(efuse_name)
    match = re.search(pattern, summary_text)
    if match:
        return match.group(1).strip()

    # Try simpler pattern
    pattern = r"%s\s*.*?=\s*(\S+)" % re.escape(efuse_name)
    match = re.search(pattern, summary_text)
    if match:
        return match.group(1).strip()

    return None


def check_efuses(summary_text, verbose=False):
    """Check all security-relevant eFuses and report status.

    Returns (num_secure, num_insecure, findings_list).
    """
    findings = []
    num_secure = 0
    num_insecure = 0

    if verbose:
        print()
        print("[*] Raw espefuse.py output (security-relevant lines):")
        print("-" * 60)
        for line in summary_text.splitlines():
            lower = line.lower()
            if any(kw in lower for kw in [
                "secure", "jtag", "download", "encrypt", "key_purpose",
                "crypt", "boot", "direct",
            ]):
                print("    %s" % line.strip())
        print("-" * 60)

    print()
    print("[*] Security eFuse Analysis")
    print("=" * 70)
    print("%-35s %-12s %-10s %s" % ("eFuse", "Value", "Status", "Expected"))
    print("-" * 70)

    for efuse_info in SECURITY_EFUSES:
        name = efuse_info["name"]
        value = parse_efuse_value(summary_text, name)

        if value is None:
            status = "UNKNOWN"
            display_value = "(not found)"
        elif efuse_info["secure_value"] is None:
            status = "INFO"
            display_value = value
        elif efuse_info["secure_value"] in value:
            status = "SECURE"
            display_value = value
            num_secure += 1
        else:
            status = "INSECURE"
            display_value = value
            num_insecure += 1

        expected = efuse_info["secure_value"] if efuse_info["secure_value"] else "varies"

        # Status markers
        if status == "SECURE":
            marker = "[OK]"
        elif status == "INSECURE":
            marker = "[!!]"
        elif status == "UNKNOWN":
            marker = "[??]"
        else:
            marker = "[--]"

        print("%-35s %-12s %-10s %s" % (name, display_value, marker, expected))

        findings.append({
            "name": name,
            "value": display_value,
            "status": status,
            "description": efuse_info["description"],
            "expected": expected,
        })

    print("-" * 70)
    return num_secure, num_insecure, findings


def attempt_firmware_extraction(port, output_file, verbose=False):
    """Attempt to read the bootloader from flash to prove it is accessible.

    If the read succeeds and returns readable data, secure boot is not
    enforcing flash read protection.
    """
    print()
    print("[*] Firmware Extraction Test")
    print("=" * 70)

    # Read bootloader (first 32KB)
    read_size = 0x8000
    target_file = output_file if output_file else "/tmp/secboot_test_bootloader.bin"

    cmd = [
        "esptool.py", "--port", port,
        "read_flash", "0x0", hex(read_size), target_file,
    ]

    if verbose:
        print("[*] Running: %s" % " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        print("[ERROR] esptool.py not found.")
        return
    except subprocess.TimeoutExpired:
        print("[ERROR] esptool.py timed out. Device may need to be in download mode.")
        return

    if result.returncode != 0:
        print("[*] Flash read failed (return code %d)" % result.returncode)
        if "secure boot" in result.stderr.lower():
            print("[+] Device may have secure boot enabled - read was blocked")
        else:
            print("[*] Error: %s" % result.stderr.strip())
        return

    # Check if the file was created and contains readable data
    if not os.path.exists(target_file):
        print("[*] Output file not created")
        return

    file_size = os.path.getsize(target_file)
    print("[*] Read %d bytes from flash offset 0x0" % file_size)

    # Check for readable strings (indicates plaintext, not encrypted)
    try:
        strings_result = subprocess.run(
            ["strings", target_file],
            capture_output=True,
            text=True,
            timeout=10,
        )
        readable_strings = [
            s for s in strings_result.stdout.splitlines()
            if len(s) >= 4
        ]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        readable_strings = []

    if readable_strings:
        print("[+] INSECURE: Firmware is readable in plaintext")
        print("[+] Found %d readable strings in bootloader" % len(readable_strings))
        print("[+] Sample strings:")
        for s in readable_strings[:10]:
            print("      %s" % s)
        if output_file:
            print("[+] Bootloader saved to: %s" % output_file)
    else:
        print("[*] No readable strings found - firmware may be encrypted")
        print("[*] (This does not necessarily mean secure boot is enabled)")

    # Clean up temp file if we created one
    if not output_file and os.path.exists(target_file):
        os.unlink(target_file)


def main():
    parser = argparse.ArgumentParser(
        description="Check ESP32-S3 secure boot configuration by reading eFuse values "
                    "with espefuse.py. Reports the status of all security-relevant "
                    "eFuses and optionally extracts firmware to prove flash is readable.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s --port /dev/ttyACM0
  %(prog)s --port /dev/ttyACM0 --extract bootloader.bin
  %(prog)s --port /dev/ttyACM0 --verbose

expected findings on CoreS3:
  SECURE_BOOT_EN = False          (secure boot disabled)
  DIS_USB_JTAG = False            (JTAG debug accessible)
  DIS_USB_SERIAL_JTAG = False     (USB serial JTAG accessible)
  KEY_PURPOSE_0 = USER            (no signing key registered)
  Flash bootloader readable in plaintext via esptool
""",
    )

    parser.add_argument(
        "--port",
        default="/dev/ttyACM0",
        help="Serial port for the ESP32-S3 device (default: /dev/ttyACM0)",
    )
    parser.add_argument(
        "--extract",
        metavar="FILE",
        help="Extract bootloader to this file to prove flash is readable",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show raw espefuse.py output and command details",
    )

    args = parser.parse_args()

    print("[*] ESP32-S3 Secure Boot Status Checker")
    print("=" * 70)
    print("[*] Target port: %s" % args.port)
    print()

    # Step 1: Read eFuse summary
    print("[*] Reading eFuse values via espefuse.py...")
    summary = run_espefuse_summary(args.port, verbose=args.verbose)

    if summary is None:
        print()
        print("[ERROR] Could not read eFuse values.")
        print("[*] Ensure the device is connected and accessible.")
        print("[*] You may need to put the device in download mode:")
        print("[*]   Hold G0 button -> Press Reset -> Release G0")
        sys.exit(1)

    # Step 2: Analyze security eFuses
    num_secure, num_insecure, findings = check_efuses(summary, verbose=args.verbose)

    # Step 3: Print verdict
    print()
    if num_insecure > 0:
        print("[+] RESULT: Secure boot is NOT properly configured")
        print("[+] %d security eFuses are in insecure state" % num_insecure)
        print("[+] %d security eFuses are properly set" % num_secure)
        print()
        print("[+] Implications:")
        for f in findings:
            if f["status"] == "INSECURE":
                print("    - %s: %s" % (f["name"], f["description"]))
    elif num_secure > 0:
        print("[*] RESULT: Security eFuses appear to be configured")
        print("[*] %d security eFuses are set" % num_secure)
    else:
        print("[?] RESULT: Could not determine secure boot status")
        print("[?] No security eFuses were found in espefuse output")

    # Step 4: Attempt firmware extraction
    if args.extract or num_insecure > 0:
        attempt_firmware_extraction(args.port, args.extract, verbose=args.verbose)

    print()
    print("[*] Done.")
    return 0 if num_insecure == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
