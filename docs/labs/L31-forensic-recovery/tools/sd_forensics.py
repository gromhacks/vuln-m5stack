#!/usr/bin/env python3
"""
SD Card Forensic Recovery Tool

Recovers forensic artifacts from the CoreS3 IoT camera's SD card, including
JPEG snapshots, debug metadata, crash dumps, and other log files written
by the firmware. Parses recovered files to extract embedded credentials
(user_pin, admin_pin, wifi_ssid, jwt secret).

The CoreS3 firmware writes forensic data to /logs/ on the SD card via
the forensics-snap serial command (run_diagnostic(31)). Files include:
  /logs/debug-snapshot.jpg  - Camera snapshot (JPEG from GC0308 sensor)
  /logs/debug-exif.txt      - EXIF-style metadata with plaintext secrets
  /logs/crash-dump.txt      - Crash report with secrets (from crash-dump command)

Usage examples:

  # Scan mounted SD card for forensic artifacts
  ./sd_forensics.py --mount-point /mnt/sdcard

  # Analyze and extract credentials
  ./sd_forensics.py --mount-point /mnt/sdcard --analyze

  # Copy recovered files to an output directory
  ./sd_forensics.py --mount-point /mnt/sdcard --output-dir ./recovered

  # Mount a device, scan, and analyze in one step
  ./sd_forensics.py --device /dev/sdb1 --mount-point /tmp/sdcard --analyze

  # Scan without mounting (assume already mounted)
  ./sd_forensics.py --mount-point /media/user/SDCARD --analyze --output-dir ./evidence
"""

import argparse
import os
import re
import shutil
import subprocess
import sys


# Patterns that indicate sensitive data in recovered files
CREDENTIAL_PATTERNS = [
    (r"user_pin\s*=\s*(\S+)", "User PIN"),
    (r"admin_pin\s*=\s*(\S+)", "Admin PIN"),
    (r"wifi_ssid\s*=\s*(\S+)", "WiFi SSID"),
    (r"wifi_pass(?:word)?\s*=\s*(\S+)", "WiFi Password"),
    (r"jwt\s*=\s*(\S+)", "JWT Secret"),
    (r"secret\s*=\s*(\S+)", "Secret Key"),
    (r"password\s*=\s*(\S+)", "Password"),
    (r"token\s*=\s*(\S+)", "Auth Token"),
    (r"api_key\s*=\s*(\S+)", "API Key"),
]

# Known forensic artifact paths on the CoreS3 SD card
KNOWN_ARTIFACTS = [
    "logs/debug-snapshot.jpg",
    "logs/debug-exif.txt",
    "logs/crash-dump.txt",
]

# File extensions of interest for forensic scanning
FORENSIC_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".bmp",   # Images
    ".txt", ".log", ".csv",            # Text/logs
    ".bin", ".dat", ".raw",            # Binary data
    ".json", ".xml", ".cfg",           # Configuration
}


def mount_device(device, mount_point):
    """Mount an SD card device to the specified mount point.

    Returns True on success, False on failure.
    """
    if not os.path.exists(mount_point):
        print("[*] Creating mount point: %s" % mount_point)
        try:
            os.makedirs(mount_point, exist_ok=True)
        except PermissionError:
            print("[ERROR] Cannot create mount point (permission denied)")
            print("[*] Try: sudo mkdir -p %s" % mount_point)
            return False

    cmd = ["sudo", "mount", device, mount_point]
    print("[*] Mounting %s to %s..." % (device, mount_point))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        print("[ERROR] 'mount' command not found")
        return False
    except subprocess.TimeoutExpired:
        print("[ERROR] Mount timed out")
        return False

    if result.returncode != 0:
        print("[ERROR] Mount failed: %s" % result.stderr.strip())
        return False

    print("[+] Mounted successfully")
    return True


def unmount_device(mount_point):
    """Unmount a previously mounted filesystem."""
    cmd = ["sudo", "umount", mount_point]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def scan_filesystem(mount_point):
    """Scan the mounted SD card for forensic artifacts.

    Returns a list of dicts describing each found file.
    """
    artifacts = []

    if not os.path.isdir(mount_point):
        print("[ERROR] Mount point does not exist or is not a directory: %s" % mount_point)
        return artifacts

    print("[*] Scanning %s for forensic artifacts..." % mount_point)

    for dirpath, dirnames, filenames in os.walk(mount_point):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            relpath = os.path.relpath(filepath, mount_point)
            ext = os.path.splitext(filename)[1].lower()

            try:
                stat = os.stat(filepath)
                file_size = stat.st_size
            except OSError:
                file_size = 0

            is_known = relpath in KNOWN_ARTIFACTS
            is_interesting = ext in FORENSIC_EXTENSIONS or is_known

            if is_interesting:
                artifacts.append({
                    "path": filepath,
                    "relpath": relpath,
                    "filename": filename,
                    "extension": ext,
                    "size": file_size,
                    "known": is_known,
                })

    # Sort: known artifacts first, then by path
    artifacts.sort(key=lambda a: (not a["known"], a["relpath"]))

    print("[+] Found %d files of interest" % len(artifacts))
    return artifacts


def analyze_text_file(filepath):
    """Read a text file and search for credentials.

    Returns a list of (label, value) tuples for found credentials.
    """
    credentials = []

    try:
        with open(filepath, "r", errors="replace") as f:
            content = f.read()
    except (IOError, OSError) as e:
        print("[WARNING] Cannot read %s: %s" % (filepath, e))
        return credentials

    for pattern, label in CREDENTIAL_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for value in matches:
            credentials.append((label, value))

    return credentials


def analyze_jpeg(filepath):
    """Examine a JPEG file for embedded metadata and secrets.

    Checks EXIF data (via exiftool if available), JPEG COM markers,
    and runs strings extraction on the binary data.

    Returns a list of (label, value) tuples for found data.
    """
    findings = []

    # Try exiftool for EXIF data
    try:
        result = subprocess.run(
            ["exiftool", filepath],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if ":" in line:
                    key, _, value = line.partition(":")
                    key = key.strip()
                    value = value.strip()
                    if any(kw in key.lower() for kw in [
                        "comment", "user", "description", "artist",
                        "copyright", "software", "make", "model",
                    ]):
                        findings.append(("EXIF: %s" % key, value))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass  # exiftool not available

    # Search for JPEG COM (comment) markers manually
    try:
        with open(filepath, "rb") as f:
            data = f.read()

        # JPEG COM marker: FF FE followed by 2-byte length
        pos = 0
        while pos < len(data) - 4:
            if data[pos] == 0xFF and data[pos + 1] == 0xFE:
                length = (data[pos + 2] << 8) | data[pos + 3]
                comment = data[pos + 4:pos + 2 + length]
                try:
                    text = comment.decode("ascii", errors="ignore")
                    if len(text) >= 4:
                        findings.append(("JPEG Comment", text))
                except UnicodeDecodeError:
                    pass
                pos += 2 + length
            else:
                pos += 1

    except (IOError, OSError):
        pass

    # Run strings on the JPEG binary
    try:
        result = subprocess.run(
            ["strings", "-n", "6", filepath],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            for pattern, label in CREDENTIAL_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(("Embedded string: %s" % label, line))
                    break
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return findings


def copy_artifacts(artifacts, output_dir):
    """Copy recovered files to an output directory for evidence preservation."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    copied = 0
    for artifact in artifacts:
        src = artifact["path"]
        # Preserve relative directory structure
        rel_dir = os.path.dirname(artifact["relpath"])
        dest_dir = os.path.join(output_dir, rel_dir) if rel_dir else output_dir
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, artifact["filename"])

        try:
            shutil.copy2(src, dest)
            copied += 1
        except (IOError, OSError) as e:
            print("[WARNING] Failed to copy %s: %s" % (src, e))

    print("[+] Copied %d files to %s" % (copied, output_dir))


def main():
    parser = argparse.ArgumentParser(
        description="Forensic recovery tool for the CoreS3 IoT camera SD card. "
                    "Scans for JPEG snapshots, metadata files, crash dumps, and "
                    "other artifacts written by the firmware. Extracts and displays "
                    "embedded credentials (PINs, WiFi config, JWT secrets).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s --mount-point /mnt/sdcard
  %(prog)s --mount-point /mnt/sdcard --analyze
  %(prog)s --mount-point /mnt/sdcard --analyze --output-dir ./recovered
  %(prog)s --device /dev/sdb1 --mount-point /tmp/sdcard --analyze

expected artifacts on CoreS3 SD card:
  /logs/debug-snapshot.jpg  - Camera snapshot
  /logs/debug-exif.txt      - EXIF metadata with user_pin, admin_pin, wifi_ssid
  /logs/crash-dump.txt      - Crash dump with user_pin, admin_pin, wifi_ssid, jwt
""",
    )

    parser.add_argument(
        "--device",
        metavar="DEV",
        help="SD card block device to mount (e.g., /dev/sdb1). "
             "Requires sudo for mounting.",
    )
    parser.add_argument(
        "--mount-point",
        default="/mnt/sdcard",
        help="Mount point for the SD card (default: /mnt/sdcard)",
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        help="Copy recovered files to this directory for evidence preservation",
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Parse recovered files and display extracted credentials",
    )

    args = parser.parse_args()

    print("[*] SD Card Forensic Recovery Tool - CoreS3 IoT Camera")
    print("=" * 60)

    mounted = False

    try:
        # Mount if device specified
        if args.device:
            if not mount_device(args.device, args.mount_point):
                sys.exit(1)
            mounted = True

        # Verify mount point is accessible
        if not os.path.isdir(args.mount_point):
            print("[ERROR] Mount point not accessible: %s" % args.mount_point)
            if not args.device:
                print("[*] Either mount the SD card first or use --device to auto-mount")
            sys.exit(1)

        # Scan for artifacts
        artifacts = scan_filesystem(args.mount_point)

        if not artifacts:
            print("[*] No forensic artifacts found.")
            print("[*] Ensure the SD card contains data from the CoreS3 device.")
            print("[*] Run 'forensics-snap' or 'crash-dump' on the device first.")
            sys.exit(0)

        # Display found artifacts
        print()
        print("[*] Recovered Artifacts")
        print("=" * 60)
        print("%-40s %10s %s" % ("File", "Size", "Status"))
        print("-" * 60)
        for artifact in artifacts:
            status = "KNOWN" if artifact["known"] else "found"
            print("%-40s %10d %s" % (
                artifact["relpath"],
                artifact["size"],
                status,
            ))
        print()

        # Copy files if output directory specified
        if args.output_dir:
            copy_artifacts(artifacts, args.output_dir)

        # Analyze files for credentials
        if args.analyze:
            print("[*] Credential Extraction")
            print("=" * 60)

            all_credentials = []

            for artifact in artifacts:
                filepath = artifact["path"]
                ext = artifact["extension"]

                if ext in (".txt", ".log", ".csv", ".cfg", ".json", ".xml"):
                    creds = analyze_text_file(filepath)
                    if creds:
                        print()
                        print("[+] %s:" % artifact["relpath"])
                        for label, value in creds:
                            print("    %-20s = %s" % (label, value))
                            all_credentials.append((artifact["relpath"], label, value))

                elif ext in (".jpg", ".jpeg"):
                    findings = analyze_jpeg(filepath)
                    if findings:
                        print()
                        print("[+] %s:" % artifact["relpath"])
                        for label, value in findings:
                            print("    %-20s : %s" % (label, value))
                            all_credentials.append((artifact["relpath"], label, value))

            # Summary
            print()
            print("=" * 60)
            if all_credentials:
                print("[+] TOTAL: %d credentials/secrets recovered from %d files" % (
                    len(all_credentials),
                    len(set(c[0] for c in all_credentials)),
                ))

                # Deduplicated credential summary
                seen = set()
                unique_creds = []
                for source, label, value in all_credentials:
                    key = (label, value)
                    if key not in seen:
                        seen.add(key)
                        unique_creds.append((label, value))

                print()
                print("[+] Unique credentials recovered:")
                for label, value in unique_creds:
                    print("    %-20s = %s" % (label, value))
            else:
                print("[-] No credentials found in recovered files.")
                print("[*] Files may be binary or use non-standard formats.")
        else:
            print("[*] Use --analyze to parse files and extract credentials.")

    finally:
        if mounted:
            print()
            print("[*] Unmounting %s..." % args.mount_point)
            unmount_device(args.mount_point)

    print()
    print("[*] Done.")


if __name__ == "__main__":
    main()
