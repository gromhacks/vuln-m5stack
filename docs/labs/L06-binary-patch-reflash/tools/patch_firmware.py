#!/usr/bin/env python3
"""
ESP32-S3 Firmware Binary Patcher

Patches ESP32-S3 (Xtensa LX7) firmware binaries at specified runtime addresses.
Converts runtime addresses to file offsets using the ESP32-S3 flash mapping
base (0x42000000) and applies binary patches.

Default patch replaces a function prologue with "return true":
  movi.n a2, 1   (0x12 0x0c)  - set return register to 1
  ret.n          (0x0d 0xf0)  - return from non-windowed call

Usage examples:

  # Patch checkPIN to always return true (using runtime address from Ghidra)
  ./patch_firmware.py --input app.bin --output app_patched.bin --address 0x42012a4c

  # Apply custom hex patch at a specific address
  ./patch_firmware.py --input app.bin --output app_patched.bin \\
      --address 0x42012a5b --patch-hex "200000"

  # Search an ELF file for function addresses by name
  ./patch_firmware.py --find-functions firmware.elf --search checkPIN

  # Patch with windowed return (retw) instead of ret.n
  ./patch_firmware.py --input app.bin --output app_patched.bin \\
      --address 0x42012a4c --patch-hex "12c20190000000"
"""

import argparse
import os
import struct
import subprocess
import sys


# ESP32-S3 flash memory mapping base for instruction execution
FLASH_MAP_BASE = 0x42000000

# Common Xtensa LX7 instruction encodings (little-endian)
PATCHES = {
    "return-true": {
        "description": "movi.n a2, 1; ret.n - return true (non-windowed)",
        "bytes": bytes([0x12, 0x0c, 0x0d, 0xf0]),
    },
    "return-true-windowed": {
        "description": "movi a2, 1; retw - return true (windowed call)",
        # movi a2, 1 = 0xa2, 0x21, 0x00 (3-byte wide); retw = 0x90, 0x00, 0x00
        "bytes": bytes([0x12, 0xc2, 0x01, 0x90, 0x00, 0x00]),
    },
    "return-false": {
        "description": "movi.n a2, 0; ret.n - return false (non-windowed)",
        "bytes": bytes([0x02, 0x0c, 0x0d, 0xf0]),
    },
    "nop3": {
        "description": "3-byte NOP (wide format)",
        "bytes": bytes([0x20, 0x00, 0x00]),
    },
    "nop2": {
        "description": "2-byte NOP (narrow format)",
        "bytes": bytes([0x20, 0xf0]),
    },
}


def runtime_to_offset(runtime_addr, firmware_data=None):
    """Convert an ESP32-S3 runtime address to a file offset in the app binary.

    Parses the ESP-IDF image segment table to find which segment contains the
    runtime address, then calculates the exact file offset within that segment.
    Falls back to simple subtraction from FLASH_MAP_BASE if no firmware data
    is provided or parsing fails.
    """
    if firmware_data and len(firmware_data) > 24:
        num_segments = firmware_data[1]
        off = 24  # skip 24-byte image header
        for i in range(num_segments):
            if off + 8 > len(firmware_data):
                break
            seg_addr = struct.unpack_from("<I", firmware_data, off)[0]
            seg_size = struct.unpack_from("<I", firmware_data, off + 4)[0]
            if seg_addr <= runtime_addr < seg_addr + seg_size:
                file_offset = (off + 8) + (runtime_addr - seg_addr)
                return file_offset
            off += 8 + seg_size

    # Fallback: simple subtraction
    if runtime_addr < FLASH_MAP_BASE:
        print(
            "[!] Warning: address 0x{:08x} is below flash map base 0x{:08x}".format(
                runtime_addr, FLASH_MAP_BASE
            )
        )
        print("    This may not be a valid flash-mapped instruction address.")
    offset = runtime_addr - FLASH_MAP_BASE
    if offset < 0:
        print("[!] Error: calculated offset is negative. Check the address.")
        sys.exit(1)
    return offset


def read_firmware(path):
    """Read firmware binary from file."""
    if not os.path.isfile(path):
        print("[!] Error: input file not found: {}".format(path))
        sys.exit(1)
    with open(path, "rb") as f:
        data = bytearray(f.read())
    print("[*] Read {} bytes from {}".format(len(data), path))
    return data


def write_firmware(path, data):
    """Write firmware binary to file."""
    with open(path, "wb") as f:
        f.write(data)
    print("[*] Wrote {} bytes to {}".format(len(data), path))


def apply_patch(data, offset, patch_bytes):
    """Apply a binary patch at the specified offset."""
    if offset + len(patch_bytes) > len(data):
        print(
            "[!] Error: patch extends beyond end of file "
            "(offset=0x{:x}, patch_len={}, file_len={})".format(
                offset, len(patch_bytes), len(data)
            )
        )
        sys.exit(1)

    # Show original bytes
    original = data[offset : offset + len(patch_bytes)]
    print("[*] File offset:    0x{:x}".format(offset))
    print("[*] Original bytes: {}".format(original.hex()))
    print("[*] Patch bytes:    {}".format(patch_bytes.hex()))

    # Check if already patched
    if data[offset : offset + len(patch_bytes)] == patch_bytes:
        print("[*] Firmware already contains the patch bytes at this offset.")
        return data

    # Apply patch
    data[offset : offset + len(patch_bytes)] = patch_bytes
    print("[+] Patch applied successfully.")
    return data


def find_functions(elf_path, search_term=None):
    """Search an ELF file for function symbols using objdump or readelf."""
    if not os.path.isfile(elf_path):
        print("[!] Error: ELF file not found: {}".format(elf_path))
        sys.exit(1)

    # Try xtensa-esp32s3-elf-objdump first, then xtensa-esp-elf-objdump, then readelf
    objdump_cmds = [
        "xtensa-esp32s3-elf-objdump",
        "xtensa-esp-elf-objdump",
        "objdump",
    ]

    symbols = []
    for cmd in objdump_cmds:
        try:
            result = subprocess.run(
                [cmd, "-t", elf_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                print("[*] Using {} to read symbols".format(cmd))
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 6 and "F" in parts[2]:
                        addr_str = parts[0]
                        name = parts[-1]
                        try:
                            addr = int(addr_str, 16)
                        except ValueError:
                            continue
                        if search_term and search_term.lower() not in name.lower():
                            continue
                        symbols.append((addr, name))
                break
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            print("[!] Warning: {} timed out".format(cmd))
            continue

    if not symbols:
        # Fallback: try readelf
        try:
            result = subprocess.run(
                ["readelf", "-s", elf_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                print("[*] Using readelf to read symbols")
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 8 and "FUNC" in line:
                        try:
                            addr = int(parts[1], 16)
                            name = parts[-1]
                        except (ValueError, IndexError):
                            continue
                        if search_term and search_term.lower() not in name.lower():
                            continue
                        symbols.append((addr, name))
        except FileNotFoundError:
            print("[!] Error: no objdump or readelf found in PATH.")
            print("    Install the Xtensa ESP32-S3 toolchain or binutils.")
            sys.exit(1)

    if not symbols:
        if search_term:
            print('[!] No functions matching "{}" found.'.format(search_term))
        else:
            print("[!] No function symbols found in ELF.")
        return

    # Sort by address and display
    symbols.sort(key=lambda x: x[0])
    print()
    print("{:<12s}  {}".format("Runtime Addr", "Function"))
    print("{:<12s}  {}".format("-" * 12, "-" * 40))
    for addr, name in symbols:
        print("0x{:08x}    {}".format(addr, name))
    print()
    print("[*] Found {} function(s).".format(len(symbols)))
    print("[*] Use --address <runtime_addr> to patch a function.")


def hexdump(data, offset, length=32):
    """Print a hex dump of data at the given offset."""
    end = min(offset + length, len(data))
    chunk = data[offset:end]
    hex_str = " ".join("{:02x}".format(b) for b in chunk)
    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    print("  0x{:08x}: {}  |{}|".format(offset, hex_str, ascii_str))


def main():
    parser = argparse.ArgumentParser(
        description="ESP32-S3 Firmware Binary Patcher - patch Xtensa firmware at "
        "runtime addresses to bypass authentication or modify behavior.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  # Patch checkPIN at 0x42012a4c to always return true
  %(prog)s --input app.bin --output app_patched.bin --address 0x42012a4c

  # Use a named patch preset
  %(prog)s --input app.bin --output app_patched.bin --address 0x42012a4c \\
      --preset return-true-windowed

  # Apply custom bytes (3-byte NOP to remove a branch instruction)
  %(prog)s --input app.bin --output app_patched.bin --address 0x42012a5b \\
      --patch-hex "200000"

  # Search ELF for functions containing "PIN" or "check"
  %(prog)s --find-functions firmware.elf --search PIN

  # List available patch presets
  %(prog)s --list-presets
""",
    )

    parser.add_argument(
        "--input", "-i", metavar="FILE", help="Input firmware binary (.bin)"
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Output patched firmware binary (default: <input>_patched.bin)",
    )
    parser.add_argument(
        "--address",
        "-a",
        metavar="ADDR",
        help="Runtime hex address to patch (e.g., 0x42012a4c)",
    )
    parser.add_argument(
        "--patch-hex",
        metavar="HEX",
        help="Custom patch bytes in hex (e.g., '120c0df0' for movi.n a2,1; ret.n)",
    )
    parser.add_argument(
        "--preset",
        "-p",
        metavar="NAME",
        default="return-true",
        help="Named patch preset (default: return-true). Use --list-presets to see options.",
    )
    parser.add_argument(
        "--find-functions",
        metavar="ELF",
        help="Search an ELF file for function symbols",
    )
    parser.add_argument(
        "--search",
        "-s",
        metavar="TERM",
        help="Filter function search results (used with --find-functions)",
    )
    parser.add_argument(
        "--list-presets",
        action="store_true",
        help="List available patch presets and exit",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Show bytes at the target offset without patching",
    )
    parser.add_argument(
        "--context",
        "-c",
        type=int,
        default=32,
        metavar="N",
        help="Number of bytes to show around the patch location (default: 32)",
    )

    args = parser.parse_args()

    # List presets
    if args.list_presets:
        print("Available patch presets:")
        print()
        for name, info in PATCHES.items():
            print(
                "  {:<24s}  {}  ({})".format(
                    name, info["bytes"].hex(), info["description"]
                )
            )
        print()
        print("Use --preset <name> to apply a preset, or --patch-hex for custom bytes.")
        return

    # Find functions mode
    if args.find_functions:
        find_functions(args.find_functions, args.search)
        return

    # Patching mode - require input and address
    if not args.input:
        parser.error("--input is required for patching (or use --find-functions)")
    if not args.address:
        parser.error("--address is required for patching")

    # Parse address
    try:
        runtime_addr = int(args.address, 16)
    except ValueError:
        parser.error("--address must be a hex value (e.g., 0x42012a4c)")

    # Read firmware first so we can parse segments for offset calculation
    data = read_firmware(args.input)

    # Calculate file offset using segment table
    offset = runtime_to_offset(runtime_addr, data)
    print("[*] Runtime address: 0x{:08x}".format(runtime_addr))
    print("[*] File offset:     0x{:08x} ({})".format(offset, offset))

    if offset >= len(data):
        print(
            "[!] Error: offset 0x{:x} is beyond end of file ({} bytes)".format(
                offset, len(data)
            )
        )
        sys.exit(1)

    # Show context around target
    print()
    print("[*] Bytes at target offset (before patch):")
    hexdump(data, offset, args.context)

    if args.verify_only:
        return

    # Determine patch bytes
    if args.patch_hex:
        try:
            patch_bytes = bytes.fromhex(args.patch_hex)
        except ValueError:
            parser.error("--patch-hex must be valid hex (e.g., '120c0df0')")
        print("[*] Using custom patch: {}".format(patch_bytes.hex()))
    else:
        if args.preset not in PATCHES:
            parser.error(
                "Unknown preset '{}'. Use --list-presets to see options.".format(
                    args.preset
                )
            )
        preset = PATCHES[args.preset]
        patch_bytes = preset["bytes"]
        print("[*] Using preset '{}': {}".format(args.preset, preset["description"]))

    # Apply patch
    print()
    data = apply_patch(data, offset, patch_bytes)

    # Show result
    print()
    print("[*] Bytes at target offset (after patch):")
    hexdump(data, offset, args.context)

    # Write output
    if not args.output:
        base, ext = os.path.splitext(args.input)
        args.output = "{}_patched{}".format(base, ext)
    print()
    write_firmware(args.output, data)
    print()
    print("[+] Done. Reflash with:")
    print(
        "    esptool.py --chip esp32s3 --port /dev/ttyACM0 "
        "write_flash 0x10000 {}".format(args.output)
    )


if __name__ == "__main__":
    main()
