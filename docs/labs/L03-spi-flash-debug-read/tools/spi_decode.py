#!/usr/bin/env python3
"""
SPI Capture Decoder for L03 - SPI Debug Logger Leak

Parse SPI capture data exported as CSV from PulseView or Saleae Logic
and extract ASCII payload from MOSI/MISO data.
"""

import argparse
import csv
import sys


def parse_pulseview_csv(filepath):
    """
    Parse PulseView SPI CSV export.

    PulseView SPI decoder CSV typically has columns:
      time, packet_id, mosi, miso

    Data values are hex bytes like "0x41".
    """
    frames = []

    with open(filepath, "r", newline="") as f:
        reader = csv.reader(f)
        header = None

        for row in reader:
            if not row:
                continue

            if header is None:
                lower_row = [c.strip().lower() for c in row]
                if any(k in " ".join(lower_row) for k in ["mosi", "miso", "data"]):
                    header = lower_row
                    continue
                continue

            if len(row) < len(header):
                continue

            fields = {}
            for i, col_name in enumerate(header):
                if i < len(row):
                    fields[col_name] = row[i].strip()

            mosi_val = None
            miso_val = None

            for key in fields:
                if "mosi" in key:
                    mosi_val = fields[key]
                elif "miso" in key:
                    miso_val = fields[key]
                elif "data" in key and mosi_val is None:
                    # Generic data column, treat as MOSI
                    mosi_val = fields[key]

            frame = {}
            for label, val in [("mosi", mosi_val), ("miso", miso_val)]:
                if val and val.strip():
                    val = val.strip()
                    byte_val = None
                    if val.startswith("0x") or val.startswith("0X"):
                        try:
                            byte_val = int(val, 16)
                        except ValueError:
                            pass
                    elif val.isdigit():
                        byte_val = int(val)
                    elif len(val) == 2 and all(c in "0123456789abcdefABCDEF" for c in val):
                        byte_val = int(val, 16)
                    if byte_val is not None:
                        frame[label] = byte_val

            if frame:
                frames.append(frame)

    return frames


def parse_saleae_csv(filepath):
    """
    Parse Saleae Logic 2 SPI CSV export.

    Saleae exports columns like:
      Time [s], Packet ID, MOSI, MISO
    """
    frames = []

    with open(filepath, "r", newline="") as f:
        reader = csv.reader(f)
        header = None

        for row in reader:
            if not row:
                continue

            if header is None:
                lower_row = [c.strip().lower() for c in row]
                if any("mosi" in c or "miso" in c or "data" in c for c in lower_row):
                    header = lower_row
                    continue
                continue

            if len(row) < len(header):
                continue

            fields = {}
            for i, col_name in enumerate(header):
                if i < len(row):
                    fields[col_name] = row[i].strip()

            frame = {}
            for key in fields:
                val = fields[key].strip()
                if not val:
                    continue
                label = None
                if "mosi" in key:
                    label = "mosi"
                elif "miso" in key:
                    label = "miso"
                if label:
                    if val.startswith("0x"):
                        try:
                            frame[label] = int(val, 16)
                        except ValueError:
                            pass
                    elif val.isdigit():
                        frame[label] = int(val)

            if frame:
                frames.append(frame)

    return frames


def extract_channel_bytes(frames, channel):
    """Extract byte values for the specified channel from frames."""
    return [f[channel] for f in frames if channel in f]


def bytes_to_ascii(data_bytes):
    """Convert byte list to ASCII string, replacing non-printable chars."""
    chars = []
    for b in data_bytes:
        if 0x20 <= b <= 0x7E:
            chars.append(chr(b))
        elif b == 0x0A:
            chars.append("\n")
        elif b == 0x0D:
            chars.append("\r")
        elif b == 0x00:
            # Skip null bytes (common padding in SPI)
            continue
        else:
            chars.append(".")
    return "".join(chars)


def main():
    parser = argparse.ArgumentParser(
        description="SPI capture decoder - parse logic analyzer CSV exports and "
                    "decode SPI debug logger traffic.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --input capture.csv
      Parse SPI capture and extract ASCII from MOSI channel

  %(prog)s --input capture.csv --channel miso
      Extract data from MISO channel instead

  %(prog)s --input capture.csv --format saleae
      Parse Saleae Logic 2 CSV export

  %(prog)s --input capture.csv --raw
      Show raw hex dump alongside ASCII output

Supported CSV formats:
  pulseview  - PulseView SPI protocol decoder export (default)
  saleae     - Saleae Logic 2 SPI analyzer export

The tool extracts ASCII strings from SPI data for manual analysis.
""")
    parser.add_argument("--input", "-i", required=True,
                        help="Input CSV file from logic analyzer export")
    parser.add_argument("--channel", "-c", choices=["mosi", "miso"],
                        default="mosi",
                        help="SPI channel to decode (default: mosi)")
    parser.add_argument("--format", "-f", choices=["pulseview", "saleae"],
                        default="pulseview",
                        help="CSV format (default: pulseview)")
    parser.add_argument("--raw", "-r", action="store_true",
                        help="Show raw hex dump of extracted bytes")

    args = parser.parse_args()

    # Parse CSV
    try:
        if args.format == "saleae":
            frames = parse_saleae_csv(args.input)
        else:
            frames = parse_pulseview_csv(args.input)
    except FileNotFoundError:
        print(f"ERROR: File not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to parse CSV: {e}", file=sys.stderr)
        sys.exit(1)

    if not frames:
        print("No SPI frames found in capture file.")
        print("Check the CSV format and ensure SPI decoder was applied.")
        sys.exit(1)

    # Extract bytes for selected channel
    data_bytes = extract_channel_bytes(frames, args.channel)

    if not data_bytes:
        print(f"No data found on {args.channel.upper()} channel.")
        other = "miso" if args.channel == "mosi" else "mosi"
        other_bytes = extract_channel_bytes(frames, other)
        if other_bytes:
            print(f"  Tip: Try --channel {other} ({len(other_bytes)} bytes available)")
        sys.exit(1)

    print(f"Extracted {len(data_bytes)} bytes from {args.channel.upper()} channel")
    print("-" * 60)

    # Raw hex dump
    if args.raw:
        print("\nRaw hex dump:")
        for offset in range(0, len(data_bytes), 16):
            chunk = data_bytes[offset:offset + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
            print(f"  {offset:04X}: {hex_part:<48s}  {ascii_part}")
        print()

    # ASCII extraction
    ascii_text = bytes_to_ascii(data_bytes)
    print("Decoded ASCII output:")
    print("-" * 60)
    for line in ascii_text.split("\n"):
        stripped = line.strip()
        if stripped:
            print(f"  {stripped}")

    print()
    print("-" * 60)


if __name__ == "__main__":
    main()
