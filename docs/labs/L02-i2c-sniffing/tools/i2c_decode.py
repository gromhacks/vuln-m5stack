#!/usr/bin/env python3
"""
I2C Capture Decoder

Parse I2C capture data exported as CSV from PulseView or Saleae Logic
and display decoded transactions with hex and ASCII output.
"""

import argparse
import csv
import sys


def parse_pulseview_csv(filepath, target_address):
    """
    Parse PulseView I2C CSV export.

    PulseView I2C decoder CSV columns vary, but commonly:
      time, packet_id, type, address, data, ack

    The 'type' field contains values like: "Start", "Address Read",
    "Address Write", "Data Read", "Data Write", "Stop".

    Data values are hex bytes like "0x41".
    """
    transactions = []
    current_transaction = None

    with open(filepath, "r", newline="") as f:
        reader = csv.reader(f)
        header = None

        for row in reader:
            if not row:
                continue

            # Detect header row
            if header is None:
                lower_row = [c.strip().lower() for c in row]
                if any(k in " ".join(lower_row) for k in ["type", "data", "address"]):
                    header = lower_row
                    continue
                # If no header found yet, try next row
                continue

            if len(row) < len(header):
                continue

            fields = {}
            for i, col_name in enumerate(header):
                if i < len(row):
                    fields[col_name] = row[i].strip()

            # Determine field names (PulseView vs Saleae vary)
            event_type = ""
            data_val = ""
            addr_val = ""

            for key in fields:
                if "type" in key:
                    event_type = fields[key].lower()
                if "data" in key and "type" not in key:
                    data_val = fields[key]
                if "addr" in key:
                    addr_val = fields[key]

            if "start" in event_type:
                current_transaction = {"address": None, "direction": None, "data": []}
            elif "address" in event_type and current_transaction is not None:
                # Parse address from field
                addr = addr_val if addr_val else data_val
                addr = addr.strip()
                if addr.startswith("0x") or addr.startswith("0X"):
                    addr_int = int(addr, 16)
                elif addr.isdigit():
                    addr_int = int(addr)
                else:
                    addr_int = None

                if addr_int is not None:
                    # 7-bit I2C address is in upper 7 bits; some tools
                    # report the shifted address, others the raw byte
                    if addr_int > 0x7F:
                        current_transaction["address"] = addr_int >> 1
                    else:
                        current_transaction["address"] = addr_int

                if "write" in event_type:
                    current_transaction["direction"] = "write"
                elif "read" in event_type:
                    current_transaction["direction"] = "read"
            elif "data" in event_type and current_transaction is not None:
                # Parse hex data byte
                val = data_val.strip()
                byte_val = None
                if val.startswith("0x") or val.startswith("0X"):
                    byte_val = int(val, 16)
                elif val.isdigit():
                    byte_val = int(val)
                if byte_val is not None:
                    current_transaction["data"].append(byte_val)
            elif "stop" in event_type and current_transaction is not None:
                if current_transaction["data"]:
                    transactions.append(current_transaction)
                current_transaction = None

        # Handle case where capture ends without Stop
        if current_transaction and current_transaction["data"]:
            transactions.append(current_transaction)

    return transactions


def parse_saleae_csv(filepath, target_address):
    """
    Parse Saleae Logic 2 I2C CSV export.

    Saleae exports a simpler format with columns:
      Time [s], Packet ID, Address, Data, Read/Write, ACK/NAK
    """
    transactions = []

    with open(filepath, "r", newline="") as f:
        reader = csv.reader(f)
        header = None

        for row in reader:
            if not row:
                continue
            if header is None:
                lower_row = [c.strip().lower() for c in row]
                if any("address" in c or "packet" in c for c in lower_row):
                    header = lower_row
                    continue
                continue

            if len(row) < 3:
                continue

            fields = {}
            for i, col_name in enumerate(header):
                if i < len(row):
                    fields[col_name] = row[i].strip()

            addr_val = ""
            data_val = ""
            direction = "write"

            for key in fields:
                if "addr" in key:
                    addr_val = fields[key]
                if "data" in key:
                    data_val = fields[key]
                if "read" in key or "write" in key:
                    if "read" in fields[key].lower():
                        direction = "read"

            if not data_val:
                continue

            addr_int = None
            if addr_val:
                addr_val = addr_val.strip()
                if addr_val.startswith("0x"):
                    addr_int = int(addr_val, 16)
                elif addr_val.isdigit():
                    addr_int = int(addr_val)

            # Parse data bytes (could be space-separated hex or single byte)
            data_bytes = []
            for part in data_val.split():
                part = part.strip(",; ")
                if part.startswith("0x"):
                    data_bytes.append(int(part, 16))
                elif all(c in "0123456789abcdefABCDEF" for c in part) and len(part) == 2:
                    data_bytes.append(int(part, 16))

            if data_bytes:
                transactions.append({
                    "address": addr_int,
                    "direction": direction,
                    "data": data_bytes,
                })

    return transactions


def filter_transactions(transactions, target_address):
    """Filter transactions by target I2C address."""
    if target_address is None:
        return transactions
    return [t for t in transactions if t["address"] == target_address]


def extract_ascii(data_bytes):
    """Extract printable ASCII string from byte list."""
    chars = []
    for b in data_bytes:
        if 0x20 <= b <= 0x7E:
            chars.append(chr(b))
        elif b == 0x0A or b == 0x0D:
            chars.append("\n")
        else:
            chars.append(".")
    return "".join(chars)


def main():
    parser = argparse.ArgumentParser(
        description="I2C capture decoder - parse logic analyzer CSV exports and "
                    "display decoded I2C bus transactions.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --input capture.csv
      Parse I2C capture and show all transactions

  %(prog)s --input capture.csv --address 0x50
      Filter to address 0x50 (EEPROM) only

  %(prog)s --input capture.csv --format saleae
      Parse Saleae Logic 2 CSV export

Supported CSV formats:
  pulseview  - PulseView I2C protocol decoder export (default)
  saleae     - Saleae Logic 2 I2C analyzer export

The tool extracts and displays ASCII strings from I2C data bytes.
""")
    parser.add_argument("--input", "-i", required=True,
                        help="Input CSV file from logic analyzer export")
    parser.add_argument("--address", "-a", default="0x50",
                        help="I2C address to filter (hex, default: 0x50). "
                             "Use 'all' to show all addresses.")
    parser.add_argument("--format", "-f", choices=["pulseview", "saleae"],
                        default="pulseview",
                        help="CSV format (default: pulseview)")

    args = parser.parse_args()

    # Parse target address
    if args.address.lower() == "all":
        target_address = None
    else:
        try:
            target_address = int(args.address, 0)
        except ValueError:
            print(f"ERROR: Invalid address: {args.address}", file=sys.stderr)
            sys.exit(1)

    # Parse CSV
    try:
        if args.format == "saleae":
            transactions = parse_saleae_csv(args.input, target_address)
        else:
            transactions = parse_pulseview_csv(args.input, target_address)
    except FileNotFoundError:
        print(f"ERROR: File not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to parse CSV: {e}", file=sys.stderr)
        sys.exit(1)

    if not transactions:
        print("No I2C transactions found in capture file.")
        print("Check the CSV format and address filter.")
        sys.exit(1)

    # Filter by address
    filtered = filter_transactions(transactions, target_address)
    if not filtered:
        addr_str = f"0x{target_address:02X}" if target_address else "any"
        print(f"No transactions found for address {addr_str}.")
        # Show available addresses
        addrs = set(t["address"] for t in transactions if t["address"] is not None)
        if addrs:
            print("Available addresses: " + ", ".join(f"0x{a:02X}" for a in sorted(addrs)))
        sys.exit(1)

    # Display transactions
    print(f"Found {len(filtered)} I2C transaction(s)")
    if target_address is not None:
        print(f"Filtered to address: 0x{target_address:02X}")
    print("-" * 60)

    for i, txn in enumerate(filtered):
        addr = txn["address"]
        direction = txn["direction"] or "unknown"
        data = txn["data"]
        hex_str = " ".join(f"{b:02X}" for b in data)
        ascii_str = extract_ascii(data)

        addr_str = f"0x{addr:02X}" if addr is not None else "????"
        print(f"\n[{i+1}] Address: {addr_str} ({direction})")
        print(f"  Hex:   {hex_str}")
        print(f"  ASCII: {ascii_str}")

    print("\n" + "-" * 60)


if __name__ == "__main__":
    main()
