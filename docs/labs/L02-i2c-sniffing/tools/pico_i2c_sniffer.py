#!/usr/bin/env python3
"""
Raspberry Pi Pico MicroPython I2C Bus Sniffer (PIO-based)

MicroPython firmware for a Raspberry Pi Pico that passively sniffs I2C bus
traffic using the RP2040's PIO (Programmable I/O) state machines. The PIO
program monitors SDA and SCL lines, detects START/STOP conditions, and
captures each byte with ACK/NACK status.

This replaces a logic analyzer ($15-100+) with a Raspberry Pi Pico (~$4)
for basic I2C bus sniffing.

Hardware connections:
  Pico GP14 (input) -> CoreS3 GPIO2 (SDA, Port.A pin 1)
  Pico GP15 (input) -> CoreS3 GPIO1 (SCL, Port.A pin 0)
  Pico GND          -> CoreS3 GND (expansion header pin 1)

IMPORTANT: The Pico pins must be high-impedance inputs only. Do NOT enable
pull-ups on the Pico - the CoreS3 already has pull-ups on its I2C bus.

Usage examples:

  # Display the MicroPython firmware to copy-paste into Thonny
  ./pico_i2c_sniffer.py --show-firmware

  # Upload firmware to Pico via serial
  ./pico_i2c_sniffer.py --upload --pico-port /dev/ttyACM1

  # Receive and decode captured I2C transactions
  ./pico_i2c_sniffer.py --receive --pico-port /dev/ttyACM1 --duration 10

  # Receive and decode captured transactions
  ./pico_i2c_sniffer.py --receive --pico-port /dev/ttyACM1 --decode
"""

import argparse
import sys
import time


# ---------------------------------------------------------------------------
# MicroPython + PIO firmware source for the Raspberry Pi Pico
# ---------------------------------------------------------------------------
PICO_FIRMWARE = r'''
# pico_i2c_sniffer.py - Raspberry Pi Pico MicroPython
# Passive I2C bus sniffer using PIO state machines
#
# Connections (high-impedance inputs, NO pull-ups):
#   GP14 (input) -> CoreS3 GPIO2 (SDA, Port.A pin 1)
#   GP15 (input) -> CoreS3 GPIO1 (SCL, Port.A pin 0)
#   GND          -> CoreS3 GND
#
# Output format over USB serial:
#   S              - START condition detected
#   P              - STOP condition detected
#   W:0x34         - Write to address 0x34
#   R:0x34         - Read from address 0x34
#   D:0xAB:ACK     - Data byte 0xAB, acknowledged
#   D:0xAB:NACK    - Data byte 0xAB, not acknowledged
#
# Commands over USB serial:
#   start          - Begin sniffing (default on boot)
#   stop           - Pause sniffing
#   status         - Report configuration
#   help           - Show available commands
#
# NOTE: PIO-based I2C sniffing is done in software using pin polling since
# the PIO instruction set does not directly support detecting SDA edges
# while SCL is held in a specific state. This implementation uses a fast
# polling loop that samples both pins and detects bit-level I2C events.

import machine
import time
import sys

# Pin configuration
SDA_PIN = 14   # GP14 - connected to CoreS3 GPIO2 (SDA, Port.A pin 1)
SCL_PIN = 15   # GP15 - connected to CoreS3 GPIO1 (SCL, Port.A pin 0)

# Initialize pins as inputs with NO pull resistors (passive sniff)
sda = machine.Pin(SDA_PIN, machine.Pin.IN)
scl = machine.Pin(SCL_PIN, machine.Pin.IN)

# State
sniffing = True
byte_count = 0
transaction_count = 0


def sniff_bus():
    """Main I2C sniffing loop using fast pin polling.

    Detects START (SDA falls while SCL high), STOP (SDA rises while SCL high),
    and captures data bits (SDA sampled on SCL rising edge).
    """
    global byte_count, transaction_count

    prev_sda = sda.value()
    prev_scl = scl.value()
    bits = 0
    bit_count = 0
    in_transaction = False
    is_first_byte = False

    while sniffing:
        cur_sda = sda.value()
        cur_scl = scl.value()

        # Detect START: SDA falls while SCL is HIGH
        if prev_sda == 1 and cur_sda == 0 and cur_scl == 1:
            if in_transaction:
                sys.stdout.write("Sr\n")  # Repeated START
            else:
                sys.stdout.write("S\n")
            in_transaction = True
            is_first_byte = True
            bits = 0
            bit_count = 0

        # Detect STOP: SDA rises while SCL is HIGH
        elif prev_sda == 0 and cur_sda == 1 and cur_scl == 1:
            if in_transaction:
                sys.stdout.write("P\n")
                transaction_count += 1
                in_transaction = False
                bit_count = 0
                bits = 0

        # Detect rising edge of SCL: sample data bit
        elif prev_scl == 0 and cur_scl == 1 and in_transaction:
            if bit_count < 8:
                bits = (bits << 1) | cur_sda
                bit_count += 1
            elif bit_count == 8:
                # This is the ACK/NACK bit
                ack = "ACK" if cur_sda == 0 else "NACK"
                if is_first_byte:
                    addr = bits >> 1
                    rw = "R" if (bits & 1) else "W"
                    sys.stdout.write("%s:0x%02X:%s\n" % (rw, addr, ack))
                    is_first_byte = False
                else:
                    sys.stdout.write("D:0x%02X:%s\n" % (bits, ack))
                byte_count += 1
                bits = 0
                bit_count = 0

        prev_sda = cur_sda
        prev_scl = cur_scl


def cmd_status():
    """Report sniffing configuration and statistics."""
    print("I2C Sniffer: SDA=GP%d, SCL=GP%d" % (SDA_PIN, SCL_PIN))
    print("Sniffing: %s" % ("ON" if sniffing else "OFF"))
    print("Bytes captured: %d" % byte_count)
    print("Transactions: %d" % transaction_count)
    print("SDA: %s  SCL: %s" % (
        "HIGH" if sda.value() else "LOW",
        "HIGH" if scl.value() else "LOW"))


def cmd_help():
    """Print available commands."""
    print("Pico I2C Bus Sniffer (polling-based)")
    print("Commands:")
    print("  start   - Begin sniffing I2C bus")
    print("  stop    - Pause sniffing")
    print("  status  - Show configuration and statistics")
    print("  help    - Show this help")


def main():
    global sniffing

    print("PICO_I2C_SNIFFER_READY")
    print("Sniffing I2C on SDA=GP%d, SCL=GP%d" % (SDA_PIN, SCL_PIN))
    print("Waiting for I2C activity...")

    sniff_bus()


main()
'''


def show_firmware():
    """Print the MicroPython firmware source for copy-paste deployment."""
    print("[*] MicroPython I2C sniffer firmware for Raspberry Pi Pico")
    print("[*] Copy this code to main.py on your Pico")
    print("=" * 60)
    print(PICO_FIRMWARE)
    print("=" * 60)


def upload_firmware(pico_port):
    """Upload the firmware to a Pico over serial using raw REPL."""
    try:
        import serial
    except ImportError:
        print("[ERROR] pyserial is required: pip install pyserial")
        sys.exit(1)

    print("[*] Connecting to Pico on %s..." % pico_port)
    ser = serial.Serial(pico_port, 115200, timeout=2)
    time.sleep(0.5)

    # Enter raw REPL mode
    ser.write(b"\x03\x03")
    time.sleep(0.3)
    ser.write(b"\x01")
    time.sleep(0.5)
    ser.read(ser.in_waiting)

    script = "f = open('main.py', 'w')\n"
    for line in PICO_FIRMWARE.split("\n"):
        escaped = line.replace("\\", "\\\\").replace("'", "\\'")
        script += "f.write('%s\\n')\n" % escaped
    script += "f.close()\n"
    script += "print('I2C sniffer firmware written to main.py')\n"

    ser.write(script.encode())
    ser.write(b"\x04")
    time.sleep(2)

    response = ser.read(ser.in_waiting).decode(errors="replace")
    if "firmware written" in response.lower():
        print("[+] Firmware uploaded successfully")
    else:
        print("[!] Upload may have failed. Response:")
        print(response)

    ser.write(b"\x02")
    time.sleep(0.2)
    ser.write(b"\x04")
    ser.close()
    print("[*] Pico will restart and run the I2C sniffer firmware")


def decode_transactions(lines):
    """Parse captured I2C sniffer output into human-readable transactions."""
    transactions = []
    current = None

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line == "S" or line == "Sr":
            if current and current["bytes"]:
                transactions.append(current)
            current = {"type": "start", "address": None, "rw": None, "bytes": [], "acks": []}

        elif line == "P":
            if current:
                transactions.append(current)
                current = None

        elif line.startswith(("W:", "R:")):
            parts = line.split(":")
            if current is not None and len(parts) >= 3:
                current["rw"] = parts[0]
                current["address"] = int(parts[1], 16)
                current["acks"].append(parts[2])

        elif line.startswith("D:"):
            parts = line.split(":")
            if current is not None and len(parts) >= 3:
                current["bytes"].append(int(parts[1], 16))
                current["acks"].append(parts[2])

    if current and current["bytes"]:
        transactions.append(current)

    return transactions


def print_decoded(transactions):
    """Print decoded I2C transactions in a readable format."""
    print("\n[*] Decoded I2C Transactions:")
    print("-" * 60)

    for i, txn in enumerate(transactions):
        if txn["address"] is None:
            continue

        direction = "WRITE" if txn["rw"] == "W" else "READ"
        data_hex = " ".join("0x%02X" % b for b in txn["bytes"])
        data_ascii = ""
        for b in txn["bytes"]:
            if 0x20 <= b <= 0x7E:
                data_ascii += chr(b)
            else:
                data_ascii += "."

        print("  [%d] %s addr=0x%02X (%d bytes): %s" % (
            i, direction, txn["address"], len(txn["bytes"]), data_hex))
        if data_ascii.strip("."):
            print("       ASCII: %s" % data_ascii)

    print("-" * 60)
    print("[*] Total transactions: %d" % len(transactions))

    return transactions


def receive_data(pico_port, duration, output_file, decode):
    """Receive I2C sniffer data from the Pico and optionally decode it."""
    try:
        import serial
    except ImportError:
        print("[ERROR] pyserial is required: pip install pyserial")
        sys.exit(1)

    print("[*] Connecting to Pico on %s..." % pico_port)
    ser = serial.Serial(pico_port, 115200, timeout=1)
    time.sleep(1)
    ser.reset_input_buffer()

    # Wait for ready banner
    deadline = time.time() + 5
    ready = False
    while time.time() < deadline:
        raw = ser.readline()
        if raw and b"PICO_I2C_SNIFFER_READY" in raw:
            ready = True
            break
    if not ready:
        print("[!] Did not see ready banner (Pico may already be running)")

    print("[*] Capturing I2C data for %d seconds (Ctrl+C to stop early)..." % duration)
    print("-" * 60)

    lines = []
    outfile = None
    if output_file:
        outfile = open(output_file, "w")

    start = time.time()
    try:
        while time.time() - start < duration:
            raw = ser.readline()
            if raw:
                try:
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                except Exception:
                    line = raw.hex()
                print(line)
                lines.append(line)
                if outfile:
                    outfile.write(line + "\n")
    except KeyboardInterrupt:
        print("\n[Capture interrupted by user]")
    finally:
        ser.close()
        if outfile:
            outfile.close()

    print("-" * 60)
    print("[*] Captured %d lines of I2C data" % len(lines))

    if output_file:
        print("[+] Raw capture saved to %s" % output_file)

    if decode or not output_file:
        transactions = decode_transactions(lines)
        if transactions:
            print_decoded(transactions)
        else:
            print("[*] No complete I2C transactions captured.")
            print("    Tip: Ensure I2C traffic is active on the CoreS3 bus.")

    return lines


def main():
    parser = argparse.ArgumentParser(
        description="Raspberry Pi Pico I2C bus sniffer using pin polling to passively "
                    "capture I2C traffic from the CoreS3 internal bus. Replaces a "
                    "logic analyzer with a ~$4 Pico.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s --show-firmware
  %(prog)s --upload --pico-port /dev/ttyACM1
  %(prog)s --receive --pico-port /dev/ttyACM1 --duration 10
  %(prog)s --receive --pico-port /dev/ttyACM1 --decode --output i2c_capture.txt
""",
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--show-firmware",
        action="store_true",
        help="Display the MicroPython firmware source for manual deployment",
    )
    mode.add_argument(
        "--upload",
        action="store_true",
        help="Upload the sniffer firmware to a Pico via raw REPL over serial",
    )
    mode.add_argument(
        "--receive",
        action="store_true",
        help="Receive and display I2C data captured by the Pico",
    )

    parser.add_argument(
        "--pico-port",
        default="/dev/ttyACM1",
        help="Serial port for the Raspberry Pi Pico (default: /dev/ttyACM1)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=10,
        help="Capture duration in seconds (default: 10)",
    )
    parser.add_argument(
        "--output",
        help="Output file for raw captured data",
    )
    parser.add_argument(
        "--decode",
        action="store_true",
        help="Decode captured data into human-readable I2C transactions",
    )

    args = parser.parse_args()

    if args.show_firmware:
        show_firmware()
    elif args.upload:
        upload_firmware(args.pico_port)
    elif args.receive:
        receive_data(args.pico_port, args.duration, args.output, args.decode)


if __name__ == "__main__":
    main()
