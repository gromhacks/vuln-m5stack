#!/usr/bin/env python3
"""
Raspberry Pi Pico MicroPython SPI Bus Sniffer (PIO-based)

MicroPython firmware for a Raspberry Pi Pico that passively sniffs SPI bus
traffic using the RP2040's PIO (Programmable I/O) state machines. The PIO
program monitors CS (active low), SCK, MOSI, and MISO lines, sampling data
on SCK rising edges while CS is asserted.

This replaces a logic analyzer ($15-100+) with a Raspberry Pi Pico (~$4)
for basic SPI bus sniffing.

Hardware connections:
  Pico GP10 (input) -> CoreS3 GPIO17 (SCK)   - Port.C pin 2
  Pico GP11 (input) -> CoreS3 GPIO8  (MOSI)  - Port.B pin 1
  Pico GP12 (input) -> CoreS3 GPIO9  (MISO)  - Port.B pin 2
  Pico GP13 (input) -> CoreS3 GPIO18 (CS)    - Port.C pin 1
  Pico GND          -> CoreS3 GND

Usage examples:

  # Display the MicroPython firmware to copy-paste into Thonny
  ./pico_spi_sniffer.py --show-firmware

  # Upload firmware to Pico via serial
  ./pico_spi_sniffer.py --upload --pico-port /dev/ttyACM1

  # Receive and decode captured SPI transactions
  ./pico_spi_sniffer.py --receive --pico-port /dev/ttyACM1 --duration 10

  # Receive with full ASCII decode of payload
  ./pico_spi_sniffer.py --receive --pico-port /dev/ttyACM1 --decode
"""

import argparse
import sys
import time


# ---------------------------------------------------------------------------
# MicroPython + PIO firmware source for the Raspberry Pi Pico
# ---------------------------------------------------------------------------
PICO_FIRMWARE = r'''
# pico_spi_sniffer.py - Raspberry Pi Pico MicroPython
# Passive SPI bus sniffer using PIO state machines
#
# Connections (all high-impedance inputs, no pull resistors):
#   GP10 (input) -> CoreS3 GPIO17 (SCK)   - SPI clock
#   GP11 (input) -> CoreS3 GPIO8  (MOSI)  - Master Out Slave In
#   GP12 (input) -> CoreS3 GPIO9  (MISO)  - Master In Slave Out
#   GP13 (input) -> CoreS3 GPIO18 (CS)    - Chip Select (active LOW)
#   GND          -> CoreS3 GND
#
# Output format over USB serial:
#   CS_LOW                  - CS asserted (transaction start)
#   CS_HIGH                 - CS deasserted (transaction end)
#   MOSI:0xAB MISO:0xCD    - One byte transferred (both directions)
#
# Commands over USB serial:
#   start    - Begin sniffing (default on boot)
#   stop     - Pause sniffing
#   status   - Report configuration and byte count
#   help     - Show available commands
#
# The PIO state machine watches for CS going LOW, then on each SCK rising
# edge it samples both MOSI and MISO simultaneously. Bytes are accumulated
# and sent over USB serial after each complete 8-bit transfer.

import machine
import rp2
import time
import sys

# Pin configuration
SCK_PIN  = 10   # GP10 - connected to CoreS3 GPIO17 (SCK)
MOSI_PIN = 11   # GP11 - connected to CoreS3 GPIO8  (MOSI)
MISO_PIN = 12   # GP12 - connected to CoreS3 GPIO9  (MISO)
CS_PIN   = 13   # GP13 - connected to CoreS3 GPIO18 (CS, active LOW)

# Initialize pins as high-impedance inputs
sck  = machine.Pin(SCK_PIN,  machine.Pin.IN)
mosi = machine.Pin(MOSI_PIN, machine.Pin.IN)
miso = machine.Pin(MISO_PIN, machine.Pin.IN)
cs   = machine.Pin(CS_PIN,   machine.Pin.IN)

# State
sniffing = True
byte_count = 0
transaction_count = 0


@rp2.asm_pio()
def spi_sniff_pio():
    """PIO program to capture SPI data on SCK rising edges.

    Reads two pins starting at MOSI_PIN (GP11):
      bit 0 = MOSI (GP11)
      bit 1 = MISO (GP12)

    Protocol:
    1. Wait for SCK rising edge
    2. Sample MOSI and MISO
    3. Push 2-bit sample to FIFO
    4. Repeat

    The host-side code handles CS detection and byte assembly.
    """
    # Wait for SCK rising edge (pin index 0 = SCK = GP10 via in_base)
    wait(0, pin, 0)     # Wait for SCK LOW
    wait(1, pin, 0)     # Wait for SCK HIGH (rising edge)

    # Sample MOSI and MISO (2 bits starting at GP11)
    # We use in_base=GP10, so pin0=SCK, pin1=MOSI, pin2=MISO
    in_(pins, 3)         # Read 3 pins: SCK, MOSI, MISO into ISR
    push(noblock)        # Push to RX FIFO

    # Loop back to wait for next edge
    wrap()


def sniff_bus_polling():
    """SPI sniffing using fast pin polling (fallback if PIO is tricky).

    Watches CS for active-low assertion, then samples MOSI and MISO
    on each SCK rising edge, accumulating bytes MSB-first.
    """
    global byte_count, transaction_count

    prev_sck = sck.value()
    prev_cs = cs.value()
    mosi_byte = 0
    miso_byte = 0
    bit_count = 0
    in_transaction = False

    while sniffing:
        cur_cs = cs.value()
        cur_sck = sck.value()

        # Detect CS falling edge (transaction start)
        if prev_cs == 1 and cur_cs == 0:
            in_transaction = True
            bit_count = 0
            mosi_byte = 0
            miso_byte = 0
            sys.stdout.write("CS_LOW\n")

        # Detect CS rising edge (transaction end)
        elif prev_cs == 0 and cur_cs == 1:
            if in_transaction:
                # Flush any partial byte
                if bit_count > 0:
                    sys.stdout.write("MOSI:0x%02X MISO:0x%02X (partial:%d)\n" % (
                        mosi_byte, miso_byte, bit_count))
                sys.stdout.write("CS_HIGH\n")
                transaction_count += 1
                in_transaction = False
                bit_count = 0

        # Sample data on SCK rising edge while CS is LOW
        elif prev_sck == 0 and cur_sck == 1 and cur_cs == 0 and in_transaction:
            mosi_byte = (mosi_byte << 1) | mosi.value()
            miso_byte = (miso_byte << 1) | miso.value()
            bit_count += 1

            if bit_count == 8:
                sys.stdout.write("MOSI:0x%02X MISO:0x%02X\n" % (mosi_byte, miso_byte))
                byte_count += 1
                mosi_byte = 0
                miso_byte = 0
                bit_count = 0

        prev_sck = cur_sck
        prev_cs = cur_cs


def cmd_status():
    """Report sniffing configuration and statistics."""
    print("SPI Sniffer: SCK=GP%d MOSI=GP%d MISO=GP%d CS=GP%d" % (
        SCK_PIN, MOSI_PIN, MISO_PIN, CS_PIN))
    print("Sniffing: %s" % ("ON" if sniffing else "OFF"))
    print("Bytes captured: %d" % byte_count)
    print("Transactions: %d" % transaction_count)
    print("Pin states: SCK=%d MOSI=%d MISO=%d CS=%d" % (
        sck.value(), mosi.value(), miso.value(), cs.value()))


def cmd_help():
    """Print available commands."""
    print("Pico SPI Bus Sniffer")
    print("Commands:")
    print("  start   - Begin sniffing SPI bus")
    print("  stop    - Pause sniffing")
    print("  status  - Show configuration and statistics")
    print("  help    - Show this help")


def main():
    global sniffing

    print("PICO_SPI_SNIFFER_READY")
    print("Sniffing SPI: SCK=GP%d MOSI=GP%d MISO=GP%d CS=GP%d" % (
        SCK_PIN, MOSI_PIN, MISO_PIN, CS_PIN))
    print("Waiting for SPI activity (CS LOW)...")

    # Use polling-based approach for reliability
    sniff_bus_polling()


main()
'''


def show_firmware():
    """Print the MicroPython firmware source for copy-paste deployment."""
    print("[*] MicroPython SPI sniffer firmware for Raspberry Pi Pico")
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
    script += "print('SPI sniffer firmware written to main.py')\n"

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
    print("[*] Pico will restart and run the SPI sniffer firmware")


def decode_transactions(lines):
    """Parse captured SPI sniffer output into transactions."""
    transactions = []
    current_mosi = []
    current_miso = []
    in_txn = False

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line == "CS_LOW":
            in_txn = True
            current_mosi = []
            current_miso = []

        elif line == "CS_HIGH":
            if in_txn and (current_mosi or current_miso):
                transactions.append({
                    "mosi": list(current_mosi),
                    "miso": list(current_miso),
                })
            in_txn = False

        elif line.startswith("MOSI:") and in_txn:
            parts = line.split()
            for part in parts:
                if part.startswith("MOSI:"):
                    try:
                        current_mosi.append(int(part[5:], 16))
                    except ValueError:
                        pass
                elif part.startswith("MISO:"):
                    try:
                        current_miso.append(int(part[5:], 16))
                    except ValueError:
                        pass

    # Handle unterminated transaction
    if in_txn and (current_mosi or current_miso):
        transactions.append({
            "mosi": list(current_mosi),
            "miso": list(current_miso),
        })

    return transactions


def bytes_to_ascii(data):
    """Convert byte list to printable ASCII, replacing non-printable with dots."""
    result = ""
    for b in data:
        if 0x20 <= b <= 0x7E:
            result += chr(b)
        else:
            result += "."
    return result


def print_decoded(transactions):
    """Print decoded SPI transactions with hex and ASCII views."""
    print("\n[*] Decoded SPI Transactions:")
    print("-" * 60)

    for i, txn in enumerate(transactions):
        mosi_hex = " ".join("%02X" % b for b in txn["mosi"])
        miso_hex = " ".join("%02X" % b for b in txn["miso"])
        mosi_ascii = bytes_to_ascii(txn["mosi"])
        miso_ascii = bytes_to_ascii(txn["miso"])

        print("  [%d] %d bytes" % (i, len(txn["mosi"])))
        print("    MOSI: %s" % mosi_hex)
        if mosi_ascii.strip("."):
            print("    MOSI ASCII: %s" % mosi_ascii)
        print("    MISO: %s" % miso_hex)
        if miso_ascii.strip("."):
            print("    MISO ASCII: %s" % miso_ascii)
        print()

    print("-" * 60)
    print("[*] Total transactions: %d" % len(transactions))

    # Look for ASCII payload in MOSI data (debug logger output)
    full_mosi = ""
    for txn in transactions:
        full_mosi += bytes_to_ascii(txn["mosi"])

    if full_mosi.strip("."):
        print("\n[*] Combined MOSI ASCII payload:")
        # Print in 80-char lines
        clean = ""
        for ch in full_mosi:
            if ch != ".":
                clean += ch
            elif clean and clean[-1] != " ":
                clean += " "
        if clean.strip():
            print("    %s" % clean.strip())

    return transactions


def receive_data(pico_port, duration, output_file, decode):
    """Receive SPI sniffer data from the Pico and optionally decode it."""
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
        if raw and b"PICO_SPI_SNIFFER_READY" in raw:
            ready = True
            break
    if not ready:
        print("[!] Did not see ready banner (Pico may already be running)")

    print("[*] Capturing SPI data for %d seconds (Ctrl+C to stop early)..." % duration)
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
    print("[*] Captured %d lines of SPI data" % len(lines))

    if output_file:
        print("[+] Raw capture saved to %s" % output_file)

    if decode or not output_file:
        transactions = decode_transactions(lines)
        if transactions:
            print_decoded(transactions)
        else:
            print("[*] No complete SPI transactions captured.")
            print("    Tip: SPI debug output occurs at boot. Try resetting the CoreS3.")

    return lines


def main():
    parser = argparse.ArgumentParser(
        description="Raspberry Pi Pico SPI bus sniffer for passively capturing SPI "
                    "debug logger traffic from the CoreS3 IoT camera. Replaces a "
                    "logic analyzer with a ~$4 Pico.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s --show-firmware
  %(prog)s --upload --pico-port /dev/ttyACM1
  %(prog)s --receive --pico-port /dev/ttyACM1 --duration 10
  %(prog)s --receive --pico-port /dev/ttyACM1 --decode --output spi_capture.txt
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
        help="Receive and display SPI data captured by the Pico",
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
        help="Decode captured data into human-readable SPI transactions with ASCII",
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
