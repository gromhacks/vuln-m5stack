#!/usr/bin/env python3
"""
Raspberry Pi Pico MicroPython UART Capture Tool

MicroPython firmware for a Raspberry Pi Pico that passively captures UART
traffic from the CoreS3 debug UART (GPIO43 TX on the expansion header).
The Pico receives data on GP1 (UART1 RX) and streams it over USB serial
to the host PC for manual analysis.

This replaces a dedicated USB-UART adapter (~$10-15) with a Raspberry Pi
Pico (~$4), making the lab accessible on a tighter budget.

Hardware connections:
  Pico GP1 (UART1 RX) -> CoreS3 GPIO43 (TXD0, expansion header pin 14)
  Pico GND             -> CoreS3 GND (expansion header pin 1)

Usage examples:

  # Display the MicroPython firmware to copy-paste into Thonny
  ./pico_uart_sniffer.py --show-firmware

  # Upload firmware to Pico via serial
  ./pico_uart_sniffer.py --upload --pico-port /dev/ttyACM1

  # Receive captured UART data
  ./pico_uart_sniffer.py --receive --pico-port /dev/ttyACM1 --duration 30

  # Receive and save raw output to file
  ./pico_uart_sniffer.py --receive --pico-port /dev/ttyACM1 --output capture.txt
"""

import argparse
import sys
import time


# ---------------------------------------------------------------------------
# MicroPython firmware source for the Raspberry Pi Pico
# ---------------------------------------------------------------------------
PICO_FIRMWARE = r'''
# pico_uart_sniffer.py - Raspberry Pi Pico MicroPython
# Passive UART sniffer for CoreS3 debug UART output
#
# Connections:
#   GP1 (UART1 RX) -> CoreS3 GPIO43 (TXD0, expansion header pin 14)
#   GND             -> CoreS3 GND (expansion header pin 1)
#
# The Pico receives UART data from the CoreS3 debug port and forwards
# every received line over USB serial to the host PC.
#
# Commands over USB serial (optional, normally runs in auto-capture mode):
#   start    - Begin forwarding UART data (default on boot)
#   stop     - Pause forwarding
#   status   - Report UART configuration and byte count
#   help     - Show available commands

import machine
import sys
import time

# Pin configuration - UART1 with RX on GP1
UART_ID = 1
UART_RX_PIN = 1       # GP1 - connected to CoreS3 GPIO43 (TX)
UART_BAUD = 115200

# Initialize UART1 for receiving target data
uart = machine.UART(UART_ID, baudrate=UART_BAUD, rx=machine.Pin(UART_RX_PIN))
uart.init(UART_BAUD, bits=8, parity=None, stop=1, rxbuf=4096)

# State
forwarding = True
total_bytes = 0


def cmd_status():
    """Report UART configuration and statistics."""
    print("UART%d RX on GP%d at %d baud" % (UART_ID, UART_RX_PIN, UART_BAUD))
    print("Forwarding: %s" % ("ON" if forwarding else "OFF"))
    print("Total bytes received: %d" % total_bytes)


def cmd_help():
    """Print available commands."""
    print("Pico UART Sniffer")
    print("Commands:")
    print("  start   - Begin forwarding UART data to USB serial")
    print("  stop    - Pause forwarding")
    print("  status  - Show UART config and byte count")
    print("  help    - Show this help")


def check_usb_command():
    """Check for commands from the host PC over USB serial (non-blocking)."""
    global forwarding
    # Read from USB serial (stdin) with a very short timeout
    import select
    if select.select([sys.stdin], [], [], 0)[0]:
        try:
            line = sys.stdin.readline().strip()
        except Exception:
            return
        if line == "start":
            forwarding = True
            print("Forwarding ON")
        elif line == "stop":
            forwarding = False
            print("Forwarding OFF")
        elif line == "status":
            cmd_status()
        elif line == "help":
            cmd_help()


def main():
    global forwarding, total_bytes

    print("PICO_UART_SNIFFER_READY")
    print("Listening on UART%d GP%d at %d baud" % (UART_ID, UART_RX_PIN, UART_BAUD))

    buf = bytearray(512)

    while True:
        # Read available data from the target UART
        n = uart.readinto(buf)
        if n and n > 0 and forwarding:
            total_bytes += n
            # Write raw bytes to USB serial (stdout)
            sys.stdout.buffer.write(buf[:n])

        # Brief sleep to avoid tight-looping when idle
        if not n:
            time.sleep_ms(10)


main()
'''


def show_firmware():
    """Print the MicroPython firmware source for copy-paste deployment."""
    print("[*] MicroPython UART sniffer firmware for Raspberry Pi Pico")
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
    script += "print('UART sniffer firmware written to main.py')\n"

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
    print("[*] Pico will restart and run the sniffer firmware")


def receive_data(pico_port, duration, output_file):
    """Receive UART data forwarded by the Pico."""
    try:
        import serial
    except ImportError:
        print("[ERROR] pyserial is required: pip install pyserial")
        sys.exit(1)

    print("[*] Connecting to Pico on %s..." % pico_port)
    ser = serial.Serial(pico_port, 115200, timeout=1)
    time.sleep(1)
    ser.reset_input_buffer()

    # Wait for the ready banner
    deadline = time.time() + 5
    ready = False
    while time.time() < deadline:
        raw = ser.readline()
        if raw and b"PICO_UART_SNIFFER_READY" in raw:
            ready = True
            break
    if not ready:
        print("[!] Did not see ready banner (Pico may already be running)")

    print("[*] Capturing UART data for %d seconds (Ctrl+C to stop early)..." % duration)
    print("-" * 60)

    lines = []
    total_bytes = 0
    outfile = None
    if output_file:
        outfile = open(output_file, "w")

    start = time.time()
    try:
        while time.time() - start < duration:
            raw = ser.readline()
            if raw:
                total_bytes += len(raw)
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
    print("\n[SUMMARY] Captured %d line(s), %d bytes received." % (len(lines), total_bytes))

    if output_file:
        print("[+] Raw capture saved to %s" % output_file)


def main():
    parser = argparse.ArgumentParser(
        description="Raspberry Pi Pico UART capture tool for passively capturing debug UART "
                    "output from the CoreS3 IoT camera. Replaces a USB-UART adapter "
                    "with a ~$4 Pico.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s --show-firmware
  %(prog)s --upload --pico-port /dev/ttyACM1
  %(prog)s --receive --pico-port /dev/ttyACM1 --duration 30
  %(prog)s --receive --pico-port /dev/ttyACM1 --output capture.txt
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
        help="Receive UART data forwarded by the Pico",
    )

    parser.add_argument(
        "--pico-port",
        default="/dev/ttyACM1",
        help="Serial port for the Raspberry Pi Pico (default: /dev/ttyACM1)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Capture duration in seconds (default: 30)",
    )
    parser.add_argument(
        "--output",
        help="Output file for raw captured data",
    )

    args = parser.parse_args()

    if args.show_firmware:
        show_firmware()
    elif args.upload:
        upload_firmware(args.pico_port)
    elif args.receive:
        receive_data(args.pico_port, args.duration, args.output)


if __name__ == "__main__":
    main()
