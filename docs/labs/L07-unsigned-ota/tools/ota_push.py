#!/usr/bin/env python3
"""
OTA Firmware Push Tool

Hosts a firmware binary via a temporary HTTP server and pushes it to an
ESP32-S3 device by sending a POST request to the /ota endpoint. The device
downloads the firmware from the HTTP server and flashes it without any
signature verification.

Usage examples:

  # Push firmware to device (auto-detects local IP)
  ./ota_push.py --firmware firmware.bin

  # Push to a specific device URL
  ./ota_push.py --firmware firmware.bin --target http://192.168.4.1

  # Use a specific port for the HTTP server
  ./ota_push.py --firmware firmware.bin --serve-port 9090

  # Specify local IP explicitly (for multi-NIC hosts)
  ./ota_push.py --firmware firmware.bin --local-ip 192.168.4.100

  # Just serve the firmware without triggering OTA (manual trigger)
  ./ota_push.py --firmware firmware.bin --serve-only
"""

import argparse
import http.server
import json
import os
import socket
import sys
import threading
import time
import urllib.request
import urllib.error


DEFAULT_TARGET = "http://192.168.4.1"
DEFAULT_PORT = 8080


class FirmwareHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler that serves a single firmware file and tracks downloads."""

    firmware_path = None
    firmware_name = None
    download_count = 0
    download_complete = threading.Event()

    def do_GET(self):
        # Serve the firmware file regardless of the requested path
        if self.path.lstrip("/") == self.firmware_name or self.path == "/":
            self._serve_firmware()
        else:
            # Also serve if the path ends with the firmware filename
            if self.path.rstrip("/").endswith(self.firmware_name):
                self._serve_firmware()
            else:
                self.send_error(404, "Not Found")

    def _serve_firmware(self):
        try:
            with open(self.firmware_path, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.send_header(
                "Content-Disposition",
                'attachment; filename="{}"'.format(self.firmware_name),
            )
            self.end_headers()
            self.wfile.write(data)
            FirmwareHandler.download_count += 1
            print(
                "[+] Firmware downloaded by {} ({} bytes)".format(
                    self.client_address[0], len(data)
                )
            )
            FirmwareHandler.download_complete.set()
        except Exception as e:
            print("[!] Error serving firmware: {}".format(e))
            self.send_error(500, "Internal Server Error")

    def log_message(self, format, *args):
        # Prefix log messages for clarity
        print("[HTTP] {}".format(format % args))


def detect_local_ip(target_host):
    """Detect the local IP address used to reach the target device."""
    try:
        # Parse host from target URL
        host = target_host.replace("http://", "").replace("https://", "").split(":")[0]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.connect((host, 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip
    except Exception:
        return None


def start_http_server(firmware_path, port):
    """Start a background HTTP server to serve the firmware file."""
    FirmwareHandler.firmware_path = os.path.abspath(firmware_path)
    FirmwareHandler.firmware_name = os.path.basename(firmware_path)
    FirmwareHandler.download_count = 0
    FirmwareHandler.download_complete.clear()

    server = http.server.HTTPServer(("0.0.0.0", port), FirmwareHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def trigger_ota(target, firmware_url, timeout=10):
    """Send OTA trigger request to the device."""
    ota_url = "{}/ota".format(target.rstrip("/"))
    payload = "url={}".format(firmware_url)

    print("[*] Sending OTA trigger to {}".format(ota_url))
    print("[*] Firmware URL: {}".format(firmware_url))

    try:
        req = urllib.request.Request(
            ota_url,
            data=payload.encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=timeout)
        body = resp.read().decode("utf-8", errors="replace")
        print("[+] Device response (HTTP {}):".format(resp.status))
        # Try to pretty-print JSON
        try:
            parsed = json.loads(body)
            print(json.dumps(parsed, indent=2))
        except json.JSONDecodeError:
            print(body)
        return True
    except urllib.error.URLError as e:
        print("[!] Failed to reach device: {}".format(e))
        return False
    except socket.timeout:
        print("[!] Request timed out (device may be processing OTA)")
        return True  # OTA might still be in progress
    except Exception as e:
        print("[!] Error: {}".format(e))
        return False


def wait_for_reboot(target, max_wait=60):
    """Wait for the device to come back online after OTA."""
    print("[*] Waiting for device to reboot and come back online...")
    status_url = "{}/status".format(target.rstrip("/"))

    start = time.time()
    # Give the device a few seconds to start rebooting
    time.sleep(5)

    while time.time() - start < max_wait:
        try:
            req = urllib.request.Request(status_url)
            resp = urllib.request.urlopen(req, timeout=3)
            body = resp.read().decode("utf-8", errors="replace")
            try:
                status = json.loads(body)
                version = status.get("firmware", status.get("version", "unknown"))
                print("[+] Device is back online. Firmware version: {}".format(version))
                return True
            except json.JSONDecodeError:
                print("[+] Device is back online (non-JSON response).")
                return True
        except Exception:
            pass
        time.sleep(2)

    print("[!] Device did not come back online within {} seconds.".format(max_wait))
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Push unsigned OTA firmware to an ESP32-S3 device via the /ota "
        "endpoint. Hosts the firmware on a temporary HTTP server and "
        "triggers the device to download and flash it.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  # Push firmware with default settings
  %(prog)s --firmware .pio/build/M5CoreS3/firmware.bin

  # Push to a device at a custom address
  %(prog)s --firmware firmware.bin --target http://10.0.0.50

  # Serve firmware without triggering OTA (trigger manually)
  %(prog)s --firmware firmware.bin --serve-only

  # Specify local IP for the HTTP server URL
  %(prog)s --firmware firmware.bin --local-ip 192.168.4.100
""",
    )

    parser.add_argument(
        "--target",
        "-t",
        default=DEFAULT_TARGET,
        metavar="URL",
        help="Device URL (default: {})".format(DEFAULT_TARGET),
    )
    parser.add_argument(
        "--firmware",
        "-f",
        required=True,
        metavar="FILE",
        help="Path to firmware binary (.bin) to push",
    )
    parser.add_argument(
        "--serve-port",
        "-p",
        type=int,
        default=DEFAULT_PORT,
        metavar="PORT",
        help="HTTP server port for serving firmware (default: {})".format(DEFAULT_PORT),
    )
    parser.add_argument(
        "--local-ip",
        metavar="IP",
        help="Local IP address to use in firmware URL (auto-detected if omitted)",
    )
    parser.add_argument(
        "--serve-only",
        action="store_true",
        help="Only start HTTP server; do not trigger OTA on device",
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Do not wait for device to reboot after OTA",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        metavar="SECS",
        help="Max seconds to wait for device reboot (default: 60)",
    )

    args = parser.parse_args()

    # Validate firmware file
    if not os.path.isfile(args.firmware):
        print("[!] Error: firmware file not found: {}".format(args.firmware))
        sys.exit(1)

    fw_size = os.path.getsize(args.firmware)
    print("[*] Firmware: {} ({} bytes / {:.1f} KB)".format(
        args.firmware, fw_size, fw_size / 1024
    ))

    # Detect local IP
    local_ip = args.local_ip
    if not local_ip:
        local_ip = detect_local_ip(
            args.target.replace("http://", "").replace("https://", "").split(":")[0]
        )
        if not local_ip:
            print("[!] Could not auto-detect local IP. Use --local-ip to specify.")
            sys.exit(1)
    print("[*] Local IP: {}".format(local_ip))

    # Start HTTP server
    print("[*] Starting HTTP server on port {}...".format(args.serve_port))
    server = start_http_server(args.firmware, args.serve_port)
    firmware_url = "http://{}:{}/{}".format(
        local_ip, args.serve_port, os.path.basename(args.firmware)
    )
    print("[*] Firmware available at: {}".format(firmware_url))

    if args.serve_only:
        print()
        print("[*] Serve-only mode. Trigger OTA manually:")
        print(
            '    curl -X POST {}/ota -d "url={}"'.format(args.target, firmware_url)
        )
        print()
        print("[*] Press Ctrl+C to stop the server.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Server stopped.")
        return

    # Trigger OTA
    print()
    success = trigger_ota(args.target, firmware_url)

    if not success:
        print("[!] OTA trigger failed. The HTTP server is still running.")
        print("[*] You can trigger OTA manually:")
        print(
            '    curl -X POST {}/ota -d "url={}"'.format(args.target, firmware_url)
        )
        print("[*] Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        return

    # Wait for firmware download
    print("[*] Waiting for device to download firmware...")
    if FirmwareHandler.download_complete.wait(timeout=30):
        print("[+] Device downloaded the firmware.")
    else:
        print("[!] No download detected within 30 seconds.")
        print("    The device may have failed to reach this server.")

    # Wait for reboot
    if not args.no_wait:
        print()
        wait_for_reboot(args.target, args.timeout)

    # Cleanup
    server.shutdown()
    print("[*] HTTP server stopped.")
    print("[*] Done.")


if __name__ == "__main__":
    main()
