#!/usr/bin/env bash
# Flash pre-built firmware to M5Stack CoreS3
# Usage: ./firmware/flash.sh [PORT]
#   PORT defaults to auto-detect

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${1:-}"

if [ -z "$PORT" ]; then
    # Auto-detect ESP32-S3 USB JTAG serial port
    PORT=$(ls /dev/serial/by-id/*Espressif* 2>/dev/null | head -1 || true)
    if [ -z "$PORT" ]; then
        echo "ERROR: No ESP32-S3 device found. Connect the CoreS3 via USB-C and try again."
        echo "       Or specify the port manually: $0 /dev/ttyACM0"
        exit 1
    fi
    echo "Auto-detected device: $PORT"
fi

# Check for esptool (prefer 'esptool' over deprecated 'esptool.py')
if command -v esptool &>/dev/null; then
    ESPTOOL="esptool"
elif command -v esptool.py &>/dev/null; then
    ESPTOOL="esptool.py"
elif [ -f ".venv/bin/esptool" ]; then
    ESPTOOL=".venv/bin/esptool"
elif [ -f ".venv/bin/esptool.py" ]; then
    ESPTOOL=".venv/bin/esptool.py"
else
    echo "ERROR: esptool not found. Install with: pip install esptool"
    exit 1
fi

echo "Flashing CoreS3 firmware on $PORT ..."
$ESPTOOL --chip esp32s3 \
    --port "$PORT" \
    --baud 460800 \
    --before default-reset \
    --after hard-reset \
    write-flash -z \
    --flash-mode dio \
    --flash-freq 80m \
    --flash-size 8MB \
    0x0 "$SCRIPT_DIR/firmware.bin"

echo "Flash complete. Device will reboot automatically."
