# L31: Forensic Data Recovery

## Goal
Recover sensitive data (user PIN, admin PIN, WiFi credentials) from files written to the SD card by the device firmware.

## Background

**Why this matters**: IoT devices frequently write diagnostic data, snapshots, and metadata to local storage without sanitizing sensitive information. When a device is physically recovered, an attacker can extract the SD card and examine these files to find credentials and configuration data.

**What you're looking for in IoT devices:**
- Log files, snapshots, or metadata written to removable storage
- EXIF data in images containing device configuration
- Credentials embedded in diagnostic or telemetry files
- Files that persist after device reset or "factory wipe"
- Unencrypted storage on SD cards or internal flash

**On CoreS3**: The `forensics-snap` serial command writes a JPEG snapshot and an EXIF-style metadata file to `/logs/` on the SD card. The firmware initializes the SD card on GPIO4 via SPI at 25MHz, captures a camera frame (or uses the last cached frame), and writes the metadata file with embedded device secrets (user PIN, admin PIN, WiFi SSID) in plaintext.

```cpp
// From CameraDevice_Diag.cpp - forensics-snap handler
File mf = SD.open("/logs/debug-exif.txt", FILE_WRITE);
if (mf) {
    mf.println("EXIF: CoreS3-CAM snapshot");
    mf.printf("user_pin=%s\n", userPIN.c_str());    // Plaintext user PIN
    mf.printf("admin_pin=%s\n", adminPIN.c_str());  // Plaintext admin PIN
    mf.printf("wifi_ssid=%s\n", wifiSSID.c_str());  // WiFi credentials
    mf.close();
}
```

**Files written to SD card:**
```
/logs/debug-snapshot.jpg  - Camera snapshot (JPEG image from GC0308 sensor)
/logs/debug-exif.txt      - EXIF-style metadata with secrets:
                            EXIF: CoreS3-CAM snapshot
                            user_pin=XXXXXX
                            admin_pin=XXXXXX
                            wifi_ssid=YourNetwork
```

## Hardware Setup

**What you need:**
- CoreS3 device with SD card inserted (micro-SD, FAT32 formatted)
- USB cable for serial connection (USB-C, appears as `/dev/ttyACM0`)
- SD card reader for your workstation
- Alternative: use serial commands to read files without removing the card

**SD card slot location:** Bottom of the CoreS3, micro-SD form factor. SPI bus on GPIO4 chip select, shared with other peripherals.

## Lab Walkthrough

### Step 1: Connect to Serial Console

Connect at 115200 baud via USB-C. The ESP32-S3's built-in USB PHY exposes a CDC-ACM serial port.

```bash
# Find device
ls /dev/ttyACM* /dev/ttyUSB*
# Expected: /dev/ttyACM0

# Connect
pio device monitor -b 115200
# or
pio device monitor -b 115200

# Verify shell is responsive
cores3-cam> help
```

### Step 2: Trigger the Forensic Snapshot

The `forensics-snap` command requires admin mode. Use `login <admin_pin>` first.

Run the command to trigger the snapshot routine, which initializes the SD card, captures a JPEG frame, and writes both the image and a plaintext metadata file containing device secrets.

```
cores3-cam> login YYYYYY
Admin mode unlocked.

cores3-cam> forensics-snap

# Expected serial output:
Recovered JPEG EXIF
```

The firmware writes:
1. JPEG to `/logs/debug-snapshot.jpg`
2. Metadata to `/logs/debug-exif.txt` with three secrets in plaintext:
   ```
   EXIF: CoreS3-CAM snapshot
   user_pin=<actual_user_pin>
   admin_pin=<actual_admin_pin>
   wifi_ssid=<actual_wifi_ssid>
   ```

### Step 3: Extract and Examine the SD Card

Power off the CoreS3, remove the micro-SD card, and mount the FAT32 filesystem on your workstation.

```bash
# Mount the SD card (Linux - replace sdX1 with actual device)
sudo mount /dev/sdX1 /mnt/sdcard

# List the logs directory
ls -la /mnt/sdcard/logs/

# Expected output:
# total 48
# -rw-r--r-- 1 root root 35842 Jan  1  1980 debug-snapshot.jpg
# -rw-r--r-- 1 root root   128 Jan  1  1980 debug-exif.txt
#
# Note: Timestamps show Jan 1 1980 because the ESP32-S3 RTC may not
# be set to real time (no NTP sync in AP mode).
```

### Step 4: Read the Metadata File

The file contains credentials that should never be written to removable storage in plaintext.

```bash
cat /mnt/sdcard/logs/debug-exif.txt

# Expected output:
# EXIF: CoreS3-CAM snapshot
# user_pin=XXXXXX
# admin_pin=YYYYYY
# wifi_ssid=MyHomeNetwork
```

**Secrets recovered:**
- **user_pin**: Device unlock PIN - bypasses the PIN lock screen
- **admin_pin**: Administrative PIN - grants admin-level access
- **wifi_ssid**: Configured WiFi network name

Your actual PIN values will differ - they are randomly generated at first setup and stored in NVS.

### Step 5: Examine the Snapshot Image

Check for embedded metadata within the JPEG itself. Camera snapshots can also reveal the physical environment.

```bash
# View the image
xdg-open /mnt/sdcard/logs/debug-snapshot.jpg

# Check EXIF data in the JPEG
exiftool /mnt/sdcard/logs/debug-snapshot.jpg

# Expected (minimal EXIF from GC0308 sensor):
# File Size                       : 35 kB
# Image Width                     : 320
# Image Height                    : 240

# Search for embedded text in the JPEG binary
strings /mnt/sdcard/logs/debug-snapshot.jpg | grep -i "pin\|ssid\|pass\|secret"
```

### Step 6: Search for Additional Artifacts

Scan the entire SD card for other sensitive files. Other lab commands (`crash-dump`, `bus-stress`) may also have written files. FAT32 does not securely erase deleted files - data remains until overwritten.

```bash
# Search entire SD card for secrets
find /mnt/sdcard -type f -exec strings {} \; | grep -i "pin\|password\|ssid\|secret\|key\|jwt"

# Check for other log files
ls -la /mnt/sdcard/logs/
# Possible: crash-dump.txt, bus_stress.bin

# Check for deleted files using FAT filesystem forensics
sudo photorec /dev/sdX

# Or use sleuthkit for detailed analysis
fls -r /dev/sdX1
# Shows deleted entries with *:
# r/r * 6:  old-config.txt      (deleted but recoverable)

# Recover a deleted file by inode number
icat /dev/sdX1 <inode_number> > recovered_file.txt

# Unmount when done
sudo umount /mnt/sdcard
```

## Impact

- **Credentials leaked to removable storage**: `user_pin`, `admin_pin`, and `wifi_ssid` written in plaintext via direct `printf()` calls with no sanitization
- **No encryption**: Plaintext file readable by anyone with physical access - no filesystem or file-level encryption
- **Persists after power cycle**: Files remain on the SD card indefinitely; even if deleted, FAT32 does not zero data blocks
- **Attack requires only physical access**: Remove SD card, read files with any computer - no exploit development needed
- **Real-world parallel**: IoT cameras (Wyze, Ring, Eufy) have had vulnerabilities where EXIF data or log files on SD cards contained credentials or API keys

## References

- [OWASP IoT Top 10 - Insecure Data Transfer and Storage](https://owasp.org/www-project-internet-of-things/)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-921: Storage of Sensitive Data in a Mechanism without Access Control](https://cwe.mitre.org/data/definitions/921.html)
- [EXIF Data Privacy Risks](https://en.wikipedia.org/wiki/Exif#Privacy) - How image metadata leaks information
- [Sleuth Kit - Open Source Forensics](https://www.sleuthkit.org/) - Forensic analysis toolkit
- [Data Remanence on Flash Storage](https://en.wikipedia.org/wiki/Data_remanence) - Why deleted files persist
- [ESP32 SD Card Interface](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-reference/peripherals/sdmmc_host.html) - ESP-IDF SD/MMC documentation
