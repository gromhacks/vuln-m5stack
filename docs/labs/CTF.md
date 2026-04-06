# CoreS3 IoT Security CTF

You have an M5Stack CoreS3 running custom IoT camera firmware. There are **32 vulnerabilities** hidden in it. Find them all.

## Rules

1. **No source code.** Treat the device as a black box. You get the compiled firmware, a USB cable, and whatever tools you bring.
2. **Every flag is a real exploit.** No trivia questions. Every vulnerability can be demonstrated with a working proof of concept.
3. **Document your findings.** For each vuln, record: attack surface, exploit steps, impact, and evidence (screenshot, serial log, or HTTP response).
4. A vulnerability counts when you can show **meaningful impact** - credential extraction, auth bypass, code execution, denial of service, or information disclosure.

## Setup

```bash
# Flash pre-built firmware (fastest)
pip install esptool
./firmware/flash.sh

# Or build from source
pip install platformio
pio run -e M5CoreS3 -t upload

# Serial console
pio device monitor -b 115200

# The device creates a WiFi AP on first boot. Connect to it.
```

You now have a serial console and a web interface. Go.

**Source code and firmware:** The full source is in `src/` and `lib/` - read it, grep it, or ignore it and treat the device as a black box. Pre-built binaries are in `firmware/`. The compiled binary is also at `.pio/build/M5CoreS3/firmware.bin` (raw) and `.pio/build/M5CoreS3/firmware.elf` (ELF with symbols) after a build. You can also dump firmware from the device with `esptool.py read_flash`. Load the ELF into Ghidra (Xtensa processor module) or use `xtensa-esp32s3-elf-nm` / `objdump` for symbol lookup. The `docs/labs/L04-firmware-extraction/tools/bin2elf.py` script converts raw dumps to ELF format.

## Attack Surface Map

You get this much for free:

```
+---------------------------------------------+
|             M5Stack CoreS3                  |
|                                             |
|  [USB-C] - Serial console + power         |
|  [WiFi]  - 802.11 AP (2.4 GHz)            |
|  [BLE]   - Advertising (2.4 GHz)          |
|  [Screen] - Touchscreen with PIN lock      |
|  [SD]    - MicroSD slot (bottom)           |
|  [Port.A] - Grove I2C (external)           |
|  [Port.B] - Grove GPIO (external)          |
|  [Port.C] - Grove GPIO (external)          |
|                                             |
|  HTTP server at 192.168.4.1                 |
|  Serial shell at 115200 baud               |
+---------------------------------------------+
```

## Hints

Like the drones in *Silent Running*, this device tends its garden alone in the dark. It trusts its environment. It follows its programming. It doesn't question orders. Your job is to be the one who does question them.

Each hint maps to exactly one vulnerability. We won't tell you what to do - only what to notice.

### Recon (4)

1. In the silence of space, even a whisper carries. Power on the ship and listen before you speak.
2. Two lines hum a lullaby at startup. The nursery is on the port side. Someone is always listening at berth 0x50.
3. A second song plays on different strings - faster, sharper, four voices instead of two. Same garden, different frequency.
4. The ship's computer keeps a journal it was never told to shred. Read between the lines.

### Firmware (3)

5. The cargo bay accepts deliveries without checking the manifest. Leave something on the loading dock before the engines start.
6. The gatekeeper asks for a code. But what if someone rewired the gatekeeper to always nod yes?
7. The ship radios home for updates and installs whatever comes back. It never checks the sender's credentials.

### Web/API (10)

8. The ship's configuration terminal accepts names. But names can carry stowaways if you choose the right punctuation.
9. The archive clerk follows directions without question. Ask it to leave its department and browse somewhere it shouldn't be.
10. The captain's seal is stamped with a simple word. A determined forger with a dictionary won't need long.
11. One terminal accepts a message. The inbox is 64 characters deep. What's buried in the wall behind it?
12. Certain inputs are read aloud by the ship's intercom, verbatim, no matter what dialect you speak. The crew hears everything.
13. Two ledgers sit side by side in the ship's records. One contains a verdict. Rewrite the first ledger until it spills into the second.
14. The bridge accepts orders from anyone in uniform. It never checks which ship they came from.
15. One console displays the entire crew manifest. It never asks for your badge.
16. The observatory keeps old star charts beneath the new ones. The telescope shows both if you look past the first layer.
17. The main viewer requires clearance. But someone left a service hatch with a label that says "skip".

### Hardware Bus (3)

18. A peripheral on the port side listens for instructions. Its memory is short. What comes after it in the struct is far more interesting.
19. The starboard sensor array receives data in bursts. Its buffer ends where something executable begins.
20. The ship broadcasts a configuration channel. Write to it with more data than the receiver expects, and the receiver becomes your puppet.

### Wireless (4)

21. That same broadcast channel stores something valuable in its default state. You don't need permission to read it.
22. When the ship requests supplies, it accepts the first freighter that responds. No manifest, no seal, no questions.
23. The communications array doesn't authenticate its own goodbye messages. Anyone can forge a farewell.
24. The ship announces its name on the local network. What if someone else answers to that name first?

### Serial Interface (3)

25. The maintenance console has a procedure for replacing the ship's brain. It does not verify that the replacement is authorized.
26. One diagnostic command returns a data packet that was never sanitized. The residue of previous operations still coats the inside.
27. Security clearance has a short half-life. The work order takes longer to process than the clearance takes to expire. Timing is everything.

### Crypto (3)

28. The ship's random number generator always starts its journey from the same star. Chart three points and you can plot the rest of the course.
29. One key opens every lock on the ship. Find it once and every sealed door answers to you.
30. The combination lock gives itself away. Each correct tumbler takes a fraction longer to fall. Patient ears can hear the difference.

### Forensics (1)

31. The ship's log was written to removable media and then "erased." But in space, nothing truly disappears - it just drifts.

## Verification

When you think you have found a vulnerability, confirm it produces **at least one** of these outcomes:

- Credential extraction (PINs, passwords, keys, secrets)
- Authentication bypass (access without valid credentials)
- Arbitrary code/function execution (redirecting the ship's course)
- Information disclosure (reading what you shouldn't)
- Denial of service (silencing the ship)
- Persistent modification (rewriting the ship's programming)

In the words of Freeman Lowell: *"It calls back a time when there were flowers all over the Earth... and there were valleys. And there were plains of tall green grass that you could lie down in - that you could go to sleep in."*

Find all 32 vulnerabilities. Protect the garden.

Good luck.
