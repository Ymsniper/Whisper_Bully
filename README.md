# Whisper Bully

**Bluetooth BDADDR Extraction, Denial-of-Service & Hijack Research Tool**

> © 2026 [@Ymsniper](https://github.com/Ymsniper) — For authorized security research only.

---

## Overview

Whisper Bully is a three-stage Bluetooth security research tool targeting devices that advertise Google Fast Pair (service UUID `fe2c`). It demonstrates two unpatched attack primitives that are **outside the scope of the CVE-2025-36911 firmware patch**:

- **Unpatched BDADDR leak** — permanent identity address disclosed via plain BLE connection, no GATT interaction required, works on fully patched devices
- **SMP authentication bypass via reset window** — persistent bond established through standard SMP Just Works during BT stack recovery after L2CAP flood, without any Fast Pair GATT handshake

> ⚠️ **This tool does NOT implement the Whisper Pair (Fast Pair GATT) protocol.** It never writes to the Key-Based Pairing characteristic (UUID 1236) or Account Key characteristic (UUID 1238). The attack surface described here is separate from and unaddressed by the CVE-2025-36911 pairing mode check patch.

---


https://github.com/user-attachments/assets/67f2bcb6-38ad-4ba0-80c5-36dbb54f3f11


## Attack Stages

### Stage 1 — BDADDR Extraction (Unpatched Information Disclosure)

**Root cause:** When a BLE connection is established, the Linux BlueZ host stack processes the `LL_CONNECTION_COMPLETE` event and resolves the device's Resolvable Private Address (RPA) to its permanent Identity Address, caching it in the BlueZ device table. This happens at the Link Layer / HCI level, before any GATT service interaction. No Fast Pair protocol is involved.

**What the code actually does:**

1. Performs an active BLE scan (`BleakScanner`) for devices advertising Fast Pair service UUID `fe2c` — used only for target identification, no protocol interaction
2. Establishes a plain BLE connection via `BleakClient.connect()` — no GATT writes of any kind
3. Sets the BlueZ agent to `NoInputNoOutput` in preparation for Step 4
4. Checks whether the Fast Pair GATT service is present on the target — this check is **advisory only**; the tool continues regardless of the result (line 452 of `wb.py`)
5. Runs `bluetoothctl pair <rpa_addr>` — standard Bluetooth SMP pairing attempt, not Fast Pair
6. Monitors `bluetoothctl` stdout for `Bonded: yes` output, which may carry the bonded address
7. **Primary fallback:** Calls `bluetoothctl devices` and compares against the initial RPA — any entry with the same device name but a different address is the permanent Identity Address, leaked by BlueZ at step 2

**Why the patch doesn't fix this:**

The CVE-2025-36911 firmware fix adds a pairing mode check to the Fast Pair GATT Key-Based Pairing characteristic handler on the accessory. This tool never writes to that characteristic. The identity address leak occurs on the **attacker's Linux host** via BlueZ's own device cache — entirely outside the accessory's firmware.

**Key behavior notes:**
- Extraction can succeed even if the `bluetoothctl pair` step fails or times out
- The FP GATT service presence check at step 4 does not gate the attack
- No PIN confirmation window appears — `NoInputNoOutput` means no user interaction on either side for Just Works

---

### Stage 2 — L2CAP Flooding (EMP Burst-Reconnect Mode)

Once the permanent address is known, optionally execute a sustained L2CAP denial-of-service using a modified version of `l2flood`.

**Two modes are used across the tool:**

**`-R` flag — EMP mode (Stage 2 flood)**
Silent fire-and-forget burst-reconnect. All threads synchronize their connect → burst → forced close cycles so the target receives periodic full ACL teardowns rather than staggered L2CAP channel shuffling it can absorb. Uses `SO_LINGER {1,0}` for immediate RST teardown on every close. Produces no stdout output during normal operation — connect errors are suppressed to stderr and only printed periodically.

**Normal mode (Stage 3 hijack probe)**
Used without `-R` to probe whether the target is still responding. This mode was also improved — it now handles reconnects automatically and outputs `no response from <addr>: id N` when the target stops responding, which is what `wb.py` monitors to trigger the hijack.

**Result:** Target device becomes unresponsive to normal connection attempts while the flood is active. Device recovers fully when the attack stops — no permanent damage.

**Multithread behavior:**
- Threads synchronize after each burst cycle so pressure hits the target simultaneously
- Effective up to ~16 threads on typical hardware; diminishing returns beyond that
- Multiple HCI adapters can be used simultaneously for increased pressure

---

### Stage 3 — Hijack via SMP Just Works During Reset Window (Unpatched Auth Bypass)

**Root cause:** The sustained L2CAP flood causes the target device's Bluetooth stack to crash or reset. During the recovery window — before the Fast Pair GATT service has re-registered and before the Security Manager has fully re-initialized — the device accepts a standard SMP Just Works bond from `NoInputNoOutput` without requiring the Fast Pair GATT handshake that would normally gate the bond. The resulting bond is **persistent**: it survives BT adapter resets and shows `Paired: yes` / `Bonded: yes` in `bluetoothctl info`.

**Why this is a separate finding from CVE-2025-36911:**

The CVE-2025-36911 patch enforces a pairing mode check in the FP GATT Key-Based Pairing characteristic handler. Stage 3 never touches that characteristic. The bond is established at the SMP layer during a window where the FP GATT server hasn't re-initialized, so the Fast Pair security gate is never even reached. A fully patched device remains vulnerable to this because the patch has no visibility into the SMP layer during stack recovery.

**What the code actually does:**

1. Sends an L2CAP probe (`l2flood -c -1 -t 2`) to confirm the device is unresponsive — looks for `no response from <addr>: id N` in output
2. Once unresponsive state is confirmed, runs `bluetoothctl connect <permanent_addr>` in a retry loop
3. SMP negotiates `NoInputNoOutput` / `NoInputNoOutput` → Just Works association model → bond completes
4. `bluetoothctl connect` returns exit code 0 on success
5. Bond persists after attack stops

**Success probability by device state:**

| Device State | Expected Result |
|---|---|
| Actively in flood / unresponsive | Highest success — stack in degraded state during recovery |
| Recovering from flood | High success — temporary SM re-init window |
| Fully recovered | Lower success — normal security restored |
| Powered off | Fails |

---

## Relationship to CVE-2025-36911

| | CVE-2025-36911 (WhisperPair) | This Tool |
|---|---|---|
| **Protocol used** | Fast Pair GATT KBP (UUID 1236 write) | None — plain BLE connect only |
| **BDADDR leak path** | Encrypted KBP notification (BR/EDR addr) | BlueZ RPA resolution on LL_CONNECTION_COMPLETE |
| **Auth bypass path** | FP pairing mode check missing | SMP Just Works during BT stack recovery window |
| **Patched by 36911 fix?** | Yes | **No** |
| **Works on patched devices?** | No | **Yes** |
| **CWE** | CWE-287 | CWE-200 (Stage 1) + CWE-362/CWE-287 (Stage 3) |

---

## ⚠️ Legal Warning

**This is a denial-of-service and unauthorized access research tool.**

Using this tool on devices you do not own or without explicit written authorization is a **federal crime** punishable by imprisonment and fines under the Computer Fraud and Abuse Act (18 U.S.C. § 1030) and equivalent statutes in other jurisdictions.

You may **only** use this tool on:
- Devices you personally own
- Devices for which you have **explicit written authorization** from the owner to conduct security testing

---

## Requirements

- Linux (tested on Ubuntu 20.04+)
- Root privileges (required for `bluetoothctl` and raw BLE access)
- `bluetoothctl` / BlueZ installed and functional
- Python 3.7+
- For Stage 2/3: `l2flood` with OpenMP support — see [kovmir/l2flood](https://github.com/kovmir/l2flood)

---

## Installation

### System dependencies

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

### Clone and install

```bash
git clone https://github.com/Ymsniper/Whisper_Bully.git
cd Whisper_Bully
pip3 install -r requirements.txt
# Required for Stage 2/3 only:
make
sudo make install
```

---

## Usage

### Stage 1: BDADDR Extraction

```bash
# Auto-detect and extract all nearby Fast Pair devices
sudo python3 wb.py

# 20 second scan, save results
sudo python3 wb.py -s 20 -o targets.json

# 30 second scan, custom output file
sudo python3 wb.py -s 30 -o extracted.json
```

> **Note:** If a device was previously connected or paired by this tool or manually, BlueZ already knows its identity address. Remove it first so extraction runs cleanly:
> ```bash
> sudo bluetoothctl remove <address>
> ```

---

### Stage 2: L2CAP Flooding (Optional)

#### Method 1 — Interactive (prompted after extraction)
```bash
sudo python3 wb.py -s 20 -o targets.json
# At completion: "Run aggressive L2CAP test... (yes/no)" → yes
```

#### Method 2 — Flags (skip prompts)
```bash
# Stage 1 + Stage 2 only
sudo python3 wb.py -s 20 -o targets.json --aggressive

# Stage 1 + Stage 2 + Stage 3
sudo python3 wb.py -s 20 -o targets.json --aggressive --hijack

# With duration and thread count
sudo python3 wb.py -s 20 -o targets.json --aggressive --hijack -d 120 -t 8
```

#### Method 3 — Standalone flood script
```bash
# Flood from extracted targets file for 120 seconds
sudo python3 aggressive_test.py -f targets.json -d 120 -t 4

# Flood a single known address for 60 seconds
sudo python3 aggressive_test.py AA:BB:CC:DD:EE:FF -d 60

# Flood forever (Ctrl+C to stop)
sudo python3 aggressive_test.py AA:BB:CC:DD:EE:FF -f
```

---

### Stage 3: Hijack (Optional)

```bash
# Integrated — extract, flood, then hijack
sudo python3 wb.py -s 20 -o targets.json --aggressive --hijack -d 120

# Manual standalone hijack on known address
sudo python3 wb.py -H AA:BB:CC:DD:EE:FF
```

---

### Full Three-Stage Run (One Command)

```bash
sudo python3 wb.py -s 20 -o targets.json --aggressive --hijack -d 120 -t 4
```

**Execution flow:**
1. Scan 20 seconds for Fast Pair devices
2. Extract permanent BDADDR from each target
3. Flood all targets for 120 seconds using 4 threads
4. Monitor for unresponsive state
5. Attempt hijack on each target during recovery window
6. Save results to `targets.json`

---

### Multi-Adapter Attack

```bash
# Terminal 1
sudo python3 wb.py -s 20 -o targets.json --aggressive --hijack -i hci0 -d 120 -t 4 &

# Terminal 2
sudo python3 wb.py -s 20 -o targets.json --aggressive --hijack -i hci1 -d 120 -t 4
```

Doubles DoS pressure and increases hijack success probability during the recovery window.

---

## Command-Line Flags

| Flag | Description |
|---|---|
| `-s, --scan-time` | BLE scan duration in seconds (default: 10) |
| `-o, --output` | Save extracted addresses to JSON file |
| `--aggressive` | Skip prompts, run Stage 2 immediately (requires prior written authorization) |
| `-H, --hijack` | Attempt Stage 3 hijack after Stage 2 (requires `--aggressive` or interactive yes) |
| `-d, --duration` | Flood duration in seconds (default: 60) or `f` for forever |
| `-t, --threads` | Parallel L2CAP flood threads (default: CPU count) |
| `-i, --hci` | HCI adapter to use (e.g. `hci0`, `hci1`) |

---

## Technical Details

### Stage 1 — Why Extraction Works Without GATT Interaction

The Fast Pair FE2C service UUID is used **only as a scan filter** to identify candidate targets. Once a BLE connection is established:

- The Link Layer completes the connection handshake and fires `LL_CONNECTION_COMPLETE` to the host
- BlueZ processes this event and, if the device uses a Resolvable Private Address, resolves it against its IRK cache or simply registers the identity address from the connection parameters
- The identity address is cached in BlueZ's internal device table
- `bluetoothctl devices` then shows both the original RPA and the newly registered identity address — same device name, different address
- The tool compares against the original RPA and returns the new entry as the permanent BDADDR

The `bluetoothctl pair` call that runs concurrently may or may not succeed — the BDADDR is typically already in the table by the time the pair command completes or fails.

### Stage 2 — EMP Mode (`l2flood -R`)

This modified `l2flood` has two modes depending on the intended stage:

**`-R` flag — EMP mode (DoS only, no hijack)**
Used when running Stage 2 standalone without proceeding to Stage 3.
Silent fire-and-forget burst-reconnect — all threads synchronize their
connect → burst → forced close cycles to guarantee periodic full ACL
teardowns. Produces no stdout output during normal operation.

**Normal mode (DoS + hijack probe)**
Used when Stage 3 is intended. Normal mode was improved to handle
reconnects automatically and outputs `no response from <addr>: id N`
when the target stops responding — this is the signal `wb.py` monitors
to trigger the hijack attempt.

### Stage 3 — Why the Bond Persists

The resulting bond is not a transient connection — it is a full SMP bond stored by BlueZ:

- `bluetoothctl info <addr>` shows `Paired: yes`, `Bonded: yes`, `Trusted: no`
- Bond survives `bluetoothctl power off/on` cycles
- Bond survives attacker machine reboot (stored in `/var/lib/bluetooth/`)
- Device accepts subsequent connections from attacker adapter without re-pairing

---

## Known Limitations

### Stage 1
- Requires Linux with BlueZ / `bluetoothctl`
- Target must not already be in BlueZ device table under the RPA (remove first if needed)
- Address rolling during the connection window can cause timing issues — re-run if extraction fails

### Stage 2
- Requires knowing the permanent address (from Stage 1 or other means)
- Target must be powered on and within range
- Device recovers fully when flood stops — no persistent effect

### Stage 3
- Requires device to enter unresponsive state (Stage 2 dependency)
- Success is timing-dependent — hijack must land during the recovery window
- Does not work if device powers off during flood

---

## Troubleshooting

**No devices found**
- Verify `bluetoothctl` is working: `sudo bluetoothctl list`
- Increase scan time: `-s 30`

**BLE connection failed / extraction fails**
- Remove device from BlueZ first: `sudo bluetoothctl remove <addr>`
- Re-run — RPA rolling can cause timing issues

**Flood has no effect**
- Increase thread count: `-t 16`
- Use multiple adapters simultaneously
- Verify the permanent address (not the RPA) is being targeted

**Permission denied**
- Run with `sudo`
- Ensure user is in `bluetooth` group or run as root

**`bleak` import error**
- Debian/Ubuntu: `sudo apt install libdbus-1-dev libglib2.0-dev`
- Fedora: `sudo dnf install dbus-devel glib2-devel`
- Arch: `sudo pacman -S dbus glib`

**D-Bus errors**
- `sudo systemctl start dbus && sudo systemctl start bluetooth`

---

## Credits

- [@kovmir](https://github.com/kovmir) for [l2flood](https://github.com/kovmir/l2flood)
- [KU Leuven COSIC](https://github.com/KULeuven-COSIC/WhisperPair) for the original WhisperPair / CVE-2025-36911 research

---

## License

MIT. See LICENSE for details.

## Disclaimer

This tool is for authorized security testing and defensive research only. Unauthorized access to Bluetooth devices is illegal. Only use on devices you own or have explicit written permission to test. The author assumes no liability for unauthorized or illegal use.
