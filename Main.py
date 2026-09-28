#!/usr/bin/env python3
"""
Not-Just-Nmap: entry point.

Runs the PortScanner (portscanner.py) with the fingerprinting engine
(fingerprint.py) using a thread pool, then prints the security report.

Only scan systems you own or have explicit permission to test.
"""

import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from Portscanner import PortScanner
except ImportError as e:
    sys.exit(f"[!] Could not import scanner modules: {e}\n"
             "    Make sure portscanner.py and fingerprint.py are in the same folder as main.py.")

BANNER = r"""
 _   _       _        _           _     _   _
| \ | | ___ | |_     | |_   _ ___| |_  | \ | |_ __ ___   __ _ _ __
|  \| |/ _ \| __|_   | | | | / __| __| |  \| | '_ ` _ \ / _` | '_ \
| |\  | (_) | |_| |__| | |_| \__ \ |_  | |\  | | | | | | (_| | |_) |
|_| \_|\dir Main.py___/ \__|\____/ \__,_|___/\__| |_| \_|_| |_| |_|\__,_| .__/
                                                              |_|
      Python port scanner with service & vulnerability fingerprinting
"""


def parse_ports(spec: str):
    """
    Parse a port spec into a sorted list of unique ports.
    Supports: '80', '1-1000', '22,80,443', '1-100,443,8000-8100'
    """
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    if not ports:
        raise ValueError("no ports given")
    if min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def build_parser():
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Not-Just-Nmap: TCP port scanner with banner grabbing, "
                    "CVE matching, risk scoring and OS guessing.",
        epilog="Example: python main.py 192.168.1.10 -p 1-1024,3306,8080 -w 200 --json out.json",
    )
    p.add_argument("host", help="IP address or hostname to scan")
    p.add_argument("-p", "--ports", default="1-1000",
                   help="Ports: '80', '1-1000', '22,80,443' or mixed (default: 1-1000)")
    p.add_argument("-t", "--timeout", type=float, default=2.0,
                   help="Socket timeout in seconds (default: 2.0)")
    p.add_argument("-w", "--workers", type=int, default=100,
                   help="Number of concurrent threads (default: 100)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Print each open/closed/filtered port as it is scanned")
    p.add_argument("--json", metavar="FILE",
                   help="Also save raw results to a JSON file")
    p.add_argument("--no-banner", action="store_true",
                   help="Do not print the ASCII banner")
    return p


def main():
    args = build_parser().parse_args()

    if not args.no_banner:
        print(BANNER)

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        sys.exit(f"[!] Invalid port specification: {e}")

    if args.workers < 1:
        sys.exit("[!] --workers must be at least 1")

    # Resolve once so a bad hostname fails fast instead of on every port
    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror as e:
        sys.exit(f"[!] Could not resolve '{args.host}': {e}")

    target = args.host if args.host == ip else f"{args.host} ({ip})"
    print(f"[*] Target:  {target}")
    print(f"[*] Ports:   {len(ports)} port(s)")
    print(f"[*] Timeout: {args.timeout}s | Threads: {args.workers}\n")

    scanner = PortScanner(timeout=args.timeout, verbose=args.verbose)
    started = time.time()
    done = 0
    interrupted = False

    executor = ThreadPoolExecutor(max_workers=min(args.workers, len(ports)))
    try:
        futures = [executor.submit(scanner.scan_port, ip, port) for port in ports]
        for _ in as_completed(futures):
            done += 1
            if not args.verbose and done % 100 == 0:
                print(f"[*] Progress: {done}/{len(ports)} ports", end="\r", flush=True)
    except KeyboardInterrupt:
        interrupted = True
        print("\n[!] Interrupted, cancelling remaining ports...")
        executor.shutdown(wait=False, cancel_futures=True)
    finally:
        executor.shutdown(wait=True)

    elapsed = time.time() - started
    scanner.results.sort(key=lambda r: r["port"])

    status = "interrupted" if interrupted else "completed"
    print(f"\n[*] Scan {status} in {elapsed:.1f}s ({len(scanner.results)} ports checked)")

    scanner.print_summary()

    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump({"target": args.host, "ip": ip, "scan_seconds": round(elapsed, 2),
                           "results": scanner.results}, f, indent=2)
            print(f"[*] Results saved to {args.json}")
        except OSError as e:
            print(f"[!] Could not write {args.json}: {e}")


if __name__ == "__main__":
    # Emoji in the report can crash legacy Windows consoles (cp1252)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    main()