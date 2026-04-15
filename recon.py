#!/usr/bin/env python3
"""Portable Recon Toolkit - CLI entry point.

A self-contained reconnaissance toolkit designed to run from a USB drive.
Combines Nmap (when available), pure-Python DNS tools, WHOIS, subdomain
enumeration, a fallback TCP port scanner and a visual dashboard.

All modules rely on the Python standard library only, so the toolkit works
from a portable Python build without any pip installs.
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from lib import dashboard, dns_tools, nmap_runner, port_scan, report, subdomain, whois_tool


def _print_banner():
    print(r"""
   ____                        _____           _ _    _ _
  |  _ \ ___  ___ ___  _ __   |_   _|__   ___ | | | _(_) |_
  | |_) / _ \/ __/ _ \| '_ \    | |/ _ \ / _ \| | |/ / | __|
  |  _ <  __/ (_| (_) | | | |   | | (_) | (_) | |   <| | |_
  |_| \_\___|\___\___/|_| |_|   |_|\___/ \___/|_|_|\_\_|\__|
            portable recon toolkit - usb edition
""")


def cmd_scan(args):
    target = args.target
    session = report.new_session(target, "scan")

    if not args.no_nmap and nmap_runner.is_available():
        print(f"[+] Nmap ({args.profile}) -> {target}")
        session["nmap"] = nmap_runner.scan(target, profile=args.profile, ports=args.ports)
    else:
        if not args.no_nmap:
            print("[!] Nmap not found, using Python TCP connect scanner")
        print(f"[+] python-portscan -> {target}")
        session["port_scan"] = port_scan.scan(target, ports=args.ports or "1-1024")

    report.save_session(session)
    print(f"[+] Saved {session['_path']}")


def cmd_dns(args):
    target = args.target
    session = report.new_session(target, "dns")
    print(f"[+] DNS reconnaissance on {target}")
    session["dns"] = dns_tools.full_lookup(target, server=args.server)

    if args.wordlist:
        wl = Path(args.wordlist)
        if not wl.is_file():
            wl = ROOT / args.wordlist
        if wl.is_file():
            print(f"[+] Subdomain brute-force with {wl}")
            session["subdomains"] = subdomain.enumerate(target, str(wl), server=args.server)
        else:
            print(f"[!] Wordlist not found: {args.wordlist}")

    report.save_session(session)
    print(f"[+] Saved {session['_path']}")


def cmd_whois(args):
    target = args.target
    session = report.new_session(target, "whois")
    print(f"[+] WHOIS lookup for {target}")
    session["whois"] = whois_tool.lookup(target)
    report.save_session(session)
    print(f"[+] Saved {session['_path']}")


def cmd_full(args):
    target = args.target
    session = report.new_session(target, "full")

    print(f"[+] [1/4] DNS reconnaissance on {target}")
    try:
        session["dns"] = dns_tools.full_lookup(target)
    except Exception as exc:
        session["dns"] = {"error": str(exc)}

    print(f"[+] [2/4] WHOIS lookup")
    try:
        session["whois"] = whois_tool.lookup(target)
    except Exception as exc:
        session["whois"] = {"error": str(exc)}

    if args.wordlist:
        wl = Path(args.wordlist)
        if not wl.is_file():
            wl = ROOT / args.wordlist
        if wl.is_file():
            print(f"[+] [3/4] Subdomain brute-force")
            try:
                session["subdomains"] = subdomain.enumerate(target, str(wl))
            except Exception as exc:
                session["subdomains"] = {"error": str(exc)}
        else:
            print(f"[!] [3/4] Wordlist not found: {args.wordlist}")
    else:
        print("[-] [3/4] Subdomain brute-force skipped (no --wordlist)")

    if not args.no_nmap and nmap_runner.is_available():
        print(f"[+] [4/4] Nmap ({args.profile}) scan")
        session["nmap"] = nmap_runner.scan(target, profile=args.profile)
    else:
        print("[+] [4/4] Python TCP connect scan")
        session["port_scan"] = port_scan.scan(target, ports="1-1024")

    report.save_session(session)
    print(f"[+] Saved {session['_path']}")


def cmd_dashboard(args):
    dashboard.serve(host=args.host, port=args.port, open_browser=not args.no_browser)


def cmd_list(args):
    sessions = report.list_sessions()
    if not sessions:
        print("[-] No sessions found. Run a scan first.")
        return
    print(f"[+] {len(sessions)} session(s):")
    for s in sessions:
        print(f"  {s.get('created', '-'):<18} {s.get('scan_type', '-'):<8} {s.get('target', '-')}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="recon",
        description="Portable Recon Toolkit - Nmap + DNS + dashboard",
    )
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("scan", help="Port scan with Nmap (or Python fallback)")
    p.add_argument("target")
    p.add_argument("--profile", default="default",
                   choices=["quick", "default", "full", "service", "stealth"],
                   help="Nmap scan profile (default: default)")
    p.add_argument("--ports", help="Ports e.g. 1-1024 or 22,80,443")
    p.add_argument("--no-nmap", action="store_true",
                   help="Force Python TCP connect fallback")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("dns", help="DNS reconnaissance (A/AAAA/NS/MX/TXT/SOA/CAA + reverse)")
    p.add_argument("target")
    p.add_argument("--server", help="DNS server (default: public resolvers)")
    p.add_argument("--wordlist", help="Subdomain wordlist to brute force")
    p.set_defaults(func=cmd_dns)

    p = sub.add_parser("whois", help="WHOIS lookup")
    p.add_argument("target")
    p.set_defaults(func=cmd_whois)

    p = sub.add_parser("full", help="Full recon: DNS + WHOIS + subdomain + port scan")
    p.add_argument("target")
    p.add_argument("--profile", default="default")
    p.add_argument("--wordlist", help="Subdomain wordlist")
    p.add_argument("--no-nmap", action="store_true")
    p.set_defaults(func=cmd_full)

    p = sub.add_parser("dashboard", help="Launch the visual dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--no-browser", action="store_true")
    p.set_defaults(func=cmd_dashboard)

    p = sub.add_parser("list", help="List previous scan sessions")
    p.set_defaults(func=cmd_list)

    return parser


def main():
    _print_banner()
    parser = build_parser()
    args = parser.parse_args()
    if not getattr(args, "func", None):
        parser.print_help()
        return
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
