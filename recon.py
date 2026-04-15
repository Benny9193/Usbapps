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

from lib import (
    dashboard,
    dns_tools,
    logutil,
    nmap_runner,
    port_scan,
    report,
    subdomain,
    whois_tool,
)

log = logutil.get()


def _print_banner():
    sys.stdout.write(r"""
   ____                        _____           _ _    _ _
  |  _ \ ___  ___ ___  _ __   |_   _|__   ___ | | | _(_) |_
  | |_) / _ \/ __/ _ \| '_ \    | |/ _ \ / _ \| | |/ / | __|
  |  _ <  __/ (_| (_) | | | |   | | (_) | (_) | |   <| | |_
  |_| \_\___|\___\___/|_| |_|   |_|\___/ \___/|_|_|\_\_|\__|
            portable recon toolkit - usb edition
""")
    sys.stdout.flush()


def cmd_scan(args):
    target = args.target
    session = report.new_session(target, "scan")

    if not args.no_nmap and nmap_runner.is_available():
        log.info("Nmap (%s) -> %s", args.profile, target)
        session["nmap"] = nmap_runner.scan(
            target,
            profile=args.profile,
            ports=args.ports,
            session_id=session["_id"],
        )
    else:
        if not args.no_nmap:
            log.warning("Nmap not found, using Python TCP connect scanner")
        log.info("python-portscan -> %s", target)
        session["port_scan"] = port_scan.scan(target, ports=args.ports or "1-1024")

    report.save_session(session)
    log.info("Saved %s", session["_path"])


def cmd_dns(args):
    target = args.target
    session = report.new_session(target, "dns")
    log.info("DNS reconnaissance on %s", target)
    session["dns"] = dns_tools.full_lookup(target, server=args.server)

    if args.wordlist:
        wl = Path(args.wordlist)
        if not wl.is_file():
            wl = ROOT / args.wordlist
        if wl.is_file():
            log.info("Subdomain brute-force with %s", wl)
            session["subdomains"] = subdomain.enumerate(target, str(wl), server=args.server)
        else:
            log.warning("Wordlist not found: %s", args.wordlist)

    report.save_session(session)
    log.info("Saved %s", session["_path"])


def cmd_whois(args):
    target = args.target
    session = report.new_session(target, "whois")
    log.info("WHOIS lookup for %s", target)
    session["whois"] = whois_tool.lookup(target)
    report.save_session(session)
    log.info("Saved %s", session["_path"])


def cmd_full(args):
    target = args.target
    session = report.new_session(target, "full")

    log.info("[1/4] DNS reconnaissance on %s", target)
    try:
        session["dns"] = dns_tools.full_lookup(target)
    except Exception as exc:
        session["dns"] = {"error": str(exc)}

    log.info("[2/4] WHOIS lookup")
    try:
        session["whois"] = whois_tool.lookup(target)
    except Exception as exc:
        session["whois"] = {"error": str(exc)}

    if args.wordlist:
        wl = Path(args.wordlist)
        if not wl.is_file():
            wl = ROOT / args.wordlist
        if wl.is_file():
            log.info("[3/4] Subdomain brute-force")
            try:
                session["subdomains"] = subdomain.enumerate(target, str(wl))
            except Exception as exc:
                session["subdomains"] = {"error": str(exc)}
        else:
            log.warning("[3/4] Wordlist not found: %s", args.wordlist)
    else:
        log.debug("[3/4] Subdomain brute-force skipped (no --wordlist)")

    if not args.no_nmap and nmap_runner.is_available():
        log.info("[4/4] Nmap (%s) scan", args.profile)
        session["nmap"] = nmap_runner.scan(
            target, profile=args.profile, session_id=session["_id"]
        )
    else:
        log.info("[4/4] Python TCP connect scan")
        session["port_scan"] = port_scan.scan(target, ports="1-1024")

    report.save_session(session)
    log.info("Saved %s", session["_path"])


def cmd_dashboard(args):
    dashboard.serve(host=args.host, port=args.port, open_browser=not args.no_browser)


def cmd_list(args):
    sessions = report.list_sessions()
    if not sessions:
        log.warning("No sessions found. Run a scan first.")
        return
    log.info("%d session(s):", len(sessions))
    for s in sessions:
        sys.stdout.write(
            f"  {s.get('created', '-'):<18} {s.get('scan_type', '-'):<8} {s.get('target', '-')}\n"
        )
    sys.stdout.flush()


def build_parser():
    parser = argparse.ArgumentParser(
        prog="recon",
        description="Portable Recon Toolkit - Nmap + DNS + dashboard",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase log verbosity (-v for debug)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress info output (warnings and errors only)")
    parser.add_argument("--log-file", metavar="PATH",
                        help="Mirror log output to this file")
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
    parser = build_parser()
    args = parser.parse_args()
    logutil.setup(verbosity=args.verbose, quiet=args.quiet, log_file=args.log_file)
    if not args.quiet:
        _print_banner()
    if not getattr(args, "func", None):
        parser.print_help()
        return
    try:
        args.func(args)
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] Interrupted\n")
        sys.exit(130)


if __name__ == "__main__":
    main()
