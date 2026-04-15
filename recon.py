#!/usr/bin/env python3
"""Portable Recon Toolkit - CLI entry point.

A self-contained reconnaissance toolkit designed to run from a USB drive.
Combines Nmap (when available), pure-Python DNS tools, WHOIS, subdomain
enumeration, a fallback TCP port scanner and a visual dashboard.

All modules rely on the Python standard library only, so the toolkit works
from a portable Python build without any pip installs.
"""
import argparse
import ipaddress
import sys
from concurrent.futures import ThreadPoolExecutor
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

# Hard ceiling so a stray /8 never accidentally melts the machine.
MAX_EXPANDED_TARGETS = 1024


def _expand_cidr(token):
    """Expand a single token into a list of host strings.

    Accepts plain hostnames, IPv4/IPv6 addresses, and CIDR ranges. Network
    addresses returned by ip_network().hosts() already exclude the network
    and broadcast addresses for IPv4/24-or-wider networks.
    """
    token = token.strip()
    if not token:
        return []
    # Try CIDR first. strict=False allows a host bit in the address.
    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
            return [str(h) for h in net.hosts()] or [str(net.network_address)]
        except ValueError:
            pass
    return [token]


def expand_targets(spec, targets_file=None):
    """Expand a `target` argument + optional -iL file into a flat host list.

    `spec` may be None, a single host, or a comma-separated list. Empty
    results raise ValueError so the caller can surface a clear error.
    """
    raw = []
    if targets_file:
        with open(targets_file, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    raw.append(line)
    if spec:
        for token in spec.split(","):
            raw.append(token)

    hosts = []
    for token in raw:
        hosts.extend(_expand_cidr(token))

    # Dedupe while preserving order.
    seen = set()
    unique = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            unique.append(h)

    if len(unique) > MAX_EXPANDED_TARGETS:
        log.warning(
            "Target list expanded to %d hosts; truncating to %d. Pass a "
            "smaller CIDR or split into multiple runs.",
            len(unique), MAX_EXPANDED_TARGETS,
        )
        unique = unique[:MAX_EXPANDED_TARGETS]

    if not unique:
        raise ValueError("No targets to scan (check --targets-file or target arg)")
    return unique


def _has_error(node):
    """Recursively detect any `error` key in a session dict."""
    if isinstance(node, dict):
        if "error" in node and node["error"]:
            return True
        return any(_has_error(v) for v in node.values())
    if isinstance(node, list):
        return any(_has_error(item) for item in node)
    return False


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


def _resolve_wordlist(arg):
    if not arg:
        return None
    wl = Path(arg)
    if not wl.is_file():
        wl = ROOT / arg
    return wl if wl.is_file() else None


def _scan_one(target, args):
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
    return session


def cmd_scan(args):
    targets = expand_targets(args.target, args.targets_file)
    log.info("Scanning %d target(s)", len(targets))
    any_error = False
    for target in targets:
        session = _scan_one(target, args)
        if _has_error(session):
            any_error = True
    return 2 if any_error else 0


def cmd_dns(args):
    targets = expand_targets(args.target, args.targets_file)
    any_error = False
    for target in targets:
        session = report.new_session(target, "dns")
        log.info("DNS reconnaissance on %s", target)
        session["dns"] = dns_tools.full_lookup(target, server=args.server)

        wl = _resolve_wordlist(args.wordlist)
        if wl:
            log.info("Subdomain brute-force with %s", wl)
            session["subdomains"] = subdomain.enumerate(
                target, str(wl), server=args.server
            )
        elif args.wordlist:
            log.warning("Wordlist not found: %s", args.wordlist)

        report.save_session(session)
        log.info("Saved %s", session["_path"])
        if _has_error(session):
            any_error = True
    return 2 if any_error else 0


def cmd_whois(args):
    targets = expand_targets(args.target, args.targets_file)
    any_error = False
    for target in targets:
        session = report.new_session(target, "whois")
        log.info("WHOIS lookup for %s", target)
        session["whois"] = whois_tool.lookup(target)
        report.save_session(session)
        log.info("Saved %s", session["_path"])
        if _has_error(session):
            any_error = True
    return 2 if any_error else 0


def _run_full_one(target, args):
    session = report.new_session(target, "full")
    wl_path = _resolve_wordlist(args.wordlist)
    # Pre-compute the wildcard answer set once - otherwise parallel workers
    # would each launch their own probes, and the subdomain brute force would
    # lose the ability to filter wildcard-echoes correctly.
    wildcard = None
    if wl_path:
        try:
            wildcard = dns_tools.detect_wildcard(target)
        except Exception as exc:
            wildcard = {"error": str(exc)}

    # DNS, WHOIS, and subdomain brute-force are all I/O bound and run
    # independently against the same target. Execute them concurrently so
    # wall-clock time drops to roughly max(individual_module_time).
    def _do_dns():
        log.info("[1/4] DNS reconnaissance on %s", target)
        try:
            return dns_tools.full_lookup(target)
        except Exception as exc:
            return {"error": str(exc)}

    def _do_whois():
        log.info("[2/4] WHOIS lookup")
        try:
            return whois_tool.lookup(target)
        except Exception as exc:
            return {"error": str(exc)}

    def _do_subdomain():
        if not wl_path:
            return None
        log.info("[3/4] Subdomain brute-force")
        try:
            return subdomain.enumerate(target, str(wl_path), wildcard=wildcard)
        except Exception as exc:
            return {"error": str(exc)}

    with ThreadPoolExecutor(max_workers=3) as executor:
        dns_f = executor.submit(_do_dns)
        whois_f = executor.submit(_do_whois)
        sub_f = executor.submit(_do_subdomain)
        session["dns"] = dns_f.result()
        session["whois"] = whois_f.result()
        sub_result = sub_f.result()
        if sub_result is not None:
            session["subdomains"] = sub_result
        elif args.wordlist:
            log.warning("[3/4] Wordlist not found: %s", args.wordlist)
        else:
            log.debug("[3/4] Subdomain brute-force skipped (no --wordlist)")

    # Nmap runs serially after the I/O-bound trio finishes; it is typically
    # the slowest step and wants full CPU / network headroom.
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
    return session


def cmd_full(args):
    targets = expand_targets(args.target, args.targets_file)
    log.info("Running full recon on %d target(s)", len(targets))
    any_error = False
    for target in targets:
        session = _run_full_one(target, args)
        if _has_error(session):
            any_error = True
    return 2 if any_error else 0


def cmd_dashboard(args):
    dashboard.serve(host=args.host, port=args.port, open_browser=not args.no_browser)
    return 0


def cmd_list(args):
    sessions = report.list_sessions()
    if not sessions:
        log.warning("No sessions found. Run a scan first.")
        return 0
    log.info("%d session(s):", len(sessions))
    for s in sessions:
        sys.stdout.write(
            f"  {s.get('created', '-'):<18} {s.get('scan_type', '-'):<8} {s.get('target', '-')}\n"
        )
    sys.stdout.flush()
    return 0


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
    p.add_argument("target", nargs="?", help="Target host, IP, CIDR, or comma-separated list")
    p.add_argument("-iL", "--targets-file", dest="targets_file",
                   help="File containing targets (one per line, # comments ok)")
    p.add_argument("--profile", default="default",
                   choices=["quick", "default", "full", "service", "stealth"],
                   help="Nmap scan profile (default: default)")
    p.add_argument("--ports", help="Ports e.g. 1-1024 or 22,80,443")
    p.add_argument("--no-nmap", action="store_true",
                   help="Force Python TCP connect fallback")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("dns", help="DNS reconnaissance (A/AAAA/NS/MX/TXT/SOA/CAA + reverse)")
    p.add_argument("target", nargs="?")
    p.add_argument("-iL", "--targets-file", dest="targets_file",
                   help="File containing targets (one per line)")
    p.add_argument("--server", help="DNS server (default: public resolvers)")
    p.add_argument("--wordlist", help="Subdomain wordlist to brute force")
    p.set_defaults(func=cmd_dns)

    p = sub.add_parser("whois", help="WHOIS lookup")
    p.add_argument("target", nargs="?")
    p.add_argument("-iL", "--targets-file", dest="targets_file",
                   help="File containing targets (one per line)")
    p.set_defaults(func=cmd_whois)

    p = sub.add_parser("full", help="Full recon: DNS + WHOIS + subdomain + port scan")
    p.add_argument("target", nargs="?")
    p.add_argument("-iL", "--targets-file", dest="targets_file",
                   help="File containing targets (one per line)")
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
        return 0
    try:
        rc = args.func(args)
    except ValueError as exc:
        log.error("%s", exc)
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] Interrupted\n")
        return 130
    return int(rc or 0)


if __name__ == "__main__":
    sys.exit(main())
