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
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from lib import (
    crypto,
    dashboard,
    differ,
    dns_tools,
    exporters,
    logutil,
    nmap_runner,
    port_scan,
    report,
    scheduler,
    subdomain,
    whois_tool,
)

log = logutil.get()

# Hard ceiling so a stray /8 never accidentally melts the machine.
MAX_EXPANDED_TARGETS = 1024

CONFIG_PATH = ROOT / "config" / "recon.toml"


def _load_config():
    """Load optional config/recon.toml. Returns a flat dict or {}.

    Missing file -> empty dict (no warning). Python <3.11 without tomllib ->
    single warning and empty dict. Malformed TOML -> warning and empty dict.
    """
    if not CONFIG_PATH.is_file():
        return {}
    try:
        import tomllib  # type: ignore
    except ModuleNotFoundError:
        log.warning("tomllib unavailable (<3.11); %s ignored", CONFIG_PATH)
        return {}
    try:
        with open(CONFIG_PATH, "rb") as fh:
            raw = tomllib.load(fh)
    except Exception as exc:
        log.warning("Could not parse %s: %s", CONFIG_PATH, exc)
        return {}
    # Flatten [section] tables into a single dict. argparse dests are flat
    # and we don't want to enforce section-per-subcommand mapping.
    flat = {}
    for section, values in raw.items():
        if isinstance(values, dict):
            for k, v in values.items():
                flat.setdefault(k, v)
        else:
            flat.setdefault(section, values)
    return flat


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


def _resolve_save_password(args):
    """Decide whether sessions saved by this command should be encrypted.

    Returns the password string (enabling auto-encrypt on save), or
    ``None`` for plaintext output. Reads two signals:

    * ``RECON_PASSWORD`` environment variable — the actual key
      material; presence alone enables auto-encrypt for any save.
    * ``encrypt_results = true`` in ``recon.toml`` — an enforcement
      aid; when set, a missing ``RECON_PASSWORD`` raises so the
      toolkit refuses to silently leave plaintext on disk.
    """
    pw = os.environ.get("RECON_PASSWORD")
    enforce = bool(getattr(args, "encrypt_results", False))
    if enforce and not pw:
        raise ValueError(
            "encrypt_results is enabled in recon.toml but RECON_PASSWORD is not set"
        )
    return pw or None


def _resolve_wordlist(arg):
    if not arg:
        return None
    wl = Path(arg)
    if not wl.is_file():
        wl = ROOT / arg
    return wl if wl.is_file() else None


def _scan_one(target, args, encrypt_password=None):
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
    report.save_session(session, encrypt_password=encrypt_password)
    saved = session["_path"] + crypto.EXTENSION if encrypt_password else session["_path"]
    log.info("Saved %s", saved)
    return session


def cmd_scan(args):
    targets = expand_targets(args.target, args.targets_file)
    try:
        encrypt_password = _resolve_save_password(args)
    except ValueError as exc:
        log.error("%s", exc)
        return 2
    log.info("Scanning %d target(s)%s", len(targets),
             " (auto-encrypt)" if encrypt_password else "")
    any_error = False
    for target in targets:
        session = _scan_one(target, args, encrypt_password=encrypt_password)
        if _has_error(session):
            any_error = True
    return 2 if any_error else 0


def cmd_dns(args):
    targets = expand_targets(args.target, args.targets_file)
    try:
        encrypt_password = _resolve_save_password(args)
    except ValueError as exc:
        log.error("%s", exc)
        return 2
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

        report.save_session(session, encrypt_password=encrypt_password)
        saved = session["_path"] + crypto.EXTENSION if encrypt_password else session["_path"]
        log.info("Saved %s", saved)
        if _has_error(session):
            any_error = True
    return 2 if any_error else 0


def cmd_whois(args):
    targets = expand_targets(args.target, args.targets_file)
    try:
        encrypt_password = _resolve_save_password(args)
    except ValueError as exc:
        log.error("%s", exc)
        return 2
    any_error = False
    for target in targets:
        session = report.new_session(target, "whois")
        log.info("WHOIS lookup for %s", target)
        session["whois"] = whois_tool.lookup(target)
        report.save_session(session, encrypt_password=encrypt_password)
        saved = session["_path"] + crypto.EXTENSION if encrypt_password else session["_path"]
        log.info("Saved %s", saved)
        if _has_error(session):
            any_error = True
    return 2 if any_error else 0


def _run_full_one(target, args, encrypt_password=None):
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

    report.save_session(session, encrypt_password=encrypt_password)
    saved = session["_path"] + crypto.EXTENSION if encrypt_password else session["_path"]
    log.info("Saved %s", saved)
    return session


def cmd_full(args):
    targets = expand_targets(args.target, args.targets_file)
    try:
        encrypt_password = _resolve_save_password(args)
    except ValueError as exc:
        log.error("%s", exc)
        return 2
    log.info("Running full recon on %d target(s)%s", len(targets),
             " (auto-encrypt)" if encrypt_password else "")
    any_error = False
    for target in targets:
        session = _run_full_one(target, args, encrypt_password=encrypt_password)
        if _has_error(session):
            any_error = True
    return 2 if any_error else 0


def cmd_diff(args):
    try:
        result = differ.diff(args.session_a, args.session_b)
    except FileNotFoundError as exc:
        log.error("%s", exc)
        return 2
    except ValueError as exc:
        log.error("%s", exc)
        return 2

    # Persist the diff as a new session-shaped document so the dashboard
    # surfaces it next to the originals.
    session = report.new_session(result["target"], "diff")
    session["diff"] = result
    report.save_session(session)

    log.info("Diff %s vs %s", result["a"]["id"], result["b"]["id"])
    log.info(
        "  ports: +%d -%d (unchanged %d)",
        len(result["ports"]["added"]),
        len(result["ports"]["removed"]),
        result["ports"]["unchanged"],
    )
    log.info(
        "  subdomains: +%d -%d",
        len(result["subdomains"]["added"]),
        len(result["subdomains"]["removed"]),
    )
    if result.get("dns"):
        log.info("  DNS changed: %s", ", ".join(result["dns"].keys()))
    log.info("Saved %s", session["_path"])
    return 0


def cmd_export(args):
    fmt = args.format.lower()
    if fmt not in exporters.EXPORTERS:
        log.error("Unknown format: %s (choose from %s)", fmt, ", ".join(exporters.EXPORTERS))
        return 2
    try:
        content = exporters.EXPORTERS[fmt](args.session)
    except FileNotFoundError as exc:
        log.error("%s", exc)
        return 2
    if args.output:
        Path(args.output).write_text(content, encoding="utf-8")
        log.info("Wrote %s", args.output)
    else:
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")
        sys.stdout.flush()
    return 0


def cmd_delete(args):
    removed_total = 0
    for sid in args.session_ids:
        removed = report.delete_session(sid)
        if not removed:
            log.warning("No session matched: %s", sid)
        else:
            removed_total += len(removed)
            for p in removed:
                log.info("Removed %s", p)
    return 0 if removed_total else 2


def cmd_purge(args):
    import time as _time
    cutoff = int(_time.time()) - int(args.older_than_days) * 86400
    if args.dry_run:
        victims = [s for s in report.list_sessions() if s.get("created_epoch", 0) < cutoff]
        log.info("Would delete %d session(s)", len(victims))
        for v in victims:
            log.info("  %s (%s)", v["id"], v["created"])
        return 0
    count, ids = report.purge(cutoff)
    log.info("Purged %d session(s)", count)
    for sid in ids:
        log.info("  %s", sid)
    return 0


def _read_password(args, *, confirm, attr="password_file", env_var="RECON_PASSWORD",
                   prompt="Password: "):
    """Resolve a password from a file, an env var, or an interactive prompt.

    ``attr`` is the args attribute holding an optional file path,
    ``env_var`` is the environment variable to consult next, and
    ``prompt`` is the label shown to the interactive user. ``confirm``
    re-prompts so a typo when encrypting cannot leave a file the user
    can never decrypt.
    """
    import getpass
    import os as _os

    pf = getattr(args, attr, None)
    if pf:
        try:
            data = Path(pf).read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"Could not read password file {pf}: {exc}")
        # Allow a trailing newline from `echo "pw" > file` without
        # silently swallowing intentional whitespace inside the password.
        if data.endswith("\r\n"):
            data = data[:-2]
        elif data.endswith("\n") or data.endswith("\r"):
            data = data[:-1]
        if not data:
            raise ValueError(f"Password file {pf} is empty")
        return data

    if env_var:
        env = _os.environ.get(env_var)
        if env:
            return env

    if not sys.stdin.isatty():
        raise ValueError(
            "No password supplied. Use --password-file, "
            f"{env_var or 'an env var'}, or run interactively."
        )
    pw = getpass.getpass(prompt)
    if not pw:
        raise ValueError("Password must not be empty")
    if confirm:
        again = getpass.getpass("Confirm:  ")
        if again != pw:
            raise ValueError("Passwords did not match")
    return pw


def _resolve_session_paths(token):
    """Map a CLI token to one or more files on disk.

    Accepts: an existing file path, a session id (resolved relative to
    ``results/`` and including sibling artifacts like ``*.nmap.xml``),
    or an existing session id with ``.enc`` already appended.
    """
    p = Path(token)
    if p.is_file():
        return [p]

    candidates = []
    sid = token
    if sid.endswith(".json") or sid.endswith(".json.enc"):
        sid = sid.rsplit(".json", 1)[0]
    base = report.RESULTS / sid
    if base.with_suffix(".json").is_file():
        candidates.append(base.with_suffix(".json"))
    # Sibling artifacts (e.g. nmap XML); skip the .json we already added.
    for sibling in report.RESULTS.glob(f"{sid}.*"):
        if sibling.is_file() and sibling not in candidates and sibling.suffix != ".enc":
            candidates.append(sibling)
    # Already-encrypted siblings, when the user asked us to decrypt.
    for sibling in report.RESULTS.glob(f"{sid}*.enc"):
        if sibling.is_file() and sibling not in candidates:
            candidates.append(sibling)
    return candidates


def _collect_bulk_session_ids(args, want_encrypted):
    """Return the list of session ids selected by --all / --older-than-days.

    ``want_encrypted=True`` means decrypt mode: filter to entries whose
    ``encrypted`` flag is set. ``False`` means encrypt mode: pick the
    plaintext entries. The caller still expands each id to concrete
    paths via :func:`_resolve_session_paths`.
    """
    import time as _time

    sessions = report.list_sessions()
    cutoff = None
    if getattr(args, "older_than_days", None) is not None:
        days = int(args.older_than_days)
        if days < 0:
            raise ValueError("--older-than-days must be non-negative")
        cutoff = int(_time.time()) - days * 86400
    selected = []
    for entry in sessions:
        if cutoff is not None and entry.get("created_epoch", 0) >= cutoff:
            continue
        if bool(entry.get("encrypted")) != bool(want_encrypted):
            continue
        sid = entry.get("id")
        if sid:
            selected.append(sid)
    return selected


def cmd_encrypt(args):
    try:
        password = _read_password(args, confirm=True)
    except ValueError as exc:
        log.error("%s", exc)
        return 2

    bulk = bool(args.all) or args.older_than_days is not None
    if bulk and args.targets:
        log.error("--all / --older-than-days cannot be combined with explicit targets")
        return 2
    if not bulk and not args.targets:
        log.error("encrypt: specify a target id, --all, or --older-than-days N")
        return 2

    if bulk:
        try:
            ids = _collect_bulk_session_ids(args, want_encrypted=False)
        except ValueError as exc:
            log.error("%s", exc)
            return 2
        if not ids:
            log.warning("No plaintext sessions matched the selection")
            return 0
        token_iter = ids
    else:
        token_iter = args.targets

    targets = []
    for token in token_iter:
        resolved = _resolve_session_paths(token)
        if not resolved:
            log.error("No file or session matched: %s", token)
            return 2
        targets.extend(resolved)

    out_dir = Path(args.output_dir) if args.output_dir else None
    encrypted = 0
    for src in targets:
        if crypto.is_encrypted(src):
            log.warning("Skipping already-encrypted file: %s", src)
            continue
        if out_dir:
            dst = out_dir / (src.name + crypto.EXTENSION)
        else:
            dst = src.with_name(src.name + crypto.EXTENSION)
        try:
            crypto.encrypt_file(src, dst, password)
        except (OSError, ValueError) as exc:
            log.error("Encrypt failed for %s: %s", src, exc)
            return 2
        log.info("Encrypted %s -> %s", src, dst)
        encrypted += 1
        if not args.keep:
            try:
                src.unlink()
                log.debug("Removed plaintext %s", src)
            except OSError as exc:
                log.warning("Could not remove plaintext %s: %s", src, exc)

    if not encrypted:
        log.warning("Nothing to encrypt")
        return 2
    log.info("Encrypted %d file(s)", encrypted)
    return 0


def cmd_decrypt(args):
    try:
        password = _read_password(args, confirm=False)
    except ValueError as exc:
        log.error("%s", exc)
        return 2

    bulk = bool(args.all) or args.older_than_days is not None
    if bulk and args.targets:
        log.error("--all / --older-than-days cannot be combined with explicit targets")
        return 2
    if not bulk and not args.targets:
        log.error("decrypt: specify a target id, --all, or --older-than-days N")
        return 2

    if bulk:
        try:
            ids = _collect_bulk_session_ids(args, want_encrypted=True)
        except ValueError as exc:
            log.error("%s", exc)
            return 2
        if not ids:
            log.warning("No encrypted sessions matched the selection")
            return 0
        token_iter = ids
    else:
        token_iter = args.targets

    targets = []
    for token in token_iter:
        resolved = _resolve_session_paths(token)
        if not resolved:
            log.error("No file or session matched: %s", token)
            return 2
        # If the user pointed at a session id, only operate on the encrypted
        # members - we don't want to "decrypt" a plaintext sibling and
        # silently overwrite it.
        targets.extend([p for p in resolved if crypto.is_encrypted(p)] or resolved)

    out_dir = Path(args.output_dir) if args.output_dir else None
    decrypted = 0
    for src in targets:
        if not crypto.is_encrypted(src):
            log.warning("Skipping non-encrypted file: %s", src)
            continue
        if out_dir:
            name = src.name[:-len(crypto.EXTENSION)] if src.name.endswith(crypto.EXTENSION) else src.name
            dst = out_dir / name
        elif src.name.endswith(crypto.EXTENSION):
            dst = src.with_name(src.name[:-len(crypto.EXTENSION)])
        else:
            dst = src.with_name(src.name + ".dec")
        try:
            crypto.decrypt_file(src, dst, password)
        except crypto.InvalidCiphertext as exc:
            log.error("Decrypt failed for %s: %s", src, exc)
            return 2
        except (OSError, ValueError) as exc:
            log.error("Decrypt failed for %s: %s", src, exc)
            return 2
        log.info("Decrypted %s -> %s", src, dst)
        decrypted += 1
        if not args.keep:
            try:
                src.unlink()
                log.debug("Removed ciphertext %s", src)
            except OSError as exc:
                log.warning("Could not remove ciphertext %s: %s", src, exc)

    if not decrypted:
        log.warning("Nothing to decrypt")
        return 2
    log.info("Decrypted %d file(s)", decrypted)
    return 0


def cmd_rekey(args):
    """Re-encrypt files with a new password without writing plaintext to disk."""
    try:
        old_password = _read_password(
            args, confirm=False,
            attr="old_password_file", env_var="RECON_OLD_PASSWORD",
            prompt="Old password: ",
        )
    except ValueError as exc:
        log.error("%s", exc)
        return 2
    try:
        new_password = _read_password(
            args, confirm=True,
            attr="new_password_file", env_var="RECON_NEW_PASSWORD",
            prompt="New password: ",
        )
    except ValueError as exc:
        log.error("%s", exc)
        return 2
    if old_password == new_password:
        log.error("Old and new passwords are identical")
        return 2

    bulk = bool(args.all) or args.older_than_days is not None
    if bulk and args.targets:
        log.error("--all / --older-than-days cannot be combined with explicit targets")
        return 2
    if not bulk and not args.targets:
        log.error("rekey: specify a target id, --all, or --older-than-days N")
        return 2

    if bulk:
        try:
            ids = _collect_bulk_session_ids(args, want_encrypted=True)
        except ValueError as exc:
            log.error("%s", exc)
            return 2
        if not ids:
            log.warning("No encrypted sessions matched the selection")
            return 0
        token_iter = ids
    else:
        token_iter = args.targets

    targets = []
    for token in token_iter:
        resolved = _resolve_session_paths(token)
        if not resolved:
            log.error("No file or session matched: %s", token)
            return 2
        targets.extend([p for p in resolved if crypto.is_encrypted(p)])

    if not targets:
        log.warning("Nothing to rekey")
        return 2

    rekeyed = 0
    for src in targets:
        try:
            blob = src.read_bytes()
            plaintext = crypto.decrypt(blob, old_password)
            new_blob = crypto.encrypt(plaintext, new_password)
        except crypto.InvalidCiphertext as exc:
            log.error("Rekey failed for %s: %s", src, exc)
            return 2
        except OSError as exc:
            log.error("Rekey failed for %s: %s", src, exc)
            return 2
        # Atomic replace via a sibling .part file. We only flip the
        # bytes once verification of the old password has succeeded,
        # so a wrong old password leaves the source untouched.
        tmp = src.with_name(src.name + ".part")
        try:
            tmp.write_bytes(new_blob)
            os.replace(tmp, src)
        except OSError as exc:
            log.error("Rekey failed for %s: %s", src, exc)
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass
            return 2
        finally:
            # Best-effort scrub of plaintext bytes in our locals.
            del plaintext
            del new_blob
        log.info("Rekeyed %s", src)
        rekeyed += 1

    log.info("Rekeyed %d file(s)", rekeyed)
    return 0


def cmd_dashboard(args):
    dashboard.serve(
        host=args.host,
        port=args.port,
        open_browser=not args.no_browser,
        token=args.token,
        require_auth=args.auth,
        run_scheduler=getattr(args, "scheduler", False),
    )
    return 0


def _fmt_schedule_row(s):
    last_run = s.get("last_run_epoch") or 0
    last_str = (
        __import__("time").strftime("%Y-%m-%d %H:%M:%S",
                                    __import__("time").localtime(last_run))
        if last_run else "-"
    )
    enabled = "on" if s.get("enabled", True) else "off"
    status = s.get("last_status") or "-"
    target = s.get("target") or "?"
    workflow = s.get("workflow") or "?"
    interval = s.get("interval") or f"{s.get('interval_seconds', '?')}s"
    sid = s.get("id") or "-"
    return f"  {sid:<32} {enabled:<4} {workflow:<5} {interval:<6} {last_str:<20} {status:<10} {target}"


def cmd_schedule(args):
    action = getattr(args, "schedule_action", None)
    if action is None:
        log.error("schedule: missing action (add/list/remove/enable/disable/run/daemon)")
        return 2

    if action == "add":
        opts = {}
        for key in ("profile", "wordlist", "ports", "server"):
            val = getattr(args, key, None)
            if val is not None:
                opts[key] = val
        if getattr(args, "no_nmap", False):
            opts["no_nmap"] = True
        try:
            entry = scheduler.add_schedule(
                args.target, args.workflow, args.every,
                options=opts, enabled=not args.disabled,
            )
        except ValueError as exc:
            log.error("%s", exc)
            return 2
        log.info(
            "Added schedule %s (%s %s every %s)",
            entry["id"], entry["workflow"], entry["target"], entry["interval"],
        )
        return 0

    if action == "list":
        schedules = scheduler.load_schedules()
        if not schedules:
            log.warning("No schedules defined. Add one with: recon schedule add ...")
            return 0
        log.info("%d schedule(s):", len(schedules))
        sys.stdout.write(
            f"  {'ID':<32} {'ST':<4} {'WF':<5} {'EVRY':<6} {'LAST RUN':<20} {'STATUS':<10} TARGET\n"
        )
        for s in schedules:
            sys.stdout.write(_fmt_schedule_row(s) + "\n")
        sys.stdout.flush()
        return 0

    if action == "remove":
        if scheduler.remove_schedule(args.id):
            log.info("Removed schedule %s", args.id)
            return 0
        log.warning("No schedule with id: %s", args.id)
        return 2

    if action == "enable":
        if scheduler.set_enabled(args.id, True):
            log.info("Enabled schedule %s", args.id)
            return 0
        log.warning("No schedule with id: %s", args.id)
        return 2

    if action == "disable":
        if scheduler.set_enabled(args.id, False):
            log.info("Disabled schedule %s", args.id)
            return 0
        log.warning("No schedule with id: %s", args.id)
        return 2

    if action == "run":
        schedules = scheduler.load_schedules()
        if args.id:
            schedules = [s for s in schedules if s.get("id") == args.id]
            if not schedules:
                log.error("No schedule with id: %s", args.id)
                return 2
        if not schedules:
            log.warning("No schedules to run")
            return 0
        any_error = False
        for entry in schedules:
            session = scheduler.run_once(entry)
            if session is None or _has_error(session):
                any_error = True
        return 2 if any_error else 0

    if action == "daemon":
        import time as _time
        sched_obj = scheduler.start_default()
        log.info("Scheduler daemon running. Press Ctrl+C to stop.")
        try:
            while sched_obj.is_running():
                _time.sleep(1.0)
        except KeyboardInterrupt:
            sys.stderr.write("\n[+] Scheduler stopped\n")
        finally:
            scheduler.stop_default(timeout=2.0)
        return 0

    log.error("Unknown schedule action: %s", action)
    return 2


def cmd_list(args):
    sessions = report.list_sessions()
    if not sessions:
        log.warning("No sessions found. Run a scan first.")
        return 0
    log.info("%d session(s):", len(sessions))
    for s in sessions:
        marker = "[enc]" if s.get("encrypted") else "     "
        sys.stdout.write(
            f"  {s.get('created', '-'):<18} {marker} {s.get('scan_type', '-'):<8} {s.get('target', '-')}\n"
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
    p.add_argument("--token", help="Require this bearer token / cookie for access")
    p.add_argument("--auth", action="store_true",
                   help="Generate a random token and print it (implies auth)")
    p.add_argument("--scheduler", action="store_true",
                   help="Start the recurring-scan scheduler alongside the dashboard")
    p.set_defaults(func=cmd_dashboard)

    p = sub.add_parser("schedule",
                       help="Manage recurring scans (add/list/remove/enable/disable/run/daemon)")
    sch_sub = p.add_subparsers(dest="schedule_action")

    p_add = sch_sub.add_parser("add", help="Add a new schedule")
    p_add.add_argument("target", help="Target host, IP, CIDR, or comma-separated list")
    p_add.add_argument("workflow", choices=list(scheduler.VALID_WORKFLOWS),
                       help="Which recon workflow to run on each fire")
    p_add.add_argument("--every", required=True,
                       help="Interval like 30s, 5m, 1h, 1d")
    p_add.add_argument("--profile", help="Nmap profile (scan/full)")
    p_add.add_argument("--wordlist", help="Subdomain wordlist (dns/full)")
    p_add.add_argument("--ports", help="Port spec (scan)")
    p_add.add_argument("--server", help="DNS server (dns)")
    p_add.add_argument("--no-nmap", action="store_true",
                       help="Force Python TCP fallback (scan/full)")
    p_add.add_argument("--disabled", action="store_true",
                       help="Create the schedule in the disabled state")

    sch_sub.add_parser("list", help="List all schedules")

    p_rm = sch_sub.add_parser("remove", help="Delete a schedule by id")
    p_rm.add_argument("id")

    p_en = sch_sub.add_parser("enable", help="Enable a schedule by id")
    p_en.add_argument("id")

    p_dis = sch_sub.add_parser("disable", help="Disable a schedule by id")
    p_dis.add_argument("id")

    p_run = sch_sub.add_parser("run",
                               help="Run schedules once now (all, or by id)")
    p_run.add_argument("id", nargs="?",
                       help="Specific schedule id (default: all enabled)")

    sch_sub.add_parser("daemon",
                       help="Run the scheduler in the foreground until Ctrl-C")

    p.set_defaults(func=cmd_schedule)

    p = sub.add_parser("list", help="List previous scan sessions")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("diff", help="Compare two sessions for the same target")
    p.add_argument("session_a", help="Earlier session id or path")
    p.add_argument("session_b", help="Later session id or path")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("export", help="Render a session to Markdown / HTML / CSV")
    p.add_argument("session", help="Session id or path")
    p.add_argument("--format", "-f", default="md", choices=["md", "html", "csv"],
                   help="Output format (default: md)")
    p.add_argument("--output", "-o", help="Write to this file instead of stdout")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("delete", help="Delete one or more sessions")
    p.add_argument("session_ids", nargs="+")
    p.set_defaults(func=cmd_delete)

    p = sub.add_parser("purge", help="Delete sessions older than N days")
    p.add_argument("--older-than-days", type=int, required=True,
                   help="Delete sessions whose created_epoch is older than this many days")
    p.add_argument("--dry-run", action="store_true",
                   help="Show which sessions would be deleted without removing them")
    p.set_defaults(func=cmd_purge)

    p = sub.add_parser(
        "encrypt",
        help="Encrypt session files (or arbitrary files) at rest with a password",
    )
    p.add_argument("targets", nargs="*",
                   help="Session ids or paths to encrypt (sibling artifacts included)")
    p.add_argument("--all", action="store_true",
                   help="Encrypt every plaintext session under results/")
    p.add_argument("--older-than-days", dest="older_than_days", type=int,
                   help="Only encrypt plaintext sessions older than this many days")
    p.add_argument("--password-file", dest="password_file",
                   help="Read the password from this file instead of prompting")
    p.add_argument("--output-dir", "-o",
                   help="Write encrypted files to this directory (default: alongside source)")
    p.add_argument("--keep", action="store_true",
                   help="Keep the original plaintext file (default: remove on success)")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser(
        "decrypt",
        help="Decrypt files produced by `recon encrypt`",
    )
    p.add_argument("targets", nargs="*",
                   help="Session ids or .enc paths to decrypt")
    p.add_argument("--all", action="store_true",
                   help="Decrypt every encrypted session under results/")
    p.add_argument("--older-than-days", dest="older_than_days", type=int,
                   help="Only decrypt encrypted sessions older than this many days")
    p.add_argument("--password-file", dest="password_file",
                   help="Read the password from this file instead of prompting")
    p.add_argument("--output-dir", "-o",
                   help="Write decrypted files to this directory (default: alongside source)")
    p.add_argument("--keep", action="store_true",
                   help="Keep the encrypted file (default: remove on success)")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser(
        "rekey",
        help="Re-encrypt sessions with a new password (plaintext never touches disk)",
    )
    p.add_argument("targets", nargs="*",
                   help="Session ids or .enc paths to rekey")
    p.add_argument("--all", action="store_true",
                   help="Rekey every encrypted session under results/")
    p.add_argument("--older-than-days", dest="older_than_days", type=int,
                   help="Only rekey encrypted sessions older than this many days")
    p.add_argument("--old-password-file", dest="old_password_file",
                   help="Read the OLD password from this file instead of prompting")
    p.add_argument("--new-password-file", dest="new_password_file",
                   help="Read the NEW password from this file instead of prompting")
    p.set_defaults(func=cmd_rekey)

    return parser


def main():
    parser = build_parser()
    defaults = _load_config()
    if defaults:
        # set_defaults silently overrides anything whose argparse dest matches.
        # Explicit CLI flags still take precedence because they're parsed after.
        parser.set_defaults(**defaults)
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
