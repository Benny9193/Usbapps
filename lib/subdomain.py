"""Subdomain brute force via DNS A-record lookups."""
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import dns_tools, logutil

log = logutil.get("subdomain")


def _check(domain, word, server):
    host = f"{word}.{domain.strip('.')}"
    result = dns_tools.query(host, "A", server=server, timeout=2)
    ips = [a["value"] for a in result.get("answers", []) if a.get("type") == "A"]
    cnames = [str(a["value"]).rstrip(".") for a in result.get("answers", []) if a.get("type") == "CNAME"]
    return host, ips, cnames


def enumerate(domain, wordlist_path, server=None, workers=32, wildcard=None):
    """Brute-force subdomains from `wordlist_path`.

    `wildcard` is an optional pre-computed dict from
    dns_tools.detect_wildcard. When provided, any answer whose IP set is a
    subset of the wildcard IP set (or whose CNAME matches a wildcard CNAME)
    is classified as a wildcard match and excluded from `found`.

    If `wildcard` is None, wildcard detection runs here automatically.
    """
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as handle:
        words = [w.strip() for w in handle if w.strip() and not w.startswith("#")]

    if wildcard is None:
        wildcard = dns_tools.detect_wildcard(domain, server=server)
    wc_ips = set(wildcard.get("ips") or [])
    wc_cnames = set(wildcard.get("cnames") or [])
    is_wildcard_zone = bool(wildcard.get("is_wildcard"))

    found = []
    wildcard_hits = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_check, domain, w, server): w for w in words}
        for fut in as_completed(futures):
            try:
                host, ips, cnames = fut.result()
            except Exception:
                continue
            if not ips and not cnames:
                continue
            # If the zone is a wildcard, drop answers that merely echo it.
            if is_wildcard_zone:
                ip_set = set(ips)
                cname_set = set(cnames)
                if (ip_set and ip_set.issubset(wc_ips)) or (cname_set and cname_set.issubset(wc_cnames)):
                    wildcard_hits += 1
                    continue
            entry = {"subdomain": host, "ips": ips}
            if cnames:
                entry["cnames"] = cnames
            found.append(entry)
            log.info("  %s -> %s", host, ", ".join(ips) if ips else ", ".join(cnames))

    found.sort(key=lambda x: x["subdomain"])
    return {
        "domain": domain,
        "wordlist": wordlist_path,
        "tested": len(words),
        "found": found,
        "wildcard": {
            "active": is_wildcard_zone,
            "ips": sorted(wc_ips),
            "cnames": sorted(wc_cnames),
            "filtered_out": wildcard_hits,
        },
    }
