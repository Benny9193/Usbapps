"""Subdomain brute force via DNS A-record lookups."""
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import dns_tools


def _check(domain, word, server):
    host = f"{word}.{domain.strip('.')}"
    result = dns_tools.query(host, "A", server=server, timeout=2)
    ips = [a["value"] for a in result.get("answers", []) if a.get("type") == "A"]
    return host, ips


def enumerate(domain, wordlist_path, server=None, workers=32):
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as handle:
        words = [w.strip() for w in handle if w.strip() and not w.startswith("#")]

    found = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_check, domain, w, server): w for w in words}
        for fut in as_completed(futures):
            try:
                host, ips = fut.result()
            except Exception:
                continue
            if ips:
                found.append({"subdomain": host, "ips": ips})
                print(f"  [+] {host} -> {', '.join(ips)}")

    found.sort(key=lambda x: x["subdomain"])
    return {
        "domain": domain,
        "wordlist": wordlist_path,
        "tested": len(words),
        "found": found,
    }
