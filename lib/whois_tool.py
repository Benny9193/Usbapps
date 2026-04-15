"""Minimal WHOIS client using stdlib sockets."""
import ipaddress
import re
import socket

IANA_WHOIS = "whois.iana.org"
ARIN_WHOIS = "whois.arin.net"

# Well-known WHOIS servers so we do not need an extra round-trip to IANA for
# the most common TLDs. Anything missing is resolved via IANA.
KNOWN_SERVERS = {
    "com":  "whois.verisign-grs.com",
    "net":  "whois.verisign-grs.com",
    "org":  "whois.pir.org",
    "info": "whois.afilias.net",
    "biz":  "whois.biz",
    "io":   "whois.nic.io",
    "dev":  "whois.nic.google",
    "app":  "whois.nic.google",
    "co":   "whois.nic.co",
    "us":   "whois.nic.us",
    "uk":   "whois.nic.uk",
    "me":   "whois.nic.me",
    "ai":   "whois.nic.ai",
    "xyz":  "whois.nic.xyz",
    "tech": "whois.nic.tech",
    "cloud": "whois.nic.cloud",
}


def _is_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _query(server, target, timeout=5):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((server, 43))
        s.sendall((target + "\r\n").encode("utf-8"))
        chunks = []
        while True:
            try:
                data = s.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", "replace")


def lookup(target):
    target = target.strip().lstrip(".")

    if _is_ip(target):
        # IPv4 / IPv6 addresses go to ARIN first; the referral regex below
        # then forwards us to the correct RIR (RIPE/APNIC/LACNIC/AFRINIC).
        server = ARIN_WHOIS
    else:
        target = target.lower()
        tld = target.rsplit(".", 1)[-1] if "." in target else target
        server = KNOWN_SERVERS.get(tld)
        if not server:
            try:
                iana_resp = _query(IANA_WHOIS, target)
                match = re.search(r"whois:\s*(\S+)", iana_resp, re.IGNORECASE)
                if match:
                    server = match.group(1)
            except Exception as exc:
                return {"target": target, "error": f"IANA query failed: {exc}", "raw": ""}

    if not server:
        return {"target": target, "error": "No WHOIS server found", "raw": ""}

    try:
        raw = _query(server, target)
    except Exception as exc:
        return {"target": target, "server": server, "error": str(exc), "raw": ""}

    # Follow a referral if the registry points us at the registrar or an RIR.
    referral_pat = r"(?:Registrar WHOIS Server|ReferralServer|refer):\s*(?:r?whois://)?(\S+)"
    referral = re.search(referral_pat, raw, re.IGNORECASE)
    if referral:
        ref_server = referral.group(1).split(":")[0].rstrip("/")
        try:
            raw2 = _query(ref_server, target)
            raw = raw + "\n\n%% Referral follow-up %%\n\n" + raw2
            # One more hop for chains like ARIN -> RIPE -> (registrar)
            referral2 = re.search(referral_pat, raw2, re.IGNORECASE)
            if referral2:
                ref2 = referral2.group(1).split(":")[0].rstrip("/")
                if ref2 != ref_server:
                    try:
                        raw3 = _query(ref2, target)
                        raw = raw + "\n\n%% Referral hop 2 %%\n\n" + raw3
                    except Exception:
                        pass
        except Exception:
            pass

    fields = {}
    for line in raw.splitlines():
        m = re.match(r"\s*([A-Za-z][A-Za-z0-9 \-/]+?):\s*(.+?)\s*$", line)
        if not m:
            continue
        key = m.group(1).strip()
        val = m.group(2).strip()
        if not val or val.startswith(">>>"):
            continue
        if key in fields:
            existing = fields[key]
            if isinstance(existing, list):
                if val not in existing:
                    existing.append(val)
            elif existing != val:
                fields[key] = [existing, val]
        else:
            fields[key] = val

    return {"target": target, "server": server, "fields": fields, "raw": raw}
