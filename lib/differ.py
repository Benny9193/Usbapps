"""Session diffing.

Given two session IDs (or file paths), compare the state of the target and
emit a structured delta: ports opened/closed, DNS record changes, subdomain
churn, and WHOIS expiry date changes. The result is a JSON-friendly dict
that `cmd_diff` can drop into results/ so the dashboard can surface it as
a first-class session.
"""
import json
from email.utils import parsedate_to_datetime
from pathlib import Path

from . import report


def _load(session_id_or_path):
    """Load a session by id or path, decrypting transparently if needed."""
    return report.load_session(session_id_or_path)


def _open_ports(session):
    """Return a set of (ip, port, protocol) for every open port in a session."""
    out = set()
    nmap = session.get("nmap") or {}
    for host in nmap.get("hosts") or []:
        ip = host.get("address") or ""
        for p in host.get("ports") or []:
            if p.get("state") == "open":
                out.add((ip, p.get("port"), p.get("protocol") or "tcp"))
    ps = session.get("port_scan") or {}
    for p in ps.get("ports") or []:
        if p.get("state") in ("open", "open|filtered"):
            out.add((p.get("ip") or ps.get("ip") or "", p.get("port"), p.get("protocol") or "tcp"))
    return out


def _dns_values(session, qtype):
    rec = ((session.get("dns") or {}).get(qtype) or {}).get("answers") or []
    return {json.dumps(a.get("value"), sort_keys=True, default=str) for a in rec}


def _subdomain_names(session):
    sub = session.get("subdomains") or {}
    return {f.get("subdomain") for f in (sub.get("found") or []) if f.get("subdomain")}


def _whois_expiry(session):
    fields = ((session.get("whois") or {}).get("fields") or {})
    for key in ("Registry Expiry Date", "Registrar Registration Expiration Date",
                "Expiration Date", "Expires On", "paid-till"):
        if key in fields:
            v = fields[key]
            if isinstance(v, list):
                v = v[0]
            try:
                return parsedate_to_datetime(v).isoformat()
            except Exception:
                return str(v)
    return None


def diff(a_session_ref, b_session_ref):
    a = _load(a_session_ref)
    b = _load(b_session_ref)
    if a.get("target") != b.get("target"):
        raise ValueError(
            f"session target mismatch: {a.get('target')} vs {b.get('target')}"
        )

    a_ports = _open_ports(a)
    b_ports = _open_ports(b)

    dns_delta = {}
    for qtype in ("A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA", "CAA"):
        a_vals = _dns_values(a, qtype)
        b_vals = _dns_values(b, qtype)
        added = sorted(b_vals - a_vals)
        removed = sorted(a_vals - b_vals)
        if added or removed:
            dns_delta[qtype] = {"added": added, "removed": removed}

    a_subs = _subdomain_names(a)
    b_subs = _subdomain_names(b)

    return {
        "target": a.get("target"),
        "a": {"id": a.get("_id"), "created": a.get("created")},
        "b": {"id": b.get("_id"), "created": b.get("created")},
        "ports": {
            "added": sorted(b_ports - a_ports),
            "removed": sorted(a_ports - b_ports),
            "unchanged": len(a_ports & b_ports),
        },
        "dns": dns_delta,
        "subdomains": {
            "added": sorted(b_subs - a_subs),
            "removed": sorted(a_subs - b_subs),
        },
        "whois_expiry": {
            "before": _whois_expiry(a),
            "after": _whois_expiry(b),
        },
    }
