"""Single-session exporters: Markdown, HTML, and CSV.

All exporters use stdlib only. The HTML export is self-contained (inline
CSS, no external references) so it can be emailed or printed. The CSV
export emits a section-tagged single file so it opens cleanly in any
spreadsheet tool.
"""
import csv
import html
import io
import json
from pathlib import Path

from . import report


def _load(session_ref):
    path = Path(session_ref)
    if not path.exists():
        candidate = report.RESULTS / f"{session_ref}.json"
        if candidate.exists():
            path = candidate
        else:
            raise FileNotFoundError(f"no such session: {session_ref}")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def to_markdown(session_ref):
    s = _load(session_ref) if not isinstance(session_ref, dict) else session_ref
    lines = [f"# Recon: {s.get('target', '?')}", ""]
    lines.append(f"- **Scan type**: {s.get('scan_type', '?')}")
    lines.append(f"- **Captured**: {s.get('created', '?')}")
    lines.append("")

    nmap = s.get("nmap") or {}
    if nmap and not nmap.get("error"):
        lines.append("## Nmap")
        if nmap.get("command"):
            lines.append(f"`{nmap['command']}`")
            lines.append("")
        for host in nmap.get("hosts") or []:
            lines.append(f"### {host.get('address', '?')} ({host.get('state', '?')})")
            if host.get("os"):
                os_info = host["os"]
                lines.append(f"- OS: {os_info.get('name', '?')} "
                             f"({os_info.get('accuracy', '?')}%)")
            if host.get("ports"):
                lines.append("")
                lines.append("| Port | Proto | State | Service | Version |")
                lines.append("|------|-------|-------|---------|---------|")
                for p in host["ports"]:
                    version = " ".join(x for x in [p.get("product"), p.get("version")] if x) or "-"
                    lines.append(
                        f"| {p.get('port')} | {p.get('protocol', '-')} | "
                        f"{p.get('state', '-')} | {p.get('service', '-')} | {version} |"
                    )
            lines.append("")

    dns = s.get("dns") or {}
    if dns and not dns.get("error"):
        lines.append("## DNS")
        for qtype in ("A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA", "CAA"):
            rec = (dns.get(qtype) or {}).get("answers") or []
            if not rec:
                continue
            lines.append(f"### {qtype}")
            for a in rec:
                lines.append(f"- {a.get('name', '?')} -> {a.get('value', '?')}")
            lines.append("")
        if dns.get("email_auth"):
            ea = dns["email_auth"]
            if ea.get("spf"):
                lines.append(f"**SPF**: `{ea['spf'].get('raw', '')}`")
            if ea.get("dmarc"):
                lines.append(f"**DMARC**: `{ea['dmarc'].get('raw', '')}`")
            lines.append("")

    sub = s.get("subdomains") or {}
    if sub and not sub.get("error"):
        lines.append("## Subdomains")
        lines.append(f"- Tested: {sub.get('tested', 0)}")
        lines.append(f"- Found: {len(sub.get('found') or [])}")
        for f in sub.get("found") or []:
            ips = ", ".join(f.get("ips") or [])
            lines.append(f"- {f.get('subdomain', '?')} -> {ips}")
        lines.append("")

    wh = s.get("whois") or {}
    if wh and not wh.get("error"):
        lines.append("## WHOIS")
        for k, v in (wh.get("fields") or {}).items():
            if isinstance(v, list):
                v = ", ".join(v)
            lines.append(f"- **{k}**: {v}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_HTML_STYLE = """
body { font-family: -apple-system, Segoe UI, sans-serif; max-width: 960px;
       margin: 2em auto; padding: 0 1em; color: #222; background: #fafafa; }
h1, h2, h3 { color: #0f4c75; }
table { border-collapse: collapse; width: 100%; margin: 1em 0; }
th, td { border: 1px solid #ddd; padding: 0.4em 0.7em; text-align: left; }
th { background: #e8eef3; }
code { background: #eef; padding: 0 4px; border-radius: 3px; }
.meta { color: #666; font-size: 0.9em; }
"""


def to_html(session_ref):
    s = _load(session_ref) if not isinstance(session_ref, dict) else session_ref
    esc = html.escape
    out = io.StringIO()
    out.write("<!doctype html><html><head><meta charset='utf-8'>")
    out.write(f"<title>Recon: {esc(str(s.get('target', '?')))}</title>")
    out.write(f"<style>{_HTML_STYLE}</style></head><body>")
    out.write(f"<h1>Recon: {esc(str(s.get('target', '?')))}</h1>")
    out.write(
        f"<p class='meta'>Scan type: <code>{esc(str(s.get('scan_type', '?')))}</code> &middot; "
        f"Captured: {esc(str(s.get('created', '?')))}</p>"
    )

    nmap = s.get("nmap") or {}
    if nmap and not nmap.get("error"):
        out.write("<h2>Nmap</h2>")
        if nmap.get("command"):
            out.write(f"<p><code>{esc(nmap['command'])}</code></p>")
        for host in nmap.get("hosts") or []:
            out.write(f"<h3>{esc(str(host.get('address', '?')))} "
                      f"<span class='meta'>{esc(str(host.get('state', '?')))}</span></h3>")
            if host.get("ports"):
                out.write("<table><tr><th>Port</th><th>Proto</th><th>State</th>"
                          "<th>Service</th><th>Version</th></tr>")
                for p in host["ports"]:
                    version = " ".join(x for x in [p.get("product"), p.get("version")] if x) or "-"
                    out.write(
                        f"<tr><td>{esc(str(p.get('port')))}</td>"
                        f"<td>{esc(str(p.get('protocol', '-')))}</td>"
                        f"<td>{esc(str(p.get('state', '-')))}</td>"
                        f"<td>{esc(str(p.get('service', '-')))}</td>"
                        f"<td>{esc(version)}</td></tr>"
                    )
                out.write("</table>")

    dns = s.get("dns") or {}
    if dns and not dns.get("error"):
        out.write("<h2>DNS</h2>")
        for qtype in ("A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA", "CAA"):
            rec = (dns.get(qtype) or {}).get("answers") or []
            if not rec:
                continue
            out.write(f"<h3>{qtype}</h3><table><tr><th>Name</th><th>TTL</th><th>Value</th></tr>")
            for a in rec:
                out.write(
                    f"<tr><td>{esc(str(a.get('name', '?')))}</td>"
                    f"<td>{esc(str(a.get('ttl', '-')))}</td>"
                    f"<td><code>{esc(json.dumps(a.get('value'), default=str))}</code></td></tr>"
                )
            out.write("</table>")

    sub = s.get("subdomains") or {}
    if sub and not sub.get("error") and sub.get("found"):
        out.write("<h2>Subdomains</h2><table><tr><th>Subdomain</th><th>IPs</th></tr>")
        for f in sub["found"]:
            out.write(
                f"<tr><td><code>{esc(str(f.get('subdomain', '?')))}</code></td>"
                f"<td>{esc(', '.join(f.get('ips') or []))}</td></tr>"
            )
        out.write("</table>")

    wh = s.get("whois") or {}
    if wh and not wh.get("error") and wh.get("fields"):
        out.write("<h2>WHOIS</h2><table><tr><th>Field</th><th>Value</th></tr>")
        for k, v in wh["fields"].items():
            if isinstance(v, list):
                v = ", ".join(v)
            out.write(f"<tr><td>{esc(str(k))}</td><td>{esc(str(v))}</td></tr>")
        out.write("</table>")

    out.write("</body></html>")
    return out.getvalue()


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def to_csv(session_ref):
    """Emit a single CSV with a `section` column so one file covers all data."""
    s = _load(session_ref) if not isinstance(session_ref, dict) else session_ref
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["section", "key", "subkey", "value"])

    w.writerow(["meta", "target", "", s.get("target", "")])
    w.writerow(["meta", "scan_type", "", s.get("scan_type", "")])
    w.writerow(["meta", "created", "", s.get("created", "")])

    nmap = s.get("nmap") or {}
    for host in nmap.get("hosts") or []:
        for p in host.get("ports") or []:
            version = " ".join(x for x in [p.get("product"), p.get("version")] if x)
            w.writerow([
                "nmap", host.get("address", ""), p.get("port", ""),
                f"{p.get('protocol', '')}|{p.get('state', '')}|{p.get('service', '')}|{version}",
            ])

    dns = s.get("dns") or {}
    for qtype in ("A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA", "CAA"):
        rec = (dns.get(qtype) or {}).get("answers") or []
        for a in rec:
            w.writerow(["dns", qtype, a.get("name", ""), json.dumps(a.get("value"), default=str)])

    sub = s.get("subdomains") or {}
    for f in (sub.get("found") or []):
        w.writerow(["subdomains", f.get("subdomain", ""), "", ", ".join(f.get("ips") or [])])

    wh = s.get("whois") or {}
    for k, v in (wh.get("fields") or {}).items():
        if isinstance(v, list):
            v = ", ".join(v)
        w.writerow(["whois", k, "", v])

    return out.getvalue()


EXPORTERS = {"md": to_markdown, "html": to_html, "csv": to_csv}
