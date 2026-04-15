"""Pure-Python DNS reconnaissance.

Implements a minimal DNS wire-format resolver so the toolkit works on a USB
stick without dig/nslookup or external packages like dnspython. Supports
EDNS0 for large responses, TCP fallback on truncation, AXFR attempts,
and DMARC/SPF parsing.
"""
import ipaddress
import random
import secrets
import socket
import struct

DEFAULT_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
EDNS_UDP_SIZE = 4096

RR_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "AXFR": 252,
    "CAA": 257,
}
RR_BY_NUM = {v: k for k, v in RR_TYPES.items()}

# DNS header flag masks
_FLAG_TC = 0x0200
_FLAG_AD = 0x0020


def _encode_name(qname):
    out = b""
    for part in qname.strip(".").split("."):
        if not part:
            continue
        encoded = part.encode("idna")
        if len(encoded) > 63:
            raise ValueError("label too long")
        out += bytes([len(encoded)]) + encoded
    return out + b"\x00"


def _encode_opt_rr(udp_size=EDNS_UDP_SIZE):
    # OPT pseudo-RR per RFC 6891.
    # name: root (0x00); type: 41 (OPT); class: UDP payload size;
    # TTL: ext-rcode(0)|version(0)|flags(0); RDLEN: 0
    return b"\x00" + struct.pack(">HHIH", 41, udp_size, 0, 0)


def _build_query(qname, qtype, recursion=True, use_edns=True):
    tid = random.randint(0, 0xFFFF)
    flags = 0x0100 if recursion else 0x0000
    arcount = 1 if use_edns else 0
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, arcount)
    question = _encode_name(qname) + struct.pack(">HH", qtype, 1)
    additional = _encode_opt_rr() if use_edns else b""
    return tid, header + question + additional


def _read_name(data, offset):
    labels = []
    jumped = False
    original = offset
    safety = 0
    while safety < 128:
        safety += 1
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original = offset + 2
                jumped = True
            offset = ptr
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    if not jumped:
        original = offset
    return ".".join(labels), original


def _parse_rdata(rtype, data, offset, rdlength):
    end = offset + rdlength
    if rtype == 1:  # A
        return ".".join(str(b) for b in data[offset:offset + 4])
    if rtype == 28:  # AAAA - delegate RFC 5952 compression to the stdlib
        return str(ipaddress.IPv6Address(bytes(data[offset:offset + 16])))
    if rtype in (2, 5, 12):  # NS, CNAME, PTR
        name, _ = _read_name(data, offset)
        return name
    if rtype == 15:  # MX
        pref = struct.unpack(">H", data[offset:offset + 2])[0]
        name, _ = _read_name(data, offset + 2)
        return {"preference": pref, "exchange": name}
    if rtype == 16:  # TXT
        parts = []
        p = offset
        while p < end:
            slen = data[p]
            p += 1
            parts.append(data[p:p + slen].decode("utf-8", "replace"))
            p += slen
        return "".join(parts)
    if rtype == 6:  # SOA
        mname, p = _read_name(data, offset)
        rname, p = _read_name(data, p)
        serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", data[p:p + 20])
        return {
            "mname": mname, "rname": rname, "serial": serial,
            "refresh": refresh, "retry": retry, "expire": expire, "minimum": minimum,
        }
    if rtype == 33:  # SRV
        pri, weight, port = struct.unpack(">HHH", data[offset:offset + 6])
        target, _ = _read_name(data, offset + 6)
        return {"priority": pri, "weight": weight, "port": port, "target": target}
    if rtype == 257:  # CAA
        flags = data[offset]
        taglen = data[offset + 1]
        tag = data[offset + 2:offset + 2 + taglen].decode("ascii", "replace")
        value = data[offset + 2 + taglen:end].decode("utf-8", "replace")
        return {"flags": flags, "tag": tag, "value": value}
    return data[offset:end].hex()


def _parse_sections(data, start_offset, count):
    answers = []
    offset = start_offset
    for _ in range(count):
        if offset >= len(data):
            break
        name, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        # Skip OPT pseudo-RRs in additional sections (type 41)
        if rtype == 41:
            offset += rdlength
            continue
        value = _parse_rdata(rtype, data, offset, rdlength)
        answers.append({
            "name": name,
            "type": RR_BY_NUM.get(rtype, str(rtype)),
            "ttl": ttl,
            "value": value,
        })
        offset += rdlength
    return answers, offset


def _parse_response(data):
    if len(data) < 12:
        return {"answers": [], "rcode": 1, "tc": False, "ad": False, "flags": 0}
    _tid, flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    offset = 12
    for _ in range(qdcount):
        if offset >= len(data):
            break
        _, offset = _read_name(data, offset)
        offset += 4
    answers, _ = _parse_sections(data, offset, ancount)
    return {
        "answers": answers,
        "rcode": flags & 0x0F,
        "tc": bool(flags & _FLAG_TC),
        "ad": bool(flags & _FLAG_AD),
        "flags": flags,
    }


def _recv_exact(sock, count):
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf


def _query_udp(qname, qtype_num, server, timeout):
    _tid, pkt = _build_query(qname, qtype_num)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (server, 53))
        data, _ = sock.recvfrom(EDNS_UDP_SIZE)
    finally:
        sock.close()
    return _parse_response(data)


def _query_tcp(qname, qtype_num, server, timeout):
    _tid, pkt = _build_query(qname, qtype_num, use_edns=False)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((server, 53))
        s.sendall(struct.pack(">H", len(pkt)) + pkt)
        header = _recv_exact(s, 2)
        (rlen,) = struct.unpack(">H", header)
        data = _recv_exact(s, rlen)
    return _parse_response(data)


def query(qname, qtype="A", server=None, timeout=3):
    if qtype not in RR_TYPES:
        raise ValueError(f"Unsupported DNS type: {qtype}")
    qtype_num = RR_TYPES[qtype]
    servers = [server] if server else DEFAULT_SERVERS
    last_err = None
    for srv in servers:
        try:
            resp = _query_udp(qname, qtype_num, srv, timeout)
            if resp["tc"]:
                # Retry over TCP/53 when the UDP response was truncated.
                try:
                    resp = _query_tcp(qname, qtype_num, srv, timeout)
                except Exception as tcp_exc:
                    last_err = tcp_exc
                    continue
            return {
                "server": srv,
                "rcode": resp["rcode"],
                "authenticated": resp["ad"],
                "truncated_retried_tcp": resp["tc"],
                "answers": resp["answers"],
            }
        except Exception as exc:  # pragma: no cover - network paths
            last_err = exc
            continue
    return {"error": str(last_err) if last_err else "no response", "answers": []}


def full_lookup(target, server=None):
    results = {"target": target}
    for qtype in ("A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA", "CAA"):
        results[qtype] = query(target, qtype, server=server)

    reverse = []
    for ans in results["A"].get("answers", []):
        if ans.get("type") == "A":
            ip = ans["value"]
            arpa = ".".join(ip.split(".")[::-1]) + ".in-addr.arpa"
            ptr = query(arpa, "PTR", server=server)
            reverse.append({"ip": ip, "ptr": ptr.get("answers", [])})
    results["reverse"] = reverse

    # New: attempt a zone transfer against every returned NS and parse SPF
    # / DMARC records. Both are best-effort and never raise.
    ns_hosts = [a["value"] for a in results["NS"].get("answers", []) if a.get("type") == "NS"]
    if ns_hosts:
        results["axfr"] = try_axfr(target, ns_hosts, server=server)
    else:
        results["axfr"] = []
    results["email_auth"] = parse_email_auth(target, txt_answers=results["TXT"].get("answers", []), server=server)
    return results


# ---------------------------------------------------------------------------
# Wildcard detection
# ---------------------------------------------------------------------------

def detect_wildcard(domain, server=None, tries=3):
    """Probe the zone for wildcard records.

    Returns {"is_wildcard", "ips", "cnames"} where is_wildcard is True when
    any of the random probes returned at least one answer. Callers should
    pass this into subdomain.enumerate so the brute-forcer can discard
    hits that merely repeat the wildcard answer set.
    """
    ips = set()
    cnames = set()
    domain = domain.strip(".")
    for _ in range(tries):
        label = secrets.token_hex(6)
        host = f"{label}.{domain}"
        a_res = query(host, "A", server=server, timeout=2)
        for ans in a_res.get("answers", []):
            if ans.get("type") == "A":
                ips.add(ans["value"])
            elif ans.get("type") == "CNAME":
                cnames.add(str(ans["value"]).rstrip("."))
        cn_res = query(host, "CNAME", server=server, timeout=2)
        for ans in cn_res.get("answers", []):
            if ans.get("type") == "CNAME":
                cnames.add(str(ans["value"]).rstrip("."))
    return {
        "is_wildcard": bool(ips or cnames),
        "ips": sorted(ips),
        "cnames": sorted(cnames),
    }


# ---------------------------------------------------------------------------
# Zone transfer (AXFR)
# ---------------------------------------------------------------------------

def _tcp_stream(sock, timeout):
    """Yield DNS messages from a TCP stream using 2-byte length prefixes."""
    sock.settimeout(timeout)
    while True:
        try:
            header = _recv_exact(sock, 2)
        except EOFError:
            return
        (rlen,) = struct.unpack(">H", header)
        if rlen == 0:
            return
        try:
            data = _recv_exact(sock, rlen)
        except EOFError:
            return
        yield data


def try_axfr(domain, nameservers, server=None, timeout=6):
    """Attempt a zone transfer against each nameserver.

    Returns a list of {"ns", "ok", "records"|"error"} entries. Most zones
    refuse AXFR from arbitrary clients - that is the normal and expected
    outcome and produces error="refused" here.
    """
    results = []
    for ns in nameservers:
        ns_clean = str(ns).rstrip(".")
        ns_ip = _resolve_ns(ns_clean, server=server)
        if not ns_ip:
            results.append({"ns": ns_clean, "error": "unresolvable"})
            continue
        try:
            _tid, pkt = _build_query(domain, RR_TYPES["AXFR"], use_edns=False)
            records = []
            soa_count = 0
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ns_ip, 53))
                s.sendall(struct.pack(">H", len(pkt)) + pkt)
                for data in _tcp_stream(s, timeout):
                    resp = _parse_response(data)
                    if resp["rcode"] != 0 and not resp["answers"]:
                        results.append({
                            "ns": ns_clean,
                            "error": f"rcode {resp['rcode']} (likely refused)",
                        })
                        break
                    for rr in resp["answers"]:
                        records.append(rr)
                        if rr["type"] == "SOA":
                            soa_count += 1
                    if soa_count >= 2:
                        break
                else:
                    # Exhausted stream cleanly.
                    if soa_count < 2:
                        results.append({"ns": ns_clean, "error": "refused or incomplete"})
                        continue
                if records and soa_count >= 2:
                    results.append({"ns": ns_clean, "ok": True, "records": records})
        except Exception as exc:
            results.append({"ns": ns_clean, "error": str(exc)})
    return results


def _resolve_ns(ns_name, server=None):
    """Resolve an NS hostname to a single IPv4 address (best-effort)."""
    # Try our own resolver first so we don't depend on the OS.
    res = query(ns_name, "A", server=server, timeout=3)
    for ans in res.get("answers", []):
        if ans.get("type") == "A":
            return ans["value"]
    # Fall back to the OS resolver.
    try:
        return socket.gethostbyname(ns_name)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# DMARC / SPF helpers
# ---------------------------------------------------------------------------

def _tag_value_parse(blob):
    """Parse a tag=value; tag=value; ... DNS TXT payload into a dict."""
    out = {}
    for part in blob.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


def parse_email_auth(domain, txt_answers=None, server=None):
    """Extract SPF and DMARC records for a domain.

    `txt_answers` is optional; when provided it should be the already-fetched
    TXT answers from full_lookup. DMARC is always queried separately under
    _dmarc.<domain>.
    """
    spf = None
    if txt_answers is None:
        txt_res = query(domain, "TXT", server=server)
        txt_answers = txt_res.get("answers", [])
    for ans in txt_answers:
        val = str(ans.get("value", ""))
        if val.startswith("v=spf1"):
            spf = {
                "raw": val,
                "mechanisms": val.split()[1:],
            }
            break

    dmarc = None
    try:
        dres = query("_dmarc." + domain.strip("."), "TXT", server=server, timeout=3)
        for ans in dres.get("answers", []):
            val = str(ans.get("value", ""))
            if val.lower().startswith("v=dmarc1"):
                dmarc = {"raw": val, "fields": _tag_value_parse(val)}
                break
    except Exception as exc:  # pragma: no cover
        dmarc = {"error": str(exc)}

    return {"spf": spf, "dmarc": dmarc}
