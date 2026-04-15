"""Pure-Python DNS reconnaissance.

Implements a minimal DNS wire-format resolver so the toolkit works on a USB
stick without dig/nslookup or external packages like dnspython.
"""
import random
import socket
import struct

DEFAULT_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

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
    "CAA": 257,
}
RR_BY_NUM = {v: k for k, v in RR_TYPES.items()}


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


def _build_query(qname, qtype):
    tid = random.randint(0, 0xFFFF)
    flags = 0x0100  # standard recursive query
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
    question = _encode_name(qname) + struct.pack(">HH", qtype, 1)
    return tid, header + question


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
    if rtype == 28:  # AAAA
        parts = struct.unpack(">8H", data[offset:offset + 16])
        # Collapse longest zero run per RFC 5952 (simple version)
        hexparts = [f"{p:x}" for p in parts]
        return ":".join(hexparts)
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


def _parse_response(data):
    if len(data) < 12:
        return [], 1
    _tid, flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    offset = 12
    for _ in range(qdcount):
        _, offset = _read_name(data, offset)
        offset += 4
    answers = []
    for _ in range(ancount):
        name, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        value = _parse_rdata(rtype, data, offset, rdlength)
        answers.append({
            "name": name,
            "type": RR_BY_NUM.get(rtype, str(rtype)),
            "ttl": ttl,
            "value": value,
        })
        offset += rdlength
    rcode = flags & 0x0F
    return answers, rcode


def query(qname, qtype="A", server=None, timeout=3):
    if qtype not in RR_TYPES:
        raise ValueError(f"Unsupported DNS type: {qtype}")
    servers = [server] if server else DEFAULT_SERVERS
    last_err = None
    for srv in servers:
        try:
            _tid, pkt = _build_query(qname, RR_TYPES[qtype])
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                sock.sendto(pkt, (srv, 53))
                data, _ = sock.recvfrom(4096)
            finally:
                sock.close()
            answers, rcode = _parse_response(data)
            return {"server": srv, "rcode": rcode, "answers": answers}
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
    return results
