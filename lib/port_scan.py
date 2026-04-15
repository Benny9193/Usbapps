"""Pure-Python port scanner (used when Nmap is unavailable).

TCP connect scans run per-address so IPv4 and IPv6 results are both covered
when a hostname resolves to several families. A minimal UDP probe mode sends
protocol-appropriate packets to common ports (DNS/NTP/SNMP) and treats any
reply as "open", a timeout as "open|filtered", and an ICMP unreachable as
"closed".
"""
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 500: "isakmp", 514: "syslog", 587: "submission", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 2181: "zookeeper",
    2375: "docker", 3000: "http-alt", 3306: "mysql", 3389: "rdp",
    5000: "http-alt", 5432: "postgres", 5601: "kibana", 5672: "amqp",
    5900: "vnc", 5985: "winrm", 5986: "winrm-ssl", 6379: "redis",
    6667: "irc", 8000: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9090: "http-alt", 9200: "elasticsearch", 9300: "elasticsearch",
    11211: "memcached", 27017: "mongodb", 50000: "sap",
}

# Ports where a TLS handshake is expected - we don't implement ClientHello in
# stdlib, so we just label them and skip the read.
_TLS_PORTS = {443, 465, 636, 993, 995, 5986, 8443}

# HTTP-ish ports where we should send a HEAD request to elicit a Server header.
_HTTP_PORTS = {80, 280, 591, 8000, 8008, 8080, 8081, 8443, 8888, 3000, 5000, 9000, 9090}


def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def _resolve(target):
    """Return a list of (family, sockaddr, display_ip) for the target."""
    # Strip brackets from IPv6 literals like [::1].
    clean = target.strip("[]")
    try:
        infos = socket.getaddrinfo(clean, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        # UnicodeError happens when idna encoding can't handle odd inputs.
        return [], str(exc)
    seen = {}
    for family, _stype, _proto, _canon, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        ip = sockaddr[0]
        key = (family, ip)
        if key in seen:
            continue
        seen[key] = (family, sockaddr, ip)
    return list(seen.values()), None


def _send_probe(sock, port):
    """Send a protocol-specific probe and return any bytes read (decoded)."""
    try:
        if port in _TLS_PORTS:
            return "(tls - handshake not performed)"
        if port in _HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: probe\r\nUser-Agent: recon/1.0\r\n\r\n")
        elif port in (25, 587):
            # SMTP: read greeting, then EHLO
            greet = sock.recv(256)
            try:
                sock.sendall(b"EHLO recon.local\r\n")
                ehlo = sock.recv(512)
                return (greet + b"\n" + ehlo).decode("utf-8", "replace").strip()
            except Exception:
                return greet.decode("utf-8", "replace").strip()
        elif port in (110, 143, 21, 22, 119):
            # Read-only protocols: server speaks first.
            pass
        else:
            # Generic: give the server a moment to speak first.
            pass
        sock.settimeout(0.8)
        data = sock.recv(512)
        return data.decode("utf-8", "replace").strip()
    except Exception:
        return ""


def _tcp_probe(family, sockaddr, port, timeout):
    host = sockaddr[0]
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            # getaddrinfo's sockaddr tuple already includes scope/flowinfo for v6.
            target = (host, port) + sockaddr[2:]
            if s.connect_ex(target) == 0:
                banner = _send_probe(s, port)
                return port, "open", banner
    except Exception:
        pass
    return port, "closed", ""


def _udp_probe(family, sockaddr, port, timeout):
    """Send a protocol-appropriate UDP packet and classify the response."""
    host = sockaddr[0]
    payload = _udp_payload(port)
    if payload is None:
        return port, "skipped", ""
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, (host, port) + sockaddr[2:])
            try:
                data, _ = s.recvfrom(2048)
                banner = data[:64].hex()
                return port, "open", banner
            except socket.timeout:
                return port, "open|filtered", ""
    except OSError as exc:
        # ECONNREFUSED typically => ICMP unreachable => port closed
        if exc.errno in (111, 10054):
            return port, "closed", ""
        return port, "error", str(exc)
    except Exception:
        return port, "error", ""


def _udp_payload(port):
    """Return a small protocol probe for well-known UDP ports, or None."""
    if port == 53:
        # Minimal DNS query for "." NS. id=0x1234, flags=standard, qd=1.
        return (
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x02\x00\x01"
        )
    if port == 123:
        # NTPv4 client packet: LI=0, VN=4, mode=3, stratum=0, rest zero.
        return b"\x23" + b"\x00" * 47
    if port == 161:
        # SNMPv1 get-request for sysDescr.0 (1.3.6.1.2.1.1.1.0) with community "public".
        return bytes.fromhex(
            "302902010004067075626c6963a01c020400000001020100020100300e300c06"
            "082b060102010101000500"
        )
    if port == 500:
        # IKEv1 informational header (zeros) - many responders will answer.
        return b"\x00" * 8 + b"\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x01\x10\x02\x00" + b"\x00" * 12
    if port == 1900:
        return (
            b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
            b"MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
        )
    return None


def scan(target, ports="1-1024", timeout=1.0, workers=200, protocol="tcp"):
    addresses, err = _resolve(target)
    if not addresses:
        return {"target": target, "error": err or "no addresses", "ports": [], "addresses": []}

    port_list = parse_ports(ports)
    start = time.time()

    per_address = []
    flat_ports = []  # aggregate the dashboard's existing renderer can consume

    probe_fn = _udp_probe if protocol == "udp" else _tcp_probe

    for family, sockaddr, display_ip in addresses:
        open_ports = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(probe_fn, family, sockaddr, p, timeout) for p in port_list]
            for fut in as_completed(futures):
                port, state, banner = fut.result()
                if state in ("open", "open|filtered"):
                    entry = {
                        "port": port,
                        "protocol": protocol,
                        "state": state,
                        "service": COMMON_SERVICES.get(port),
                        "banner": banner,
                    }
                    open_ports.append(entry)
                    flat_ports.append(dict(entry, ip=display_ip))
        open_ports.sort(key=lambda p: p["port"])
        per_address.append({
            "ip": display_ip,
            "family": "AF_INET6" if family == socket.AF_INET6 else "AF_INET",
            "ports": open_ports,
        })

    flat_ports.sort(key=lambda p: (p.get("ip", ""), p["port"]))

    return {
        "target": target,
        # Legacy keys preserved so the dashboard's current renderer still works.
        "ip": addresses[0][2],
        "scanned": len(port_list),
        "elapsed": round(time.time() - start, 2),
        "ports": flat_ports,
        # New richer per-address breakdown.
        "addresses": per_address,
        "protocol": protocol,
    }
