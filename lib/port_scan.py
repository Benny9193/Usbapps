"""Pure-Python TCP connect port scanner (used when Nmap is unavailable)."""
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 587: "submission", 636: "ldaps",
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


def _probe(host, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                banner = ""
                try:
                    s.settimeout(0.5)
                    data = s.recv(128)
                    banner = data.decode("utf-8", "replace").strip()
                except Exception:
                    banner = ""
                return port, "open", banner
    except Exception:
        pass
    return port, "closed", ""


def scan(target, ports="1-1024", timeout=1.0, workers=200):
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        return {"target": target, "error": str(exc), "ports": []}

    port_list = parse_ports(ports)
    start = time.time()
    open_ports = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_probe, ip, p, timeout) for p in port_list]
        for fut in as_completed(futures):
            port, state, banner = fut.result()
            if state == "open":
                open_ports.append({
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": COMMON_SERVICES.get(port),
                    "banner": banner,
                })

    open_ports.sort(key=lambda p: p["port"])
    return {
        "target": target,
        "ip": ip,
        "scanned": len(port_list),
        "elapsed": round(time.time() - start, 2),
        "ports": open_ports,
    }
