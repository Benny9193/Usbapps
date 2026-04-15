"""HTTP CONNECT proxy client for TCP sockets.

Reads HTTPS_PROXY / ALL_PROXY from the environment (or uses the PROXY_URL
module-level override) and returns a connected socket that has already
traversed the CONNECT handshake. When no proxy is configured, returns a
plain socket.create_connection.

UDP cannot be tunneled through CONNECT; callers that want UDP (the UDP port
scanner, DNS) MUST keep using direct sockets.
"""
import os
import socket
import urllib.parse


PROXY_URL = None  # tests can monkey-patch this


def _proxy():
    if PROXY_URL:
        return PROXY_URL
    for key in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        val = os.environ.get(key)
        if val:
            return val
    return None


def connect(host, port, timeout=5.0):
    """Return a connected socket to (host, port) via any configured proxy."""
    proxy = _proxy()
    if not proxy:
        return socket.create_connection((host, port), timeout=timeout)

    parsed = urllib.parse.urlparse(proxy if "://" in proxy else "http://" + proxy)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported proxy scheme: {parsed.scheme}")
    proxy_host = parsed.hostname
    proxy_port = parsed.port or (443 if parsed.scheme == "https" else 80)

    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        # We deliberately do not upgrade to TLS even for https proxies,
        # because stdlib only ships ssl which isn't always available on
        # a pared-down portable Python. Operators who need TLS-to-proxy
        # should run a local relay.
        req = (
            f"CONNECT {host}:{port} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
        )
        if parsed.username and parsed.password:
            import base64
            creds = f"{parsed.username}:{parsed.password}".encode("utf-8")
            token = base64.b64encode(creds).decode("ascii")
            req += f"Proxy-Authorization: Basic {token}\r\n"
        req += "\r\n"
        sock.sendall(req.encode("ascii"))

        # Read until we hit the blank line terminator.
        buf = b""
        sock.settimeout(timeout)
        while b"\r\n\r\n" not in buf and len(buf) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("proxy closed before response")
            buf += chunk
        status_line = buf.split(b"\r\n", 1)[0].decode("ascii", "replace")
        if not status_line.startswith("HTTP/1.") or " 200" not in status_line:
            raise ConnectionError(f"proxy CONNECT failed: {status_line}")
        return sock
    except Exception:
        sock.close()
        raise
