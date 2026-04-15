"""Tests for lib.port_scan: port parser, resolver, and UDP payload registry."""
import socket
import threading
import time
import unittest

from tests import _path  # noqa: F401
from lib import port_scan


class ParsePortsTests(unittest.TestCase):
    def test_comma_separated(self):
        self.assertEqual(port_scan.parse_ports("80,443"), [80, 443])

    def test_range(self):
        self.assertEqual(port_scan.parse_ports("1-3"), [1, 2, 3])

    def test_mixed(self):
        self.assertEqual(port_scan.parse_ports("22,80,1-3"), [1, 2, 3, 22, 80])

    def test_empty(self):
        self.assertEqual(port_scan.parse_ports(""), [])

    def test_bounds(self):
        # Ports outside 1..65535 are dropped.
        self.assertEqual(port_scan.parse_ports("0,1,65535,65536"), [1, 65535])


class ResolveTests(unittest.TestCase):
    def test_localhost_resolves(self):
        addrs, err = port_scan._resolve("127.0.0.1")
        self.assertIsNone(err)
        self.assertEqual(len(addrs), 1)
        self.assertEqual(addrs[0][2], "127.0.0.1")

    def test_ipv6_literal_strips_brackets(self):
        addrs, err = port_scan._resolve("[::1]")
        # Not every CI host has IPv6 on loopback; tolerate either.
        if addrs:
            self.assertEqual(addrs[0][0], socket.AF_INET6)

    def test_bogus_host(self):
        addrs, err = port_scan._resolve("nxdomain-...invalid")
        self.assertEqual(addrs, [])
        self.assertIsNotNone(err)


class UdpPayloadTests(unittest.TestCase):
    def test_ntp_48_bytes(self):
        self.assertEqual(len(port_scan._udp_payload(123)), 48)

    def test_dns_header_first_12_bytes(self):
        pkt = port_scan._udp_payload(53)
        # id=0x1234
        self.assertEqual(pkt[:2], b"\x12\x34")

    def test_unknown_port_returns_none(self):
        self.assertIsNone(port_scan._udp_payload(9999))


class TcpScanIntegrationTest(unittest.TestCase):
    """End-to-end: open a loopback listener and scan it."""

    def setUp(self):
        self._listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listen.bind(("127.0.0.1", 0))
        self._listen.listen(5)
        self.port = self._listen.getsockname()[1]
        self._running = True

        def accept_loop():
            while self._running:
                try:
                    c, _ = self._listen.accept()
                except OSError:
                    return
                try:
                    c.sendall(b"SSH-2.0-TestServer\r\n")
                finally:
                    c.close()

        self._t = threading.Thread(target=accept_loop, daemon=True)
        self._t.start()
        time.sleep(0.05)

    def tearDown(self):
        self._running = False
        self._listen.close()

    def test_scan_detects_open_port(self):
        spec = f"{self.port - 1}-{self.port + 1}"
        res = port_scan.scan("127.0.0.1", ports=spec, timeout=1.0, workers=4)
        open_ports = [p["port"] for p in res["ports"]]
        self.assertIn(self.port, open_ports)
        # Per-address structure exists alongside flat list
        self.assertEqual(res["addresses"][0]["family"], "AF_INET")


if __name__ == "__main__":
    unittest.main()
