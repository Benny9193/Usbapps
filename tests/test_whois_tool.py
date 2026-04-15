"""Tests for lib.whois_tool IP vs domain routing and referral chasing."""
import unittest

from tests import _path  # noqa: F401
from lib import whois_tool


class IsIpTests(unittest.TestCase):
    def test_ipv4(self):
        self.assertTrue(whois_tool._is_ip("8.8.8.8"))

    def test_ipv6(self):
        self.assertTrue(whois_tool._is_ip("2001:db8::1"))

    def test_domain(self):
        self.assertFalse(whois_tool._is_ip("example.com"))

    def test_ip_with_extra(self):
        self.assertFalse(whois_tool._is_ip("8.8.8.8.arpa"))


class LookupRoutingTests(unittest.TestCase):
    def setUp(self):
        self._real_query = whois_tool._query
        self.calls = []

        def fake(server, target, timeout=5):
            self.calls.append((server, target))
            if server == whois_tool.ARIN_WHOIS:
                return "OrgName: Google LLC\nReferralServer: whois://whois.apnic.net\n"
            if server == "whois.apnic.net":
                return "inetnum: 8.8.8.0 - 8.8.8.255\n"
            if server == "whois.verisign-grs.com":
                return "Registrar: Example Registrar\nRegistry Expiry Date: 2030-01-01T00:00:00Z\n"
            return ""

        whois_tool._query = fake

    def tearDown(self):
        whois_tool._query = self._real_query

    def test_ip_routes_to_arin_with_referral(self):
        res = whois_tool.lookup("8.8.8.8")
        self.assertEqual(res["server"], whois_tool.ARIN_WHOIS)
        servers_hit = {c[0] for c in self.calls}
        self.assertIn("whois.apnic.net", servers_hit)

    def test_domain_routes_to_known_server(self):
        res = whois_tool.lookup("example.com")
        self.assertEqual(res["server"], "whois.verisign-grs.com")
        self.assertIn("Registrar", res["fields"])


if __name__ == "__main__":
    unittest.main()
