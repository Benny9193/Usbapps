"""Tests for lib.dns_tools (wire-format parser, EDNS0, TCP fallback, wildcard,
AAAA RFC 5952, DMARC/SPF).
"""
import struct
import unittest

from tests import _path  # noqa: F401 - path fix
from lib import dns_tools


class EncodeTests(unittest.TestCase):
    def test_opt_rr_is_11_bytes(self):
        opt = dns_tools._encode_opt_rr()
        self.assertEqual(len(opt), 11)
        # root name (0), type=41, class=4096, ttl=0, rdlen=0
        self.assertEqual(opt[0], 0)
        self.assertEqual(opt[1:3], b"\x00\x29")  # type 41

    def test_build_query_sets_arcount(self):
        _, pkt = dns_tools._build_query("example.com", dns_tools.RR_TYPES["A"])
        arcount = struct.unpack(">H", pkt[10:12])[0]
        self.assertEqual(arcount, 1)

    def test_build_query_without_edns(self):
        _, pkt = dns_tools._build_query("example.com", dns_tools.RR_TYPES["A"], use_edns=False)
        arcount = struct.unpack(">H", pkt[10:12])[0]
        self.assertEqual(arcount, 0)


class ParseResponseTests(unittest.TestCase):
    def _header(self, flags):
        return struct.pack(">HHHHHH", 0x1234, flags, 0, 0, 0, 0)

    def test_short_packet_returns_error_structure(self):
        r = dns_tools._parse_response(b"\x00\x00")
        self.assertEqual(r["answers"], [])
        self.assertFalse(r["tc"])

    def test_tc_flag_exposed(self):
        flags = 0x8300  # response, authoritative, TC set
        r = dns_tools._parse_response(self._header(flags))
        self.assertTrue(r["tc"])
        self.assertEqual(r["rcode"], 0)

    def test_ad_flag_exposed(self):
        flags = 0x8020  # response, AD set
        r = dns_tools._parse_response(self._header(flags))
        self.assertTrue(r["ad"])

    def test_rcode_mask(self):
        flags = 0x8003  # NXDOMAIN
        r = dns_tools._parse_response(self._header(flags))
        self.assertEqual(r["rcode"], 3)


class RdataParseTests(unittest.TestCase):
    def test_a_record(self):
        raw = bytes([8, 8, 8, 8])
        v = dns_tools._parse_rdata(1, raw, 0, 4)
        self.assertEqual(v, "8.8.8.8")

    def test_aaaa_record_rfc5952(self):
        raw = bytes.fromhex("20010db8000000000000000000000001")
        v = dns_tools._parse_rdata(28, raw, 0, 16)
        self.assertEqual(v, "2001:db8::1")

    def test_aaaa_localhost(self):
        raw = bytes.fromhex("00000000000000000000000000000001")
        v = dns_tools._parse_rdata(28, raw, 0, 16)
        self.assertEqual(v, "::1")


class WildcardDetectionTests(unittest.TestCase):
    def test_wildcard_detected_when_random_labels_resolve(self):
        def fake_query(qname, qtype="A", server=None, timeout=3):
            # Every random label resolves to 9.9.9.9 => wildcard
            if qtype == "A":
                return {"answers": [{"name": qname, "type": "A", "value": "9.9.9.9", "ttl": 60}]}
            return {"answers": []}
        saved = dns_tools.query
        dns_tools.query = fake_query
        try:
            wc = dns_tools.detect_wildcard("example.test")
            self.assertTrue(wc["is_wildcard"])
            self.assertEqual(wc["ips"], ["9.9.9.9"])
        finally:
            dns_tools.query = saved

    def test_wildcard_not_detected_for_nxdomain_zone(self):
        def fake_query(qname, qtype="A", server=None, timeout=3):
            return {"answers": []}
        saved = dns_tools.query
        dns_tools.query = fake_query
        try:
            wc = dns_tools.detect_wildcard("example.test")
            self.assertFalse(wc["is_wildcard"])
            self.assertEqual(wc["ips"], [])
        finally:
            dns_tools.query = saved


class EmailAuthTests(unittest.TestCase):
    def test_spf_from_txt_answers(self):
        txt = [{"name": "x", "type": "TXT", "value": "v=spf1 mx -all", "ttl": 1}]

        def fake_query(qname, qtype="A", server=None, timeout=3):
            return {"answers": []}

        saved = dns_tools.query
        dns_tools.query = fake_query
        try:
            ea = dns_tools.parse_email_auth("example.com", txt_answers=txt)
            self.assertEqual(ea["spf"]["mechanisms"], ["mx", "-all"])
            self.assertIsNone(ea["dmarc"])
        finally:
            dns_tools.query = saved

    def test_dmarc_parse(self):
        txt = []

        def fake_query(qname, qtype="A", server=None, timeout=3):
            if qname.startswith("_dmarc"):
                return {"answers": [{"name": qname, "type": "TXT",
                                     "value": "v=DMARC1; p=reject; rua=mailto:x@y.z",
                                     "ttl": 1}]}
            return {"answers": []}

        saved = dns_tools.query
        dns_tools.query = fake_query
        try:
            ea = dns_tools.parse_email_auth("example.com", txt_answers=txt)
            self.assertEqual(ea["dmarc"]["fields"]["p"], "reject")
            self.assertEqual(ea["dmarc"]["fields"]["rua"], "mailto:x@y.z")
        finally:
            dns_tools.query = saved


if __name__ == "__main__":
    unittest.main()
