"""Tests for lib.subdomain wildcard filtering."""
import os
import tempfile
import unittest

from tests import _path  # noqa: F401
from lib import dns_tools, subdomain


class SubdomainEnumTests(unittest.TestCase):
    def setUp(self):
        self._real_query = dns_tools.query
        self.real_names = {
            "mail.example.test": ["1.1.1.1"],
            "www.example.test": ["2.2.2.2"],
        }

        def fake_query(qname, qtype="A", server=None, timeout=3):
            if qtype != "A":
                return {"answers": []}
            if qname in self.real_names:
                return {"answers": [{"name": qname, "type": "A", "value": ip, "ttl": 60}
                                    for ip in self.real_names[qname]]}
            # Wildcard zone: anything else under the domain resolves to 9.9.9.9
            if qname.endswith(".example.test"):
                return {"answers": [{"name": qname, "type": "A", "value": "9.9.9.9", "ttl": 60}]}
            return {"answers": []}

        dns_tools.query = fake_query

        self._fd, self._wordlist = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(self._fd, "w") as fh:
            fh.write("mail\nwww\nfoo\nbar\nbaz\n")

    def tearDown(self):
        dns_tools.query = self._real_query
        os.unlink(self._wordlist)

    def test_wildcard_entries_are_filtered(self):
        wc = dns_tools.detect_wildcard("example.test")
        self.assertTrue(wc["is_wildcard"])
        res = subdomain.enumerate("example.test", self._wordlist, wildcard=wc)
        names = {f["subdomain"] for f in res["found"]}
        self.assertEqual(names, {"mail.example.test", "www.example.test"})
        self.assertEqual(res["wildcard"]["filtered_out"], 3)

    def test_enumerate_auto_detects_wildcard_when_not_passed(self):
        res = subdomain.enumerate("example.test", self._wordlist)
        # Even without a pre-computed wildcard dict, foo/bar/baz should be filtered.
        names = {f["subdomain"] for f in res["found"]}
        self.assertEqual(names, {"mail.example.test", "www.example.test"})


if __name__ == "__main__":
    unittest.main()
