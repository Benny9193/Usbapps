"""Tests for lib.differ and lib.exporters."""
import shutil
import tempfile
import unittest
from pathlib import Path

from tests import _path  # noqa: F401
from lib import differ, exporters, report


_BASE = {
    "_id": "a_scan_x",
    "target": "example.com",
    "scan_type": "scan",
    "created": "2026-04-01 00:00:00",
    "created_epoch": 1700000000,
}


class DifferTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._real = report.RESULTS
        report.RESULTS = self.tmp
        report._HEADER_CACHE.clear()

        self.a = dict(_BASE, _id="a_scan_x", _path=str(self.tmp / "a_scan_x.json"))
        self.a["port_scan"] = {
            "target": "example.com", "ip": "1.1.1.1",
            "ports": [
                {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "ip": "1.1.1.1"},
                {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "ip": "1.1.1.1"},
            ],
        }
        self.a["subdomains"] = {"found": [{"subdomain": "www.example.com", "ips": ["1.1.1.1"]}]}

        self.b = dict(_BASE, _id="b_scan_x", _path=str(self.tmp / "b_scan_x.json"),
                      created_epoch=1700086400)
        self.b["port_scan"] = {
            "target": "example.com", "ip": "1.1.1.1",
            "ports": [
                {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "ip": "1.1.1.1"},
                {"port": 8080, "protocol": "tcp", "state": "open", "service": "http-alt", "ip": "1.1.1.1"},
            ],
        }
        self.b["subdomains"] = {"found": [
            {"subdomain": "www.example.com", "ips": ["1.1.1.1"]},
            {"subdomain": "api.example.com", "ips": ["2.2.2.2"]},
        ]}

        report.save_session(self.a)
        report.save_session(self.b)

    def tearDown(self):
        report.RESULTS = self._real
        report._HEADER_CACHE.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_port_delta(self):
        d = differ.diff("a_scan_x", "b_scan_x")
        added_tups = {tuple(x) for x in d["ports"]["added"]}
        removed_tups = {tuple(x) for x in d["ports"]["removed"]}
        self.assertIn(("1.1.1.1", 8080, "tcp"), added_tups)
        self.assertIn(("1.1.1.1", 443, "tcp"), removed_tups)

    def test_subdomain_delta(self):
        d = differ.diff("a_scan_x", "b_scan_x")
        self.assertIn("api.example.com", d["subdomains"]["added"])
        self.assertEqual(d["subdomains"]["removed"], [])

    def test_target_mismatch_raises(self):
        self.b["target"] = "other.com"
        report.save_session(self.b)
        with self.assertRaises(ValueError):
            differ.diff("a_scan_x", "b_scan_x")


class ExporterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._real = report.RESULTS
        report.RESULTS = self.tmp
        report._HEADER_CACHE.clear()
        self.session = dict(_BASE, _path=str(self.tmp / "a_scan_x.json"))
        self.session["port_scan"] = {"target": "example.com", "ip": "1.1.1.1",
                                     "ports": [{"port": 80, "protocol": "tcp",
                                                "state": "open", "service": "http"}]}
        report.save_session(self.session)

    def tearDown(self):
        report.RESULTS = self._real
        report._HEADER_CACHE.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_markdown_has_title(self):
        md = exporters.to_markdown("a_scan_x")
        self.assertIn("# Recon: example.com", md)

    def test_html_is_self_contained(self):
        h = exporters.to_html("a_scan_x")
        self.assertIn("<title>Recon: example.com</title>", h)
        # Must not reference external assets.
        self.assertNotIn("http://", h)
        self.assertNotIn("https://", h)

    def test_csv_has_header(self):
        c = exporters.to_csv("a_scan_x")
        rows = c.splitlines()
        self.assertEqual(rows[0], "section,key,subkey,value")


if __name__ == "__main__":
    unittest.main()
