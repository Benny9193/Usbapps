"""Tests for lib.report mtime cache, delete, and purge."""
import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from tests import _path  # noqa: F401
from lib import report


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._real_results = report.RESULTS
        report.RESULTS = self.tmp
        report._HEADER_CACHE.clear()

    def tearDown(self):
        report.RESULTS = self._real_results
        report._HEADER_CACHE.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mk(self, sid, epoch):
        session = {
            "_id": sid,
            "_path": str(self.tmp / f"{sid}.json"),
            "target": sid,
            "scan_type": "scan",
            "created": "2026-01-01 00:00:00",
            "created_epoch": epoch,
        }
        report.save_session(session)
        return session

    def test_list_returns_newest_first(self):
        self._mk("a", 10)
        self._mk("b", 20)
        self._mk("c", 15)
        ids = [s["id"] for s in report.list_sessions()]
        self.assertEqual(ids, ["b", "c", "a"])

    def test_cache_population(self):
        self._mk("a", 10)
        report.list_sessions()
        self.assertEqual(len(report._HEADER_CACHE), 1)

    def test_mtime_invalidation(self):
        self._mk("a", 10)
        report.list_sessions()  # populate cache
        time.sleep(0.05)
        # Modify the file's JSON contents so mtime changes.
        with open(self.tmp / "a.json", "w") as fh:
            json.dump({"_id": "a", "target": "new-target", "scan_type": "scan",
                       "created_epoch": 999}, fh)
        sessions = report.list_sessions()
        a_entry = [s for s in sessions if s["id"] == "a"][0]
        self.assertEqual(a_entry["target"], "new-target")

    def test_delete_session(self):
        self._mk("a", 10)
        self._mk("b", 20)
        # Simulate a sibling artifact (e.g. nmap XML)
        (self.tmp / "a.nmap.xml").write_text("<nmaprun/>")
        removed = report.delete_session("a")
        self.assertEqual(len(removed), 2)  # JSON + XML
        self.assertFalse((self.tmp / "a.json").exists())
        self.assertFalse((self.tmp / "a.nmap.xml").exists())

    def test_purge(self):
        self._mk("old", 100)
        self._mk("new", 1000)
        count, ids = report.purge(500)
        self.assertEqual(count, 1)
        self.assertEqual(ids, ["old"])
        remaining = {s["id"] for s in report.list_sessions()}
        self.assertEqual(remaining, {"new"})


if __name__ == "__main__":
    unittest.main()
