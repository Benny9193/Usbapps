"""Tests for lib.scheduler - interval parsing, persistence, auto-diff, runtime."""
import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from tests import _path  # noqa: F401
from lib import report, scheduler


class IntervalParsingTests(unittest.TestCase):
    def test_seconds(self):
        self.assertEqual(scheduler.parse_interval("30s"), 30)
        self.assertEqual(scheduler.parse_interval("30"), 30)

    def test_minutes(self):
        self.assertEqual(scheduler.parse_interval("5m"), 300)

    def test_hours(self):
        self.assertEqual(scheduler.parse_interval("2h"), 7200)

    def test_days(self):
        self.assertEqual(scheduler.parse_interval("1d"), 86400)

    def test_int_passthrough(self):
        self.assertEqual(scheduler.parse_interval(45), 45)

    def test_case_insensitive(self):
        self.assertEqual(scheduler.parse_interval("2H"), 7200)

    def test_rejects_zero(self):
        with self.assertRaises(ValueError):
            scheduler.parse_interval("0s")

    def test_rejects_negative_int(self):
        with self.assertRaises(ValueError):
            scheduler.parse_interval(-5)

    def test_rejects_garbage(self):
        with self.assertRaises(ValueError):
            scheduler.parse_interval("banana")

    def test_rejects_bool(self):
        with self.assertRaises(ValueError):
            scheduler.parse_interval(True)

    def test_rejects_none(self):
        with self.assertRaises(ValueError):
            scheduler.parse_interval(None)

    def test_format_interval(self):
        self.assertEqual(scheduler.format_interval(30), "30s")
        self.assertEqual(scheduler.format_interval(300), "5m")
        self.assertEqual(scheduler.format_interval(3600), "1h")
        self.assertEqual(scheduler.format_interval(86400), "1d")
        self.assertEqual(scheduler.format_interval(90), "90s")


class SchedulePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._real_path = scheduler.SCHEDULES_PATH
        scheduler.SCHEDULES_PATH = self.tmp / "schedules.json"

    def tearDown(self):
        scheduler.SCHEDULES_PATH = self._real_path
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_missing_file_returns_empty(self):
        self.assertEqual(scheduler.load_schedules(), [])

    def test_add_persists(self):
        entry = scheduler.add_schedule("example.com", "scan", "5m",
                                       options={"profile": "quick"})
        self.assertEqual(entry["target"], "example.com")
        self.assertEqual(entry["workflow"], "scan")
        self.assertEqual(entry["interval_seconds"], 300)
        self.assertEqual(entry["options"]["profile"], "quick")
        self.assertTrue(entry["enabled"])

        schedules = scheduler.load_schedules()
        self.assertEqual(len(schedules), 1)
        self.assertEqual(schedules[0]["id"], entry["id"])

    def test_id_disambiguation(self):
        a = scheduler.add_schedule("example.com", "scan", "5m")
        b = scheduler.add_schedule("example.com", "scan", "10m")
        self.assertNotEqual(a["id"], b["id"])

    def test_add_rejects_unknown_workflow(self):
        with self.assertRaises(ValueError):
            scheduler.add_schedule("example.com", "bogus", "5m")

    def test_add_rejects_empty_target(self):
        with self.assertRaises(ValueError):
            scheduler.add_schedule("", "scan", "5m")

    def test_remove(self):
        e = scheduler.add_schedule("example.com", "scan", "5m")
        self.assertTrue(scheduler.remove_schedule(e["id"]))
        self.assertEqual(scheduler.load_schedules(), [])
        # Second removal should be a no-op.
        self.assertFalse(scheduler.remove_schedule(e["id"]))

    def test_set_enabled(self):
        e = scheduler.add_schedule("example.com", "scan", "5m")
        self.assertTrue(scheduler.set_enabled(e["id"], False))
        self.assertFalse(scheduler.load_schedules()[0]["enabled"])
        self.assertTrue(scheduler.set_enabled(e["id"], True))
        self.assertTrue(scheduler.load_schedules()[0]["enabled"])
        self.assertFalse(scheduler.set_enabled("no-such-id", True))

    def test_corrupt_file_returns_empty(self):
        scheduler.SCHEDULES_PATH.parent.mkdir(parents=True, exist_ok=True)
        scheduler.SCHEDULES_PATH.write_text("{not json", encoding="utf-8")
        self.assertEqual(scheduler.load_schedules(), [])

    def test_legacy_list_format_accepted(self):
        scheduler.SCHEDULES_PATH.parent.mkdir(parents=True, exist_ok=True)
        scheduler.SCHEDULES_PATH.write_text(
            '[{"id": "x", "target": "example.com", "workflow": "scan", '
            '"interval_seconds": 60}]', encoding="utf-8")
        schedules = scheduler.load_schedules()
        self.assertEqual(len(schedules), 1)
        self.assertEqual(schedules[0]["id"], "x")


class AutoDiffTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._real_results = report.RESULTS
        report.RESULTS = self.tmp
        report._HEADER_CACHE.clear()

    def tearDown(self):
        report.RESULTS = self._real_results
        report._HEADER_CACHE.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mk_scan(self, sid, target, ports, epoch):
        session = {
            "_id": sid,
            "_path": str(self.tmp / f"{sid}.json"),
            "target": target,
            "scan_type": "scan",
            "created": "2026-01-01 00:00:00",
            "created_epoch": epoch,
            "port_scan": {
                "target": target,
                "ip": "1.1.1.1",
                "ports": [
                    {"port": p, "protocol": "tcp", "state": "open",
                     "service": "?", "ip": "1.1.1.1"}
                    for p in ports
                ],
            },
        }
        report.save_session(session)
        return session

    def test_auto_diff_returns_none_without_history(self):
        session = self._mk_scan("only_scan_x", "example.com", [80], 10)
        result = scheduler.auto_diff(session)
        self.assertIsNone(result)
        self.assertNotIn("diff_against_previous", session)

    def test_auto_diff_picks_prior_session(self):
        self._mk_scan("a_scan_x", "example.com", [80, 443], 10)
        new = self._mk_scan("b_scan_x", "example.com", [80, 8080], 20)
        result = scheduler.auto_diff(new)
        self.assertIsNotNone(result)
        added_ports = {tuple(x)[1] for x in result["ports"]["added"]}
        removed_ports = {tuple(x)[1] for x in result["ports"]["removed"]}
        self.assertIn(8080, added_ports)
        self.assertIn(443, removed_ports)
        self.assertEqual(new["diff_against_previous"], result)

    def test_auto_diff_skips_diff_sessions(self):
        # Prior session is a "diff" type; auto_diff should fall back to real scan.
        self._mk_scan("base_scan_x", "example.com", [80], 5)
        diff_session = {
            "_id": "mid_diff_x",
            "_path": str(self.tmp / "mid_diff_x.json"),
            "target": "example.com",
            "scan_type": "diff",
            "created_epoch": 15,
            "diff": {},
        }
        report.save_session(diff_session)
        new = self._mk_scan("later_scan_x", "example.com", [80, 22], 20)
        result = scheduler.auto_diff(new)
        self.assertIsNotNone(result)
        # The diff should compare against base_scan_x, not mid_diff_x.
        added = {tuple(x)[1] for x in result["ports"]["added"]}
        self.assertIn(22, added)

    def test_auto_diff_skips_other_targets(self):
        self._mk_scan("a_scan_x", "other.com", [80], 10)
        new = self._mk_scan("b_scan_x", "example.com", [80], 20)
        self.assertIsNone(scheduler.auto_diff(new))


class RunOnceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._real_results = report.RESULTS
        self._real_sched_path = scheduler.SCHEDULES_PATH
        report.RESULTS = self.tmp
        report._HEADER_CACHE.clear()
        scheduler.SCHEDULES_PATH = self.tmp / "schedules.json"

        # Replace the scan executor with a stub so the test doesn't need
        # a network stack or Nmap binary.
        self._real_scan_exec = scheduler.EXECUTORS["scan"]

        def fake_scan(session, target, opts):
            session["port_scan"] = {
                "target": target,
                "ip": "127.0.0.1",
                "ports": [
                    {"port": 80, "protocol": "tcp", "state": "open",
                     "service": "http", "ip": "127.0.0.1"},
                ],
            }

        scheduler.EXECUTORS["scan"] = fake_scan

    def tearDown(self):
        scheduler.EXECUTORS["scan"] = self._real_scan_exec
        report.RESULTS = self._real_results
        scheduler.SCHEDULES_PATH = self._real_sched_path
        report._HEADER_CACHE.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_run_once_creates_session_and_updates_entry(self):
        entry = scheduler.add_schedule("example.com", "scan", "1h")
        session = scheduler.run_once(entry)
        self.assertIsNotNone(session)
        self.assertEqual(session["target"], "example.com")
        self.assertIn("port_scan", session)
        self.assertEqual(session["scheduled"]["schedule_id"], entry["id"])

        # Entry metadata must be updated on disk.
        stored = scheduler.get_schedule(entry["id"])
        self.assertEqual(stored["run_count"], 1)
        self.assertIsNotNone(stored["last_session_id"])
        # No previous session existed; status is "ok", not "changed".
        self.assertEqual(stored["last_status"], "ok")

    def test_second_run_produces_auto_diff(self):
        entry = scheduler.add_schedule("example.com", "scan", "1h")
        scheduler.run_once(entry)

        # Mutate the fake so the second run reports a different port set.
        def fake_scan_changed(session, target, opts):
            session["port_scan"] = {
                "target": target,
                "ip": "127.0.0.1",
                "ports": [
                    {"port": 443, "protocol": "tcp", "state": "open",
                     "service": "https", "ip": "127.0.0.1"},
                ],
            }

        scheduler.EXECUTORS["scan"] = fake_scan_changed
        second = scheduler.run_once(scheduler.get_schedule(entry["id"]))
        self.assertIn("diff_against_previous", second)
        diff = second["diff_against_previous"]
        added = {tuple(x)[1] for x in diff["ports"]["added"]}
        removed = {tuple(x)[1] for x in diff["ports"]["removed"]}
        self.assertIn(443, added)
        self.assertIn(80, removed)

        stored = scheduler.get_schedule(entry["id"])
        self.assertEqual(stored["run_count"], 2)
        self.assertEqual(stored["last_status"], "changed")

    def test_unchanged_run_marks_unchanged(self):
        entry = scheduler.add_schedule("example.com", "scan", "1h")
        scheduler.run_once(entry)
        scheduler.run_once(scheduler.get_schedule(entry["id"]))
        stored = scheduler.get_schedule(entry["id"])
        self.assertEqual(stored["last_status"], "unchanged")

    def test_unknown_workflow_returns_none(self):
        # Manually craft an entry with a broken workflow.
        bad = {"id": "bad", "target": "x", "workflow": "bogus",
               "interval_seconds": 60}
        self.assertIsNone(scheduler.run_once(bad))


class SchedulerThreadTests(unittest.TestCase):
    """Exercise the Scheduler thread against a fast in-memory executor."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._real_results = report.RESULTS
        self._real_sched_path = scheduler.SCHEDULES_PATH
        report.RESULTS = self.tmp
        report._HEADER_CACHE.clear()
        scheduler.SCHEDULES_PATH = self.tmp / "schedules.json"

        self._real_scan_exec = scheduler.EXECUTORS["scan"]
        self.calls = []

        def fake_scan(session, target, opts):
            self.calls.append(target)
            session["port_scan"] = {"target": target, "ip": "127.0.0.1",
                                    "ports": []}

        scheduler.EXECUTORS["scan"] = fake_scan

    def tearDown(self):
        scheduler.EXECUTORS["scan"] = self._real_scan_exec
        report.RESULTS = self._real_results
        scheduler.SCHEDULES_PATH = self._real_sched_path
        report._HEADER_CACHE.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_thread_fires_then_stops(self):
        # A 1-second interval so the first fire happens fast.
        scheduler.add_schedule("example.com", "scan", "1s")
        sch = scheduler.Scheduler()
        sch.start()
        try:
            deadline = time.time() + 5.0
            while time.time() < deadline and not self.calls:
                time.sleep(0.1)
            self.assertTrue(self.calls, "scheduler should have fired at least once")
        finally:
            sch.stop(timeout=2.0)
        self.assertFalse(sch.is_running())

    def test_disabled_entry_is_skipped(self):
        scheduler.add_schedule("example.com", "scan", "1s", enabled=False)
        sch = scheduler.Scheduler()
        sch.start()
        try:
            time.sleep(1.5)
        finally:
            sch.stop(timeout=2.0)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
