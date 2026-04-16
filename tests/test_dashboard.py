"""Tests for lib.dashboard URL whitelist, path normalization, and auth token."""
import os
import threading
import time
import unittest
import unittest.mock as mock
import urllib.error
import urllib.request

from tests import _path  # noqa: F401
from lib import dashboard, report


class NormalizeTests(unittest.TestCase):
    def test_root(self):
        self.assertEqual(dashboard._normalize("/"), "/")

    def test_dashboard_asset(self):
        self.assertEqual(dashboard._normalize("/dashboard/index.html"), "/dashboard/index.html")

    def test_strips_query_string(self):
        self.assertEqual(dashboard._normalize("/results/x.json?t=1"), "/results/x.json")

    def test_traversal_collapses(self):
        # posixpath.normpath resolves the `..` inside the string; the gate
        # then rejects because it's no longer in /results/ or /dashboard/.
        n = dashboard._normalize("/results/../lib/foo.py")
        self.assertEqual(n, "/lib/foo.py")
        self.assertFalse(dashboard._is_allowed(n))

    def test_nul_byte_rejected(self):
        self.assertIsNone(dashboard._normalize("/dashboard/\x00evil"))

    def test_backslash_rejected(self):
        self.assertIsNone(dashboard._normalize("/dashboard\\foo"))


class IsAllowedTests(unittest.TestCase):
    def test_allowed(self):
        for p in ("/", "/dashboard/", "/dashboard/app.js",
                  "/results/", "/results/index.json",
                  "/config/schedules.json"):
            self.assertTrue(dashboard._is_allowed(p), p)

    def test_blocked(self):
        for p in ("/lib/dns_tools.py", "/recon.py", "/.gitignore",
                  "/config/recon.toml", "/config/", "/config",
                  "/config/wordlists/subdomains.txt",
                  "/bin/nmap", "/.git/HEAD"):
            self.assertFalse(dashboard._is_allowed(p), p)


class ServingTests(unittest.TestCase):
    """End-to-end test: start the server on an ephemeral port and poke it."""

    @classmethod
    def setUpClass(cls):
        report.update_index()
        cls.server = dashboard._Server(("127.0.0.1", 0), dashboard._Handler)
        cls.server.auth_token = None
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _fetch(self, path, headers=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}",
                                     headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=2) as r:
                return r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers) if e.headers else {}

    def test_root_served(self):
        st, h = self._fetch("/")
        self.assertEqual(st, 200)
        self.assertIn("Content-Security-Policy", h)

    def test_lib_blocked(self):
        st, _ = self._fetch("/lib/dns_tools.py")
        self.assertEqual(st, 404)

    def test_results_index_served(self):
        st, _ = self._fetch("/results/index.json")
        self.assertEqual(st, 200)


class AuthTests(unittest.TestCase):
    TOKEN = "unit-test-token-zzz"

    @classmethod
    def setUpClass(cls):
        report.update_index()
        cls.server = dashboard._Server(("127.0.0.1", 0), dashboard._Handler)
        cls.server.auth_token = cls.TOKEN
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _fetch(self, path, headers=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}",
                                     headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=2) as r:
                return r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers) if e.headers else {}

    def test_no_auth_returns_401(self):
        st, h = self._fetch("/")
        self.assertEqual(st, 401)
        self.assertIn("WWW-Authenticate", h)

    def test_bearer_header_ok(self):
        st, _ = self._fetch("/", headers={"Authorization": f"Bearer {self.TOKEN}"})
        self.assertEqual(st, 200)

    def test_query_param_sets_cookie(self):
        st, h = self._fetch(f"/?token={self.TOKEN}")
        self.assertEqual(st, 200)
        self.assertIn("Set-Cookie", h)
        self.assertIn("recon_token=", h["Set-Cookie"])

    def test_cookie_alone_ok(self):
        st, _ = self._fetch("/", headers={"Cookie": f"recon_token={self.TOKEN}"})
        self.assertEqual(st, 200)


class SafeOpenAndroidTests(unittest.TestCase):
    """_safe_open must shell out via RECON_ANDROID_OPEN on Android (Termux)."""

    def setUp(self):
        self._orig = os.environ.get("RECON_ANDROID_OPEN")

    def tearDown(self):
        if self._orig is None:
            os.environ.pop("RECON_ANDROID_OPEN", None)
        else:
            os.environ["RECON_ANDROID_OPEN"] = self._orig

    def test_uses_termux_open_url_when_set(self):
        os.environ["RECON_ANDROID_OPEN"] = "termux-open-url"
        with mock.patch.object(dashboard.shutil, "which", return_value="/usr/bin/termux-open-url"), \
             mock.patch.object(dashboard.subprocess, "Popen") as popen, \
             mock.patch.object(dashboard.webbrowser, "open") as wb_open:
            dashboard._safe_open("http://127.0.0.1:8787/")
            popen.assert_called_once()
            args = popen.call_args[0][0]
            self.assertEqual(args, ["termux-open-url", "http://127.0.0.1:8787/"])
            wb_open.assert_not_called()

    def test_falls_back_when_opener_missing(self):
        os.environ["RECON_ANDROID_OPEN"] = "termux-open-url"
        with mock.patch.object(dashboard.shutil, "which", return_value=None), \
             mock.patch.object(dashboard.webbrowser, "open") as wb_open:
            dashboard._safe_open("http://127.0.0.1:8787/")
            wb_open.assert_called_once_with("http://127.0.0.1:8787/")

    def test_falls_back_when_env_not_set(self):
        os.environ.pop("RECON_ANDROID_OPEN", None)
        with mock.patch.object(dashboard.webbrowser, "open") as wb_open:
            dashboard._safe_open("http://127.0.0.1:8787/")
            wb_open.assert_called_once_with("http://127.0.0.1:8787/")


if __name__ == "__main__":
    unittest.main()
