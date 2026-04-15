"""Tests for recon.py CLI helpers (expand_targets, _has_error, config loader)."""
import tempfile
import unittest
from pathlib import Path

from tests import _path  # noqa: F401
import recon


class ExpandTargetsTests(unittest.TestCase):
    def test_single_host(self):
        self.assertEqual(recon.expand_targets("example.com"), ["example.com"])

    def test_single_ip(self):
        self.assertEqual(recon.expand_targets("127.0.0.1"), ["127.0.0.1"])

    def test_cidr(self):
        self.assertEqual(recon.expand_targets("10.0.0.0/30"), ["10.0.0.1", "10.0.0.2"])

    def test_comma_separated(self):
        self.assertEqual(
            recon.expand_targets("10.0.0.1,10.0.0.2,example.com"),
            ["10.0.0.1", "10.0.0.2", "example.com"],
        )

    def test_targets_file_with_comments(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# comment\n10.0.0.0/30\n\nexample.com # inline\n")
            tf = f.name
        try:
            result = recon.expand_targets(None, tf)
            self.assertEqual(result, ["10.0.0.1", "10.0.0.2", "example.com"])
        finally:
            Path(tf).unlink()

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            recon.expand_targets(None, None)


class HasErrorTests(unittest.TestCase):
    def test_direct_error(self):
        self.assertTrue(recon._has_error({"error": "boom"}))

    def test_nested_error(self):
        self.assertTrue(recon._has_error({"a": {"b": {"error": "boom"}}}))

    def test_in_list(self):
        self.assertTrue(recon._has_error({"x": [{"ok": 1}, {"error": "no"}]}))

    def test_clean(self):
        self.assertFalse(recon._has_error({"a": 1, "b": {"c": [1, 2, 3]}}))

    def test_empty_error_string_is_not_error(self):
        self.assertFalse(recon._has_error({"error": ""}))
        self.assertFalse(recon._has_error({"error": None}))


class ConfigLoaderTests(unittest.TestCase):
    def setUp(self):
        self._real = recon.CONFIG_PATH

    def tearDown(self):
        recon.CONFIG_PATH = self._real

    def test_missing_file_returns_empty(self):
        recon.CONFIG_PATH = Path("/nonexistent/nope.toml")
        self.assertEqual(recon._load_config(), {})

    def test_valid_toml_flattens_sections(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write('[scan]\nprofile = "quick"\n[dashboard]\nport = 9999\n')
            cfg = f.name
        try:
            recon.CONFIG_PATH = Path(cfg)
            d = recon._load_config()
            self.assertEqual(d.get("profile"), "quick")
            self.assertEqual(d.get("port"), 9999)
        finally:
            Path(cfg).unlink()


if __name__ == "__main__":
    unittest.main()
