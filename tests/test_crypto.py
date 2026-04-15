"""Tests for lib.crypto and the recon encrypt/decrypt CLI commands."""
import argparse
import logging
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from tests import _path  # noqa: F401
import recon
from lib import crypto, report

# The CLI tests deliberately exercise failure paths (wrong password,
# bad target, ...) which the production logger writes to stderr. Mute
# them so unittest output stays readable without losing real failures.
logging.getLogger("recon").setLevel(logging.CRITICAL)


class CryptoBytesTests(unittest.TestCase):
    """Round-trip and tamper-detection on the bytes API."""

    def test_round_trip_basic(self):
        pt = b"hello, recon"
        blob = crypto.encrypt(pt, "secret")
        self.assertEqual(crypto.decrypt(blob, "secret"), pt)

    def test_round_trip_empty(self):
        blob = crypto.encrypt(b"", "pw")
        self.assertEqual(crypto.decrypt(blob, "pw"), b"")

    def test_round_trip_large(self):
        pt = os.urandom(50_000)
        blob = crypto.encrypt(pt, "pw")
        self.assertEqual(crypto.decrypt(blob, "pw"), pt)

    def test_password_can_be_bytes(self):
        blob = crypto.encrypt(b"x", b"binary-pw")
        self.assertEqual(crypto.decrypt(blob, b"binary-pw"), b"x")

    def test_password_unicode(self):
        pw = "p\u00e4ssw\u00f6rt-\U0001F600"
        blob = crypto.encrypt(b"unicode test", pw)
        self.assertEqual(crypto.decrypt(blob, pw), b"unicode test")

    def test_blob_starts_with_magic_and_has_correct_layout(self):
        blob = crypto.encrypt(b"abc", "pw")
        self.assertTrue(blob.startswith(crypto.MAGIC))
        # 8 magic + 1 ver + 1 flags + 16 salt + 16 nonce + 3 ct + 32 tag = 77
        self.assertEqual(len(blob), len(crypto.MAGIC) + 1 + 1 + 16 + 16 + 3 + 32)
        self.assertEqual(blob[len(crypto.MAGIC)], crypto.VERSION)

    def test_two_encryptions_use_unique_nonces(self):
        # Same plaintext + same password must produce different blobs.
        a = crypto.encrypt(b"same", "pw")
        b = crypto.encrypt(b"same", "pw")
        self.assertNotEqual(a, b)
        self.assertEqual(crypto.decrypt(a, "pw"), b"same")
        self.assertEqual(crypto.decrypt(b, "pw"), b"same")

    def test_wrong_password_rejected(self):
        blob = crypto.encrypt(b"top secret", "right")
        with self.assertRaises(crypto.InvalidCiphertext):
            crypto.decrypt(blob, "wrong")

    def test_tampered_ciphertext_rejected(self):
        blob = bytearray(crypto.encrypt(b"top secret", "pw"))
        # Flip a byte in the ciphertext region (after the 42-byte header,
        # before the 32-byte tag).
        blob[50] ^= 0x01
        with self.assertRaises(crypto.InvalidCiphertext):
            crypto.decrypt(bytes(blob), "pw")

    def test_tampered_tag_rejected(self):
        blob = bytearray(crypto.encrypt(b"x", "pw"))
        blob[-1] ^= 0x01
        with self.assertRaises(crypto.InvalidCiphertext):
            crypto.decrypt(bytes(blob), "pw")

    def test_tampered_header_rejected(self):
        blob = bytearray(crypto.encrypt(b"x", "pw"))
        # Flip a salt byte - decryption derives different keys, so tag
        # verification must fail.
        blob[12] ^= 0x01
        with self.assertRaises(crypto.InvalidCiphertext):
            crypto.decrypt(bytes(blob), "pw")

    def test_truncated_blob_rejected(self):
        blob = crypto.encrypt(b"hello", "pw")
        with self.assertRaises(crypto.InvalidCiphertext):
            crypto.decrypt(blob[:10], "pw")
        with self.assertRaises(crypto.InvalidCiphertext):
            crypto.decrypt(b"", "pw")

    def test_bad_magic_rejected(self):
        with self.assertRaises(crypto.InvalidCiphertext):
            crypto.decrypt(b"NOT-RECON" + b"\x00" * 100, "pw")

    def test_unsupported_version_rejected(self):
        blob = bytearray(crypto.encrypt(b"x", "pw"))
        blob[len(crypto.MAGIC)] = 0xFF  # bogus version
        with self.assertRaises(crypto.InvalidCiphertext):
            crypto.decrypt(bytes(blob), "pw")

    def test_empty_password_rejected(self):
        with self.assertRaises(ValueError):
            crypto.encrypt(b"x", "")
        with self.assertRaises(ValueError):
            crypto.encrypt(b"x", b"")

    def test_password_type_validation(self):
        with self.assertRaises(TypeError):
            crypto.encrypt(b"x", 12345)  # type: ignore
        with self.assertRaises(TypeError):
            crypto.encrypt("not-bytes", "pw")  # type: ignore

    def test_is_encrypted_bytes(self):
        self.assertTrue(crypto.is_encrypted(crypto.encrypt(b"hi", "pw")))
        self.assertFalse(crypto.is_encrypted(b"plain text"))
        self.assertFalse(crypto.is_encrypted(b""))


class CryptoFileTests(unittest.TestCase):
    """File-based encrypt_file / decrypt_file helpers."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_file_round_trip(self):
        src = self.tmp / "session.json"
        src.write_bytes(b'{"target": "example.com", "ports": [22, 80]}')
        enc = self.tmp / "session.json.enc"
        crypto.encrypt_file(src, enc, "pw")
        self.assertTrue(enc.is_file())
        self.assertTrue(crypto.is_encrypted(enc))

        out = self.tmp / "session.dec.json"
        crypto.decrypt_file(enc, out, "pw")
        self.assertEqual(out.read_bytes(), src.read_bytes())

    def test_decrypt_failure_does_not_create_destination(self):
        src = self.tmp / "data.bin"
        src.write_bytes(b"plaintext")
        enc = self.tmp / "data.bin.enc"
        crypto.encrypt_file(src, enc, "right")

        dst = self.tmp / "should_not_exist"
        with self.assertRaises(crypto.InvalidCiphertext):
            crypto.decrypt_file(enc, dst, "wrong")
        self.assertFalse(dst.exists())
        # The transient .part file should also be cleaned up.
        self.assertFalse((dst.with_name(dst.name + ".part")).exists())

    def test_is_encrypted_path(self):
        src = self.tmp / "x.json"
        src.write_bytes(b"plain")
        self.assertFalse(crypto.is_encrypted(src))
        enc = self.tmp / "x.enc"
        crypto.encrypt_file(src, enc, "pw")
        self.assertTrue(crypto.is_encrypted(enc))
        self.assertFalse(crypto.is_encrypted(self.tmp / "missing"))


class ReconCliTests(unittest.TestCase):
    """End-to-end exercise of the encrypt/decrypt subcommands."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._real_results = report.RESULTS
        report.RESULTS = self.tmp
        report._HEADER_CACHE.clear()
        # Stash a session that looks like a real one.
        (self.tmp / "20260101-000000_scan_example.com.json").write_bytes(
            b'{"_id": "20260101-000000_scan_example.com", "target": "example.com"}'
        )
        # And a sibling artifact.
        (self.tmp / "20260101-000000_scan_example.com.nmap.xml").write_bytes(
            b"<nmaprun><host/></nmaprun>"
        )
        self.pwfile = self.tmp / "pw"
        self.pwfile.write_text("hunter2\n", encoding="utf-8")

    def tearDown(self):
        report.RESULTS = self._real_results
        report._HEADER_CACHE.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _args(self, **kwargs):
        defaults = dict(
            password_file=str(self.pwfile),
            output_dir=None,
            keep=False,
            targets=[],
            all=False,
            older_than_days=None,
        )
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_encrypt_then_decrypt_session_id(self):
        sid = "20260101-000000_scan_example.com"
        rc = recon.cmd_encrypt(self._args(targets=[sid]))
        self.assertEqual(rc, 0)
        # Both files should now be .enc and the plaintext gone.
        self.assertTrue((self.tmp / f"{sid}.json.enc").is_file())
        self.assertTrue((self.tmp / f"{sid}.nmap.xml.enc").is_file())
        self.assertFalse((self.tmp / f"{sid}.json").exists())
        self.assertFalse((self.tmp / f"{sid}.nmap.xml").exists())

        rc = recon.cmd_decrypt(self._args(targets=[sid]))
        self.assertEqual(rc, 0)
        self.assertTrue((self.tmp / f"{sid}.json").is_file())
        self.assertTrue((self.tmp / f"{sid}.nmap.xml").is_file())
        self.assertFalse((self.tmp / f"{sid}.json.enc").exists())
        self.assertEqual(
            (self.tmp / f"{sid}.json").read_bytes(),
            b'{"_id": "20260101-000000_scan_example.com", "target": "example.com"}',
        )

    def test_encrypt_keeps_plaintext_with_keep_flag(self):
        path = self.tmp / "20260101-000000_scan_example.com.json"
        rc = recon.cmd_encrypt(self._args(targets=[str(path)], keep=True))
        self.assertEqual(rc, 0)
        self.assertTrue(path.is_file())  # still there
        self.assertTrue((self.tmp / f"{path.name}.enc").is_file())

    def test_encrypt_skips_already_encrypted(self):
        path = self.tmp / "20260101-000000_scan_example.com.json"
        recon.cmd_encrypt(self._args(targets=[str(path)]))
        # Try to encrypt the .enc file directly - should be skipped.
        enc = self.tmp / f"{path.name}.enc"
        rc = recon.cmd_encrypt(self._args(targets=[str(enc)]))
        # Nothing was actually encrypted -> exit 2.
        self.assertEqual(rc, 2)

    def test_decrypt_wrong_password_returns_error(self):
        sid = "20260101-000000_scan_example.com"
        recon.cmd_encrypt(self._args(targets=[sid]))
        bad = self.tmp / "bad_pw"
        bad.write_text("wrong", encoding="utf-8")
        rc = recon.cmd_decrypt(self._args(targets=[sid], password_file=str(bad)))
        self.assertEqual(rc, 2)
        # Decrypted file must not exist.
        self.assertFalse((self.tmp / f"{sid}.json").exists())

    def test_unknown_target_returns_error(self):
        rc = recon.cmd_encrypt(self._args(targets=["not-a-real-session-id"]))
        self.assertEqual(rc, 2)

    def test_password_file_strips_single_trailing_newline(self):
        # Two trailing newlines -> the second one is part of the password.
        self.pwfile.write_text("pw\n\n", encoding="utf-8")
        sid = "20260101-000000_scan_example.com"
        recon.cmd_encrypt(self._args(targets=[sid]))
        # Decrypting with just "pw" must fail because the real password is "pw\n".
        with_pw = self.tmp / "just_pw"
        with_pw.write_text("pw", encoding="utf-8")
        rc = recon.cmd_decrypt(self._args(targets=[sid], password_file=str(with_pw)))
        self.assertEqual(rc, 2)
        # And the original (with trailing \n) must succeed.
        rc = recon.cmd_decrypt(self._args(targets=[sid]))
        self.assertEqual(rc, 0)

    def test_empty_password_file_rejected(self):
        self.pwfile.write_text("", encoding="utf-8")
        rc = recon.cmd_encrypt(
            self._args(targets=["20260101-000000_scan_example.com"])
        )
        self.assertEqual(rc, 2)


class BulkEncryptDecryptTests(unittest.TestCase):
    """Exercise --all and --older-than-days flag combinations."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._real_results = report.RESULTS
        report.RESULTS = self.tmp
        report._HEADER_CACHE.clear()
        # Three sessions across different epochs so --older-than-days N
        # has something to bite on. Filename timestamps are consistent
        # with the parsed created_epoch so list_sessions agrees with
        # the on-disk metadata.
        import time as _time
        self.sids = [
            ("20260415-100000_scan_a.com", "a.com"),
            ("20260410-100000_scan_b.com", "b.com"),
            ("20260101-100000_scan_c.com", "c.com"),
        ]
        for sid, target in self.sids:
            epoch = int(_time.mktime(_time.strptime(sid.split("_")[0], "%Y%m%d-%H%M%S")))
            sess = {
                "_id": sid,
                "_path": str(self.tmp / f"{sid}.json"),
                "target": target,
                "scan_type": "scan",
                "created": _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(epoch)),
                "created_epoch": epoch,
            }
            report.save_session(sess)
        self.pwfile = self.tmp / "pw"
        self.pwfile.write_text("hunter2\n", encoding="utf-8")

    def tearDown(self):
        report.RESULTS = self._real_results
        report._HEADER_CACHE.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _args(self, **kwargs):
        defaults = dict(
            password_file=str(self.pwfile),
            output_dir=None,
            keep=False,
            targets=[],
            all=False,
            older_than_days=None,
        )
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def _enc_files(self):
        return sorted(p.name for p in self.tmp.glob("*.json.enc"))

    def _plain_files(self):
        return sorted(p.name for p in self.tmp.glob("*.json"))

    def test_encrypt_all(self):
        rc = recon.cmd_encrypt(self._args(all=True))
        self.assertEqual(rc, 0)
        self.assertEqual(len(self._enc_files()), 3)
        # No leftover plaintext (index.json doesn't match *.json glob alone)
        plain = [n for n in self._plain_files() if not n.endswith(".enc")]
        self.assertEqual(plain, ["index.json"])

    def test_encrypt_older_than_days(self):
        # Use an enormous cutoff anchored to the test wall clock so only
        # the genuinely-stale entry (epoch in 2026-01-01) is matched.
        # Anchor: now is at least 2026-04 -> 100 days easily covers c.com.
        import time as _time
        days = (int(_time.time()) - int(_time.mktime(_time.strptime(
            "20260105-000000", "%Y%m%d-%H%M%S")))) // 86400
        rc = recon.cmd_encrypt(self._args(older_than_days=days))
        self.assertEqual(rc, 0)
        # Only c.com should have been encrypted.
        self.assertEqual(self._enc_files(), ["20260101-100000_scan_c.com.json.enc"])

    def test_encrypt_all_and_targets_rejected(self):
        rc = recon.cmd_encrypt(self._args(all=True, targets=["foo"]))
        self.assertEqual(rc, 2)

    def test_encrypt_no_selection_rejected(self):
        # Neither --all nor --older-than-days nor explicit targets.
        rc = recon.cmd_encrypt(self._args())
        self.assertEqual(rc, 2)

    def test_decrypt_all_round_trip(self):
        recon.cmd_encrypt(self._args(all=True))
        rc = recon.cmd_decrypt(self._args(all=True))
        self.assertEqual(rc, 0)
        self.assertEqual(self._enc_files(), [])
        # All three sessions back as plaintext.
        plain = [n for n in self._plain_files()
                 if n != "index.json" and not n.endswith(".enc")]
        self.assertEqual(len(plain), 3)

    def test_encrypt_all_with_no_plaintext_returns_zero(self):
        # Encrypt everything, then run --all again - nothing left to do.
        recon.cmd_encrypt(self._args(all=True))
        rc = recon.cmd_encrypt(self._args(all=True))
        self.assertEqual(rc, 0)


class RekeyTests(unittest.TestCase):
    """recon rekey: in-memory password rotation."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._real_results = report.RESULTS
        report.RESULTS = self.tmp
        report._HEADER_CACHE.clear()
        # Encrypt one fresh session with the old password.
        self.sid = "20260101-000000_scan_example.com"
        plain = (self.tmp / f"{self.sid}.json")
        plain.write_bytes(
            b'{"_id": "20260101-000000_scan_example.com", "target": "example.com"}'
        )
        self.old_pw = self.tmp / "old"
        self.old_pw.write_text("oldpw", encoding="utf-8")
        self.new_pw = self.tmp / "new"
        self.new_pw.write_text("newpw", encoding="utf-8")
        # Encrypt via the bytes API directly (bypasses the CLI for setup).
        crypto.encrypt_file(plain, self.tmp / f"{self.sid}.json.enc", "oldpw")
        plain.unlink()

    def tearDown(self):
        report.RESULTS = self._real_results
        report._HEADER_CACHE.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _args(self, **kwargs):
        defaults = dict(
            old_password_file=str(self.old_pw),
            new_password_file=str(self.new_pw),
            targets=[self.sid],
            all=False,
            older_than_days=None,
        )
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def _enc_path(self):
        return self.tmp / f"{self.sid}.json.enc"

    def test_rekey_rotates_password(self):
        rc = recon.cmd_rekey(self._args())
        self.assertEqual(rc, 0)
        # New password works.
        plaintext = crypto.decrypt(self._enc_path().read_bytes(), "newpw")
        self.assertIn(b"example.com", plaintext)
        # Old password no longer works.
        with self.assertRaises(crypto.InvalidCiphertext):
            crypto.decrypt(self._enc_path().read_bytes(), "oldpw")

    def test_rekey_wrong_old_password_leaves_file_untouched(self):
        bogus = self.tmp / "bogus"
        bogus.write_text("nope", encoding="utf-8")
        before = self._enc_path().read_bytes()
        rc = recon.cmd_rekey(self._args(old_password_file=str(bogus)))
        self.assertEqual(rc, 2)
        self.assertEqual(self._enc_path().read_bytes(), before)
        # Original password still works.
        crypto.decrypt(self._enc_path().read_bytes(), "oldpw")

    def test_rekey_identical_passwords_rejected(self):
        rc = recon.cmd_rekey(self._args(new_password_file=str(self.old_pw)))
        self.assertEqual(rc, 2)

    def test_rekey_all_flag(self):
        # Add a second encrypted session.
        sid2 = "20260102-000000_scan_other.com"
        plain2 = self.tmp / f"{sid2}.json"
        plain2.write_bytes(b'{"_id": "20260102-000000_scan_other.com", "target": "other.com"}')
        crypto.encrypt_file(plain2, self.tmp / f"{sid2}.json.enc", "oldpw")
        plain2.unlink()
        rc = recon.cmd_rekey(self._args(all=True, targets=[]))
        self.assertEqual(rc, 0)
        # Both files now decrypt with newpw.
        for sid in (self.sid, sid2):
            crypto.decrypt((self.tmp / f"{sid}.json.enc").read_bytes(), "newpw")


class EncryptedListingTests(unittest.TestCase):
    """report.list_sessions surfaces encrypted entries via filename parsing."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._real_results = report.RESULTS
        report.RESULTS = self.tmp
        report._HEADER_CACHE.clear()

    def tearDown(self):
        report.RESULTS = self._real_results
        report._HEADER_CACHE.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_lists_encrypted_session(self):
        # Drop a `.json.enc` file with a real recon-encrypted body and
        # the canonical filename pattern.
        sid = "20260415-094812_full_example.com"
        crypto_blob = crypto.encrypt(b'{"_id": "x"}', "pw")
        (self.tmp / f"{sid}.json.enc").write_bytes(crypto_blob)
        sessions = report.list_sessions()
        self.assertEqual(len(sessions), 1)
        entry = sessions[0]
        self.assertEqual(entry["id"], sid)
        self.assertEqual(entry["target"], "example.com")
        self.assertEqual(entry["scan_type"], "full")
        self.assertTrue(entry["encrypted"])
        self.assertGreater(entry["created_epoch"], 0)

    def test_lists_mixed_plaintext_and_encrypted(self):
        # Plaintext for a.com, encrypted for b.com.
        a = self.tmp / "20260415-100000_scan_a.com.json"
        a.write_bytes(b'{"_id": "20260415-100000_scan_a.com", "target": "a.com", "scan_type": "scan", "created_epoch": 1}')
        b_blob = crypto.encrypt(b"x", "pw")
        (self.tmp / "20260410-100000_scan_b.com.json.enc").write_bytes(b_blob)
        sessions = report.list_sessions()
        ids = sorted(s["id"] for s in sessions)
        self.assertEqual(ids, ["20260410-100000_scan_b.com", "20260415-100000_scan_a.com"])
        for s in sessions:
            if s["id"].endswith("a.com"):
                self.assertFalse(s["encrypted"])
            else:
                self.assertTrue(s["encrypted"])

    def test_plaintext_wins_when_both_variants_present(self):
        sid = "20260415-100000_scan_dup.com"
        # Plaintext.
        (self.tmp / f"{sid}.json").write_bytes(
            b'{"_id": "20260415-100000_scan_dup.com", "target": "dup.com", "scan_type": "scan", "created_epoch": 1}'
        )
        # Encrypted sibling for the same id.
        (self.tmp / f"{sid}.json.enc").write_bytes(crypto.encrypt(b"x", "pw"))
        sessions = report.list_sessions()
        self.assertEqual(len(sessions), 1)
        self.assertFalse(sessions[0]["encrypted"])


class AutoEncryptSaveTests(unittest.TestCase):
    """report.save_session learns to encrypt at write-time."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._real_results = report.RESULTS
        report.RESULTS = self.tmp
        report._HEADER_CACHE.clear()

    def tearDown(self):
        report.RESULTS = self._real_results
        report._HEADER_CACHE.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_save_with_password_writes_encrypted_only(self):
        sess = {
            "_id": "20260415-100000_scan_x.com",
            "_path": str(self.tmp / "20260415-100000_scan_x.com.json"),
            "target": "x.com",
            "scan_type": "scan",
            "created_epoch": 1,
            "data": [1, 2, 3],
        }
        report.save_session(sess, encrypt_password="pw")
        # The plaintext path must NOT exist; only the .enc file.
        self.assertFalse(Path(sess["_path"]).exists())
        enc = Path(sess["_path"] + crypto.EXTENSION)
        self.assertTrue(enc.is_file())
        self.assertTrue(crypto.is_encrypted(enc))
        # Round-trip: decrypted bytes parse back to our session.
        import json as _json
        round_tripped = _json.loads(crypto.decrypt(enc.read_bytes(), "pw").decode("utf-8"))
        self.assertEqual(round_tripped["target"], "x.com")
        self.assertEqual(round_tripped["data"], [1, 2, 3])

    def test_save_with_password_removes_stale_plaintext(self):
        sess = {
            "_id": "20260415-100000_scan_y.com",
            "_path": str(self.tmp / "20260415-100000_scan_y.com.json"),
            "target": "y.com",
            "scan_type": "scan",
            "created_epoch": 1,
        }
        # Pre-existing plaintext from an earlier unencrypted save.
        report.save_session(sess)
        self.assertTrue(Path(sess["_path"]).exists())
        # Now save again with a password - the plaintext should disappear.
        report.save_session(sess, encrypt_password="pw")
        self.assertFalse(Path(sess["_path"]).exists())
        self.assertTrue(Path(sess["_path"] + crypto.EXTENSION).is_file())

    def test_load_session_decrypts_with_env_password(self):
        sess = {
            "_id": "20260415-100000_scan_z.com",
            "_path": str(self.tmp / "20260415-100000_scan_z.com.json"),
            "target": "z.com",
            "scan_type": "scan",
            "created_epoch": 1,
        }
        report.save_session(sess, encrypt_password="env-pw")
        # Explicit password kwarg.
        loaded = report.load_session(sess["_id"], password="env-pw")
        self.assertEqual(loaded["target"], "z.com")
        # Env var.
        old = os.environ.get("RECON_PASSWORD")
        os.environ["RECON_PASSWORD"] = "env-pw"
        try:
            loaded2 = report.load_session(sess["_id"])
            self.assertEqual(loaded2["target"], "z.com")
        finally:
            if old is None:
                os.environ.pop("RECON_PASSWORD", None)
            else:
                os.environ["RECON_PASSWORD"] = old

    def test_load_session_missing_password_raises(self):
        sess = {
            "_id": "20260415-100000_scan_q.com",
            "_path": str(self.tmp / "20260415-100000_scan_q.com.json"),
            "target": "q.com",
            "scan_type": "scan",
            "created_epoch": 1,
        }
        report.save_session(sess, encrypt_password="some-pw")
        old = os.environ.pop("RECON_PASSWORD", None)
        try:
            with self.assertRaises(crypto.InvalidCiphertext):
                report.load_session(sess["_id"])
        finally:
            if old is not None:
                os.environ["RECON_PASSWORD"] = old


class ResolveSavePasswordTests(unittest.TestCase):
    """recon._resolve_save_password env + config resolution."""

    def setUp(self):
        self._real_env = os.environ.get("RECON_PASSWORD")

    def tearDown(self):
        if self._real_env is None:
            os.environ.pop("RECON_PASSWORD", None)
        else:
            os.environ["RECON_PASSWORD"] = self._real_env

    def test_env_unset_returns_none(self):
        os.environ.pop("RECON_PASSWORD", None)
        ns = argparse.Namespace(encrypt_results=False)
        self.assertIsNone(recon._resolve_save_password(ns))

    def test_env_set_returns_password(self):
        os.environ["RECON_PASSWORD"] = "hunter2"
        ns = argparse.Namespace(encrypt_results=False)
        self.assertEqual(recon._resolve_save_password(ns), "hunter2")

    def test_enforce_without_env_raises(self):
        os.environ.pop("RECON_PASSWORD", None)
        ns = argparse.Namespace(encrypt_results=True)
        with self.assertRaises(ValueError):
            recon._resolve_save_password(ns)

    def test_enforce_with_env_returns_password(self):
        os.environ["RECON_PASSWORD"] = "x"
        ns = argparse.Namespace(encrypt_results=True)
        self.assertEqual(recon._resolve_save_password(ns), "x")


if __name__ == "__main__":
    unittest.main()
