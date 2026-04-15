"""Tests for lib.password_crack - identification, hashing, dictionary
and brute-force attacks, salted variants, and rule-based mangling.

Uses only stdlib; no network I/O. Crypt-backed formats are tested only
when the `crypt` module is actually importable on the host, since it
was deprecated in 3.11 and removed in 3.13.
"""
import hashlib
import os
import tempfile
import unittest

from tests import _path  # noqa: F401
from lib import password_crack


def _md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def _sha1(s):
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


def _sha256(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _sha512(s):
    return hashlib.sha512(s.encode("utf-8")).hexdigest()


class IdentifyHashTests(unittest.TestCase):
    def test_md5_by_length(self):
        self.assertEqual(password_crack.identify_hash(_md5("hello")), "md5")

    def test_sha1_by_length(self):
        self.assertEqual(password_crack.identify_hash(_sha1("hello")), "sha1")

    def test_sha224(self):
        self.assertEqual(password_crack.identify_hash("a" * 56), "sha224")

    def test_sha256(self):
        self.assertEqual(password_crack.identify_hash(_sha256("hello")), "sha256")

    def test_sha384(self):
        self.assertEqual(password_crack.identify_hash("a" * 96), "sha384")

    def test_sha512(self):
        self.assertEqual(password_crack.identify_hash(_sha512("hello")), "sha512")

    def test_crypt_sha512(self):
        self.assertEqual(
            password_crack.identify_hash("$6$salt$hashdigestpart"), "sha512crypt",
        )

    def test_crypt_sha256(self):
        self.assertEqual(
            password_crack.identify_hash("$5$salt$hashdigestpart"), "sha256crypt",
        )

    def test_crypt_bcrypt(self):
        self.assertEqual(
            password_crack.identify_hash(
                "$2b$12$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz1234"
            ),
            "bcrypt",
        )

    def test_unknown_returns_none(self):
        self.assertIsNone(password_crack.identify_hash("not-a-hash"))

    def test_wrong_length_hex_returns_none(self):
        self.assertIsNone(password_crack.identify_hash("abc123"))

    def test_none_input(self):
        self.assertIsNone(password_crack.identify_hash(None))
        self.assertIsNone(password_crack.identify_hash(""))


class ComputeHashTests(unittest.TestCase):
    def test_md5_matches_hashlib(self):
        self.assertEqual(
            password_crack.compute_hash(b"hello", "md5"),
            hashlib.md5(b"hello").hexdigest(),
        )

    def test_accepts_str_password(self):
        self.assertEqual(
            password_crack.compute_hash("hello", "md5"),
            hashlib.md5(b"hello").hexdigest(),
        )

    def test_salt_append(self):
        self.assertEqual(
            password_crack.compute_hash(b"password", "sha256", salt="NaCl"),
            hashlib.sha256(b"passwordNaCl").hexdigest(),
        )

    def test_salt_prepend(self):
        self.assertEqual(
            password_crack.compute_hash(
                b"password", "sha256", salt="NaCl", salt_position="prepend"
            ),
            hashlib.sha256(b"NaClpassword").hexdigest(),
        )

    def test_rejects_unknown_algo(self):
        with self.assertRaises(ValueError):
            password_crack.compute_hash(b"x", "rot13")

    def test_rejects_bad_salt_position(self):
        with self.assertRaises(ValueError):
            password_crack.compute_hash(b"x", "md5", salt="s", salt_position="side")


class ParseLineTests(unittest.TestCase):
    def test_blank_and_comment_return_none(self):
        self.assertIsNone(password_crack.parse_hash_line(""))
        self.assertIsNone(password_crack.parse_hash_line("   "))
        self.assertIsNone(password_crack.parse_hash_line("# comment"))

    def test_plain_md5(self):
        parsed = password_crack.parse_hash_line(_md5("hello"))
        self.assertEqual(parsed["algo"], "md5")
        self.assertIsNone(parsed["label"])
        self.assertIsNone(parsed["salt"])

    def test_uppercase_hex_normalised(self):
        parsed = password_crack.parse_hash_line(_md5("hello").upper())
        self.assertEqual(parsed["hash"], _md5("hello"))

    def test_labeled(self):
        parsed = password_crack.parse_hash_line("alice:" + _md5("password"))
        self.assertEqual(parsed["label"], "alice")
        self.assertEqual(parsed["algo"], "md5")

    def test_label_hash_salt(self):
        parsed = password_crack.parse_hash_line(
            "bob:" + _md5("password") + ":NaCl"
        )
        self.assertEqual(parsed["label"], "bob")
        self.assertEqual(parsed["salt"], "NaCl")
        self.assertEqual(parsed["algo"], "md5")

    def test_hash_colon_salt(self):
        parsed = password_crack.parse_hash_line(_md5("password") + ":sugar")
        self.assertIsNone(parsed["label"])
        self.assertEqual(parsed["salt"], "sugar")

    def test_inline_comment_stripped(self):
        parsed = password_crack.parse_hash_line(
            _md5("hello") + "   # admin hash"
        )
        self.assertEqual(parsed["hash"], _md5("hello"))

    def test_shadow_style(self):
        line = "root:$6$abc$defghijklmnop:17000:0:99999:7:::"
        parsed = password_crack.parse_hash_line(line)
        self.assertEqual(parsed["label"], "root")
        self.assertEqual(parsed["hash"], "$6$abc$defghijklmnop")
        self.assertEqual(parsed["algo"], "sha512crypt")

    def test_bare_crypt(self):
        parsed = password_crack.parse_hash_line("$1$aSalt$somedigest")
        self.assertIsNone(parsed["label"])
        self.assertEqual(parsed["hash"], "$1$aSalt$somedigest")
        self.assertEqual(parsed["algo"], "md5crypt")

    def test_default_algo_override(self):
        # An ambiguous 32-char hash is forced to NTLM when requested.
        parsed = password_crack.parse_hash_line(
            "a" * 32, default_algo="ntlm"
        )
        self.assertEqual(parsed["algo"], "ntlm")

    def test_default_salt_applied(self):
        parsed = password_crack.parse_hash_line(
            _md5("hello"), default_salt="pepper"
        )
        self.assertEqual(parsed["salt"], "pepper")


class DictionaryCrackTests(unittest.TestCase):
    def setUp(self):
        fd, self._wordlist = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as fh:
            fh.write("# Common passwords\n")
            fh.write("hello\nworld\npassword\nletmein\nhunter2\n")

    def tearDown(self):
        os.unlink(self._wordlist)

    def test_cracks_single_md5(self):
        target = password_crack.parse_hash_line(_md5("password"))
        result = password_crack.crack([target], wordlist=self._wordlist)
        self.assertEqual(len(result["cracked"]), 1)
        self.assertEqual(result["cracked"][0]["password"], "password")
        self.assertEqual(result["stopped_reason"], "all_cracked")

    def test_multiple_targets_stop_when_all_found(self):
        targets = [
            password_crack.parse_hash_line("a:" + _md5("hello")),
            password_crack.parse_hash_line("b:" + _sha256("world")),
        ]
        result = password_crack.crack(targets, wordlist=self._wordlist)
        self.assertEqual(len(result["cracked"]), 2)
        # Both algos were exercised
        algos = {c["algo"] for c in result["cracked"]}
        self.assertEqual(algos, {"md5", "sha256"})

    def test_uncracked_reported(self):
        target = password_crack.parse_hash_line(_md5("notinlist"))
        result = password_crack.crack([target], wordlist=self._wordlist)
        self.assertEqual(len(result["cracked"]), 0)
        self.assertEqual(len(result["uncracked"]), 1)
        self.assertEqual(result["stopped_reason"], "exhausted")

    def test_salted_sha256(self):
        h = hashlib.sha256(b"helloNaCl").hexdigest()
        target = {"label": None, "hash": h, "algo": "sha256", "salt": "NaCl"}
        result = password_crack.crack([target], wordlist=self._wordlist)
        self.assertEqual(len(result["cracked"]), 1)
        self.assertEqual(result["cracked"][0]["password"], "hello")

    def test_salted_prepend_also_tried(self):
        h = hashlib.sha256(b"NaClhello").hexdigest()
        target = {"label": None, "hash": h, "algo": "sha256", "salt": "NaCl"}
        result = password_crack.crack([target], wordlist=self._wordlist)
        self.assertEqual(len(result["cracked"]), 1)

    def test_max_candidates_stops_early(self):
        target = password_crack.parse_hash_line(_md5("never-in-list"))
        result = password_crack.crack(
            [target], wordlist=self._wordlist, max_candidates=2,
        )
        self.assertEqual(result["stopped_reason"], "max_candidates")
        self.assertLessEqual(result["tested"], 3)

    def test_rejects_empty_targets(self):
        with self.assertRaises(ValueError):
            password_crack.crack([], wordlist=self._wordlist)

    def test_rejects_no_source(self):
        target = password_crack.parse_hash_line(_md5("hello"))
        with self.assertRaises(ValueError):
            password_crack.crack([target])

    def test_unknown_algo_is_ignored_not_cracked(self):
        target = {"label": "x", "hash": "abc", "algo": None, "salt": None}
        result = password_crack.crack([target], wordlist=self._wordlist)
        self.assertEqual(len(result["cracked"]), 0)
        self.assertEqual(len(result["uncracked"]), 1)
        self.assertEqual(result["ignored"], 1)
        self.assertIn("reason", result["uncracked"][0])


class RulesTests(unittest.TestCase):
    def setUp(self):
        fd, self._wordlist = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as fh:
            fh.write("hello\n")

    def tearDown(self):
        os.unlink(self._wordlist)

    def test_rule_capitalize_plus_suffix(self):
        # "Hello!" is capitalize + append-bang, produced by the rule set.
        target = password_crack.parse_hash_line(_md5("Hello!"))
        result = password_crack.crack(
            [target], wordlist=self._wordlist, rules=True,
        )
        self.assertEqual(len(result["cracked"]), 1)
        self.assertEqual(result["cracked"][0]["password"], "Hello!")

    def test_rule_year_suffix(self):
        target = password_crack.parse_hash_line(_md5("hello2025"))
        result = password_crack.crack(
            [target], wordlist=self._wordlist, rules=True,
        )
        self.assertEqual(len(result["cracked"]), 1)

    def test_rules_off_misses_variant(self):
        target = password_crack.parse_hash_line(_md5("Hello!"))
        result = password_crack.crack([target], wordlist=self._wordlist)
        self.assertEqual(len(result["cracked"]), 0)


class BruteForceTests(unittest.TestCase):
    def test_short_numeric(self):
        target = password_crack.parse_hash_line(_sha1("42"))
        result = password_crack.crack(
            [target],
            brute_force={"charset": "0123456789", "min_length": 1, "max_length": 2},
        )
        self.assertEqual(len(result["cracked"]), 1)
        self.assertEqual(result["cracked"][0]["password"], "42")

    def test_length_cap(self):
        target = password_crack.parse_hash_line(_md5("a"))
        with self.assertRaises(ValueError):
            password_crack.crack(
                [target],
                brute_force={"charset": "a", "min_length": 1, "max_length": 9},
            )

    def test_empty_charset_rejected(self):
        target = password_crack.parse_hash_line(_md5("a"))
        with self.assertRaises(ValueError):
            password_crack.crack(
                [target],
                brute_force={"charset": "", "min_length": 1, "max_length": 3},
            )

    def test_wordlist_then_brute_force(self):
        # Wordlist miss but brute force finds it. Verifies the stream
        # chains both phases.
        fd, wl = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as fh:
            fh.write("never-matches\n")
        try:
            target = password_crack.parse_hash_line(_md5("ab"))
            result = password_crack.crack(
                [target],
                wordlist=wl,
                brute_force={"charset": "ab", "min_length": 1, "max_length": 2},
            )
            self.assertEqual(len(result["cracked"]), 1)
            self.assertEqual(result["cracked"][0]["password"], "ab")
        finally:
            os.unlink(wl)


class NTLMTests(unittest.TestCase):
    """NTLM = MD4(UTF-16LE(password)). md4 availability varies by platform."""

    def setUp(self):
        try:
            # Compute a known NTLM digest using the same path the
            # cracker will use; if md4 is unavailable on this build,
            # skip the whole class.
            self._password = "Password1"
            self._hash = password_crack.compute_hash(self._password, "ntlm")
        except (ValueError, Exception) as exc:  # pragma: no cover
            self.skipTest(f"md4 unavailable: {exc}")

    def test_ntlm_known_vector(self):
        # RFC/NTLM well-known: NTLM("Password1") == 64f12cddaa88057e06a81b54e73b949b
        self.assertEqual(self._hash.lower(), "64f12cddaa88057e06a81b54e73b949b")

    def test_ntlm_dictionary_crack(self):
        fd, wl = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as fh:
            fh.write("wrong\nPassword1\n")
        try:
            target = {
                "label": "user", "hash": self._hash, "algo": "ntlm", "salt": None,
            }
            result = password_crack.crack([target], wordlist=wl)
            self.assertEqual(len(result["cracked"]), 1)
            self.assertEqual(result["cracked"][0]["password"], "Password1")
        finally:
            os.unlink(wl)


class LoadHashFileTests(unittest.TestCase):
    def test_roundtrip(self):
        fd, path = tempfile.mkstemp(suffix=".hashes")
        with os.fdopen(fd, "w") as fh:
            fh.write("# header comment\n")
            fh.write("\n")  # blank line
            fh.write(f"alice:{_md5('hunter2')}\n")
            fh.write(f"bob:{_sha256('letmein')}:salt\n")
        try:
            targets = password_crack.load_hash_file(path)
            self.assertEqual(len(targets), 2)
            labels = {t["label"] for t in targets}
            self.assertEqual(labels, {"alice", "bob"})
            bob = next(t for t in targets if t["label"] == "bob")
            self.assertEqual(bob["salt"], "salt")
            self.assertEqual(bob["algo"], "sha256")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
