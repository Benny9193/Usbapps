"""Password hash cracking for authorised audits.

A small, stdlib-only hash cracker to round out the toolkit for credential
hygiene assessments. Given a hash (or a file full of hashes) and a
wordlist, it walks the candidates, optionally applies a compact set of
mangling rules, and reports which hashes fell to which passwords.

Supported algorithms (auto-detected from hash length unless overridden):

* Raw hex digests: ``md5``, ``sha1``, ``sha224``, ``sha256``, ``sha384``,
  ``sha512`` - all via :mod:`hashlib`.
* ``ntlm`` - MD4 of the password encoded as UTF-16LE. MD4 is a legacy
  primitive; on OpenSSL 3 builds it is only available via
  ``hashlib.new('md4', usedforsecurity=False)``. Must be selected
  explicitly with ``--algorithm ntlm`` because it shares a length (32
  hex) with MD5.
* Unix crypt-style ``$id$salt$hash`` entries (``$1$`` md5crypt,
  ``$5$`` sha256crypt, ``$6$`` sha512crypt, ``$2a/2b/2y$`` bcrypt).
  Verification is delegated to the stdlib :mod:`crypt` module, which
  itself leans on the platform ``crypt(3)``. When ``crypt`` is not
  available (Python 3.13+ or Windows), these hashes are parsed and
  reported but cannot be cracked - the result records them as
  ``uncracked`` with a ``reason`` explaining why.

Salts from ``--salt`` or per-line ``label:hash:salt`` entries are tried
in both ``append`` and ``prepend`` positions so common
``hash(password + salt)`` / ``hash(salt + password)`` schemes are
covered without configuration.

The cracker is intentionally single-threaded. The hashing primitives
release the GIL but the candidate generator and target fan-out are
sequential, which keeps ``--max-candidates`` and ``--timeout`` simple
and deterministic. For throughput-sensitive attacks reach for hashcat
or John; this module is built for USB-portable sanity checks.
"""
import hashlib
import itertools
import re
import time
from pathlib import Path

from . import logutil

log = logutil.get("crack")

try:
    import crypt as _crypt  # deprecated in 3.11, removed in 3.13
except ImportError:  # pragma: no cover - platform-dependent
    _crypt = None


# Raw hex hash length -> canonical algorithm name. NTLM is deliberately
# omitted because its 32-char length collides with MD5; callers must
# opt in with --algorithm ntlm when they know they have NT hashes.
HEX_LENGTHS = {
    32: "md5",
    40: "sha1",
    56: "sha224",
    64: "sha256",
    96: "sha384",
    128: "sha512",
}

RAW_ALGORITHMS = frozenset({"md5", "sha1", "sha224", "sha256", "sha384", "sha512"})
ALL_ALGORITHMS = RAW_ALGORITHMS | {"ntlm"}

# Unix crypt-style identifier -> friendly algorithm label.
CRYPT_IDS = {
    "1":  "md5crypt",
    "5":  "sha256crypt",
    "6":  "sha512crypt",
    "2a": "bcrypt",
    "2b": "bcrypt",
    "2y": "bcrypt",
    "y":  "yescrypt",
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# Brute-force sanity cap. The toolkit is not meant for multi-day jobs,
# and len > 8 in the default charset is already ~2.8e12 candidates.
_MAX_BRUTE_LENGTH = 8

# Default suffixes for the mangling ruleset. Deliberately small so
# --rules cannot accidentally explode a big wordlist.
_RULE_SUFFIXES = (
    "", "!", "!!", "?", ".", "1", "12", "123", "1234",
    "!@#", "2023", "2024", "2025", "2026",
)


def identify_hash(hash_str):
    """Return an algorithm label for ``hash_str`` or ``None``.

    The classifier only recognises raw hex digests (by length) and Unix
    ``$id$`` crypt strings. NTLM hashes look identical to MD5 at this
    layer and therefore always fall through to ``md5`` - use the
    ``--algorithm ntlm`` override when you know you have NT hashes.
    """
    if hash_str is None:
        return None
    s = hash_str.strip()
    if not s:
        return None
    if s.startswith("$"):
        parts = s.split("$")
        # Expected layout: ['', id, (rounds=...)?, salt, hash]
        if len(parts) < 4:
            return None
        return CRYPT_IDS.get(parts[1], f"crypt-{parts[1]}")
    if _HEX_RE.match(s):
        return HEX_LENGTHS.get(len(s))
    return None


def compute_hash(password, algo, *, salt=None, salt_position="append"):
    """Return the hex digest of ``password`` under ``algo``.

    ``password`` may be ``bytes`` or ``str``. ``salt`` is concatenated
    either before (``prepend``) or after (``append``) the password
    before hashing. NTLM ignores ``salt`` - its construction is
    MD4(UTF-16LE(password)) with no salt.
    """
    if isinstance(password, str):
        pw_bytes = password.encode("utf-8", "surrogatepass")
    else:
        pw_bytes = password

    if algo == "ntlm":
        try:
            h = hashlib.new("md4", usedforsecurity=False)
        except (TypeError, ValueError):
            h = hashlib.new("md4")
        # NTLM always hashes the UTF-16LE of the password, no salt.
        try:
            text = pw_bytes.decode("utf-8", "surrogatepass")
        except UnicodeDecodeError:
            text = pw_bytes.decode("latin-1")
        h.update(text.encode("utf-16-le"))
        return h.hexdigest()

    if algo not in RAW_ALGORITHMS:
        raise ValueError(f"unsupported algorithm: {algo}")

    if salt:
        salt_bytes = salt.encode("utf-8") if isinstance(salt, str) else salt
        if salt_position == "prepend":
            data = salt_bytes + pw_bytes
        elif salt_position == "append":
            data = pw_bytes + salt_bytes
        else:
            raise ValueError(f"salt_position must be prepend/append, not {salt_position!r}")
    else:
        data = pw_bytes

    return hashlib.new(algo, data).hexdigest()


def _normalise_hash(hash_part, algo):
    """Lower-case raw hex hashes so comparisons are case-insensitive.

    Crypt-style strings are left untouched because their salts can be
    case-sensitive.
    """
    if algo in RAW_ALGORITHMS and _HEX_RE.match(hash_part):
        return hash_part.lower()
    return hash_part


def parse_hash_line(line, *, default_algo=None, default_salt=None):
    """Decode one input line into a target dict, or ``None`` if blank.

    Accepted forms (``#`` starts a comment, whitespace is trimmed):

    * ``<hash>``                                - auto-detect algorithm
    * ``<hash>:<salt>``                         - append-style salt
    * ``<label>:<hash>``                        - e.g. username:hash
    * ``<label>:<hash>:<salt>``
    * ``<label>:$id$salt$hash[:...]``           - shadow file entries;
      any trailing ``:`` fields (aging metadata) are ignored.
    * ``$id$salt$hash[:...]``                   - bare crypt entry.

    ``default_algo``/``default_salt`` are applied when a line does not
    pin its own. Returns ``{"label", "hash", "algo", "salt"}`` or
    ``None`` for blanks/comments/unparseable input.
    """
    if line is None:
        return None
    raw = line.split("#", 1)[0].strip()
    if not raw:
        return None

    label = None
    salt_part = None

    if raw.startswith("$"):
        # Bare crypt entry. Stop at the first ``:`` so aging metadata
        # (e.g. shadow password age columns) is ignored.
        hash_part = raw.split(":", 1)[0]
    else:
        tokens = raw.split(":")
        if len(tokens) == 1:
            hash_part = tokens[0]
        elif tokens[1].startswith("$"):
            # Shadow-style: label first, then a crypt hash, then ignore
            # the remaining colon-delimited aging columns.
            label = tokens[0] or None
            hash_part = tokens[1]
        elif len(tokens) == 2:
            first = tokens[0]
            # If the first field already looks like a raw hex hash,
            # the whole line is ``hash:salt``; otherwise ``label:hash``.
            if _HEX_RE.match(first) and len(first) in HEX_LENGTHS:
                hash_part = first
                salt_part = tokens[1]
            else:
                label = first or None
                hash_part = tokens[1]
        else:
            label = tokens[0] or None
            hash_part = tokens[1]
            salt_part = ":".join(tokens[2:]) or None

    hash_part = hash_part.strip()
    if not hash_part:
        return None

    algo = default_algo or identify_hash(hash_part)
    salt = salt_part if salt_part is not None else default_salt

    return {
        "label": label,
        "hash": _normalise_hash(hash_part, algo),
        "algo": algo,
        "salt": salt,
    }


def _mangle(word):
    """Yield wordlist mutations under a compact, bounded rule set.

    The goal is to flag obvious policy bypasses (``Password123``,
    ``summer2025!``) without ever producing more than
    ``len(variants) * len(_RULE_SUFFIXES)`` candidates per source word.
    """
    seen = set()
    variants = []
    for v in (word, word.lower(), word.upper(), word.capitalize(), word[::-1]):
        if v and v not in seen:
            seen.add(v)
            variants.append(v)
    for v in variants:
        for suf in _RULE_SUFFIXES:
            yield v + suf


def _candidate_stream(wordlist, rules, brute_force):
    """Yield password candidates as ``bytes``.

    The wordlist phase dedupes within itself (so ``rules`` cannot re-emit
    a word that is already in the dictionary); the brute-force phase is
    already unique by construction so it skips the dedupe set to keep
    memory flat.
    """
    if wordlist:
        seen = set()
        try:
            fh = open(wordlist, "r", encoding="utf-8", errors="ignore")
        except OSError as exc:
            raise ValueError(f"could not open wordlist {wordlist}: {exc}")
        try:
            for line in fh:
                word = line.rstrip("\r\n")
                if not word or word.startswith("#"):
                    continue
                candidates = list(_mangle(word)) if rules else [word]
                for c in candidates:
                    b = c.encode("utf-8", "ignore")
                    if b in seen:
                        continue
                    seen.add(b)
                    yield b
        finally:
            fh.close()
        seen.clear()

    if brute_force:
        # Fall back to the default charset only when the caller did not
        # pass the key at all; an explicit empty string is a config
        # error we want to surface loudly.
        if "charset" in brute_force:
            charset = brute_force["charset"]
        else:
            charset = "abcdefghijklmnopqrstuvwxyz0123456789"
        min_len = int(brute_force.get("min_length") or 1)
        max_len = int(brute_force.get("max_length") or 4)
        if min_len < 1 or max_len < min_len or max_len > _MAX_BRUTE_LENGTH:
            raise ValueError(
                f"brute_force: require 1 <= min_length <= max_length <= {_MAX_BRUTE_LENGTH}"
            )
        if not charset:
            raise ValueError("brute_force: charset must be non-empty")
        charset_bytes = charset.encode("utf-8")
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(charset_bytes, repeat=length):
                yield bytes(combo)


def _verify(target, pw_bytes):
    """Return True when ``pw_bytes`` matches ``target['hash']``."""
    algo = target.get("algo")
    expected = target.get("hash") or ""
    salt = target.get("salt")

    if algo in RAW_ALGORITHMS:
        # Without a salt, one hash of the raw password. With a salt,
        # try both append and prepend positions to cover the two
        # conventions seen in the wild.
        if not salt:
            return compute_hash(pw_bytes, algo) == expected
        return (
            compute_hash(pw_bytes, algo, salt=salt, salt_position="append") == expected
            or compute_hash(pw_bytes, algo, salt=salt, salt_position="prepend") == expected
        )

    if algo == "ntlm":
        return compute_hash(pw_bytes, algo) == expected

    if algo and algo.endswith("crypt"):
        if _crypt is None:
            return False
        try:
            pw_str = pw_bytes.decode("utf-8", "ignore")
            return _crypt.crypt(pw_str, expected) == expected
        except (OSError, ValueError):
            return False

    return False


def crack(
    targets,
    *,
    wordlist=None,
    rules=False,
    brute_force=None,
    timeout=None,
    max_candidates=None,
):
    """Run a dictionary / brute-force attack against ``targets``.

    ``targets`` is a list of parsed dicts (or a single dict) as
    produced by :func:`parse_hash_line`. Returns a JSON-safe summary:

    .. code-block:: python

        {
          "targets": <count>,
          "cracked":   [{label, hash, algo, password, candidates_at_hit}, ...],
          "uncracked": [{label, hash, algo, reason}, ...],
          "tested": <total candidates tried>,
          "elapsed_seconds": <float>,
          "wordlist": <path or None>,
          "brute_force": <original brute_force dict or None>,
          "stopped_reason": "all_cracked"|"exhausted"|"timeout"|"max_candidates",
        }
    """
    if isinstance(targets, dict):
        targets = [targets]
    targets = list(targets)
    if not targets:
        raise ValueError("crack(): no targets supplied")
    if not wordlist and not brute_force:
        raise ValueError("crack(): supply wordlist= and/or brute_force=")

    # Partition into cracker-viable targets and ones we cannot touch
    # (unknown algo, or a crypt hash when stdlib crypt is unavailable).
    viable = []
    ignored = []
    for i, t in enumerate(targets):
        algo = t.get("algo")
        if algo in RAW_ALGORITHMS or algo == "ntlm":
            viable.append((i, t))
        elif algo and algo.endswith("crypt"):
            if _crypt is None:
                ignored.append((i, t, f"{algo} requires the stdlib `crypt` module"))
            else:
                viable.append((i, t))
        else:
            ignored.append((i, t, "unknown or unsupported algorithm"))

    cracked = {}
    pending = dict(viable)  # index -> target

    start = time.monotonic()
    tested = 0
    stopped_reason = "exhausted"

    if pending:
        try:
            stream = _candidate_stream(wordlist, rules, brute_force)
            for pw_bytes in stream:
                tested += 1
                if max_candidates and tested > max_candidates:
                    stopped_reason = "max_candidates"
                    break
                if timeout and (time.monotonic() - start) > timeout:
                    stopped_reason = "timeout"
                    break
                # Walk a copy because successful verification mutates
                # ``pending`` in place.
                for idx in list(pending):
                    if _verify(pending[idx], pw_bytes):
                        tgt = pending.pop(idx)
                        try:
                            password_text = pw_bytes.decode("utf-8")
                        except UnicodeDecodeError:
                            password_text = pw_bytes.decode("latin-1", "replace")
                        cracked[idx] = {
                            "label": tgt.get("label"),
                            "hash": tgt.get("hash"),
                            "algo": tgt.get("algo"),
                            "salt": tgt.get("salt"),
                            "password": password_text,
                            "candidates_at_hit": tested,
                        }
                        log.info(
                            "cracked %s (%s) -> %s",
                            tgt.get("label") or (tgt.get("hash") or "?")[:16],
                            tgt.get("algo"),
                            password_text,
                        )
                if not pending:
                    stopped_reason = "all_cracked"
                    break
        except ValueError:
            raise

    elapsed = time.monotonic() - start

    cracked_list = [cracked[i] for i in sorted(cracked.keys())]
    uncracked_list = []
    for i, t in enumerate(targets):
        if i in cracked:
            continue
        entry = {
            "label": t.get("label"),
            "hash": t.get("hash"),
            "algo": t.get("algo"),
            "salt": t.get("salt"),
        }
        # Look up the ignore reason, if any.
        for ii, _, reason in ignored:
            if ii == i:
                entry["reason"] = reason
                break
        uncracked_list.append(entry)

    return {
        "targets": len(targets),
        "cracked": cracked_list,
        "uncracked": uncracked_list,
        "tested": tested,
        "elapsed_seconds": round(elapsed, 3),
        "wordlist": str(wordlist) if wordlist else None,
        "brute_force": brute_force,
        "stopped_reason": stopped_reason,
        "ignored": len(ignored),
    }


def load_hash_file(path, *, default_algo=None, default_salt=None):
    """Parse a hash file into a list of target dicts (skipping blanks)."""
    out = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            parsed = parse_hash_line(
                line, default_algo=default_algo, default_salt=default_salt
            )
            if parsed is not None:
                out.append(parsed)
    return out
