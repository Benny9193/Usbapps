"""Authenticated, password-based encryption for recon session files.

Why a custom construction? The whole toolkit is deliberately stdlib-only
(see README), and Python's standard library does not ship AES or
ChaCha20. Rather than vendor a pure-Python AES, we build a small
encrypt-then-MAC scheme out of primitives that ARE in the stdlib:

  * Key derivation: ``hashlib.scrypt`` (memory-hard, password-based)
  * Stream cipher : HMAC-SHA256 used as a PRF in counter mode
  * Authentication: HMAC-SHA256 over ``header || ciphertext``

HMAC-SHA256 is a well-established PRF, and a PRF in counter mode is a
secure stream cipher provided each (key, nonce) pair is used at most
once. We pick the nonce uniformly at random per encryption (16 bytes -
birthday bound ~2^64 messages), and derive a fresh enc_key/mac_key pair
from a fresh 16-byte salt for every file, so two encryptions of the
same plaintext under the same password produce completely unrelated
output.

File layout (all integers big-endian):

    offset  size   field
    0       8      magic        b"RECONENC"
    8       1      version      0x01
    9       1      flags        0x00 (reserved)
    10      16     salt         random, per-file
    26      16     nonce        random, per-file
    42      *      ciphertext   len(plaintext) bytes
    -32     32     tag          HMAC-SHA256(mac_key, header || ciphertext)

Decryption verifies the tag in constant time before producing any
plaintext, so a wrong password / tampered file raises
``InvalidCiphertext`` without leaking partial output.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

# --- Public constants --------------------------------------------------------

#: Magic bytes that mark a recon-encrypted blob.
MAGIC = b"RECONENC"
#: On-disk format version. Bump if KDF parameters or layout change.
VERSION = 1
#: Suffix used by ``encrypt_file`` when no explicit destination is given.
EXTENSION = ".enc"

# --- Internal layout ---------------------------------------------------------

_SALT_LEN = 16
_NONCE_LEN = 16
_TAG_LEN = 32
_HEADER_LEN = len(MAGIC) + 1 + 1 + _SALT_LEN + _NONCE_LEN  # = 42
_MIN_BLOB_LEN = _HEADER_LEN + _TAG_LEN

# --- KDF parameters ----------------------------------------------------------
#
# scrypt cost parameters. N=2**14, r=8, p=1 needs roughly
# 128 * N * r ~= 16 MiB of RAM, which gives meaningful brute-force
# resistance on commodity hardware while still running in well under a
# second on a modern laptop. ``maxmem`` is sized comfortably above that
# so portable Pythons with the conservative default (32 MiB) do not
# refuse the call.

_SCRYPT_N = 1 << 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_MAXMEM = 64 * 1024 * 1024
_KEY_BYTES = 64  # 32-byte enc key + 32-byte mac key


class CryptoError(Exception):
    """Base class for every error this module raises."""


class InvalidCiphertext(CryptoError):
    """Raised when the input is not a recon-encrypted blob.

    Covers truncation, wrong magic, unsupported version, and tag
    verification failures (which are also what a wrong password looks
    like - we deliberately do not distinguish, to avoid leaking
    information about which password was tried).
    """


def _coerce_password(password) -> bytes:
    if isinstance(password, bytes):
        if not password:
            raise ValueError("password must not be empty")
        return password
    if isinstance(password, str):
        if not password:
            raise ValueError("password must not be empty")
        return password.encode("utf-8")
    raise TypeError("password must be str or bytes")


def _derive_keys(password: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """scrypt(password, salt) -> (enc_key, mac_key), 32 bytes each."""
    material = hashlib.scrypt(
        password,
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        maxmem=_SCRYPT_MAXMEM,
        dklen=_KEY_BYTES,
    )
    return material[:32], material[32:]


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate ``length`` keystream bytes via HMAC-SHA256 in CTR mode.

    Each 32-byte block is ``HMAC-SHA256(enc_key, nonce || counter)``
    where ``counter`` is an 8-byte big-endian integer. Counters never
    repeat under a given (key, nonce), so the construction is a secure
    stream cipher up to the obvious 2^64-block ceiling.
    """
    if length <= 0:
        return b""
    out = bytearray(length)
    full_blocks, tail = divmod(length, 32)
    total_blocks = full_blocks + (1 if tail else 0)
    pos = 0
    for counter in range(total_blocks):
        block = hmac.new(
            enc_key,
            nonce + counter.to_bytes(8, "big"),
            "sha256",
        ).digest()
        take = 32 if counter < full_blocks else tail
        out[pos:pos + take] = block[:take]
        pos += take
    return bytes(out)


def _xor(a: bytes, b: bytes) -> bytes:
    # int.from_bytes / int.to_bytes is the fastest stdlib XOR for
    # mid-sized blobs and avoids per-byte Python overhead.
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def encrypt(plaintext: bytes, password) -> bytes:
    """Encrypt ``plaintext`` under ``password`` and return a self-contained blob.

    The returned bytes carry their own salt, nonce, and authentication
    tag, so all you need to decrypt them is the same password.
    """
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")
    plaintext = bytes(plaintext)
    pwd = _coerce_password(password)

    salt = secrets.token_bytes(_SALT_LEN)
    nonce = secrets.token_bytes(_NONCE_LEN)
    enc_key, mac_key = _derive_keys(pwd, salt)

    header = MAGIC + bytes([VERSION, 0]) + salt + nonce
    keystream = _keystream(enc_key, nonce, len(plaintext))
    ciphertext = _xor(plaintext, keystream) if plaintext else b""

    tag = hmac.new(mac_key, header + ciphertext, "sha256").digest()
    return header + ciphertext + tag


def decrypt(blob: bytes, password) -> bytes:
    """Verify and decrypt a blob produced by :func:`encrypt`.

    Raises :class:`InvalidCiphertext` for any failure (truncation, bad
    magic, unsupported version, wrong password, tampered ciphertext).
    """
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise TypeError("blob must be bytes-like")
    blob = bytes(blob)
    pwd = _coerce_password(password)

    if len(blob) < _MIN_BLOB_LEN:
        raise InvalidCiphertext("ciphertext too short")
    if blob[:len(MAGIC)] != MAGIC:
        raise InvalidCiphertext("not a recon-encrypted blob (bad magic)")

    version = blob[len(MAGIC)]
    if version != VERSION:
        raise InvalidCiphertext(f"unsupported format version {version}")

    salt = blob[10:10 + _SALT_LEN]
    nonce = blob[10 + _SALT_LEN:_HEADER_LEN]
    header = blob[:_HEADER_LEN]
    ciphertext = blob[_HEADER_LEN:-_TAG_LEN]
    tag = blob[-_TAG_LEN:]

    enc_key, mac_key = _derive_keys(pwd, salt)
    expected = hmac.new(mac_key, header + ciphertext, "sha256").digest()
    # Constant-time comparison so a wrong password / tampered tag does
    # not leak timing information about how many bytes matched.
    if not hmac.compare_digest(tag, expected):
        raise InvalidCiphertext("authentication failed (wrong password or tampered data)")

    if not ciphertext:
        return b""
    keystream = _keystream(enc_key, nonce, len(ciphertext))
    return _xor(ciphertext, keystream)


def is_encrypted(blob_or_path) -> bool:
    """Return True if the bytes / file at the given path start with our magic."""
    if isinstance(blob_or_path, (bytes, bytearray, memoryview)):
        return bytes(blob_or_path[:len(MAGIC)]) == MAGIC
    path = Path(blob_or_path)
    try:
        with open(path, "rb") as fh:
            return fh.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def encrypt_file(src, dst, password) -> Path:
    """Encrypt ``src`` to ``dst`` and return the destination path.

    ``dst`` is overwritten if it exists. The plaintext is held in
    memory; this is fine for session JSONs (typically <1 MiB) and
    matches how the rest of the toolkit treats them.
    """
    src = Path(src)
    dst = Path(dst)
    plaintext = src.read_bytes()
    blob = encrypt(plaintext, password)
    dst.parent.mkdir(parents=True, exist_ok=True)
    # Write to a temp file and rename so a crash mid-write cannot leave
    # a half-encrypted file masquerading as a valid blob.
    tmp = dst.with_name(dst.name + ".part")
    try:
        tmp.write_bytes(blob)
        os.replace(tmp, dst)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
    return dst


def decrypt_file(src, dst, password) -> Path:
    """Decrypt ``src`` to ``dst`` and return the destination path.

    Raises :class:`InvalidCiphertext` on any verification failure; in
    that case ``dst`` is not created (or, if it already existed, is not
    modified).
    """
    src = Path(src)
    dst = Path(dst)
    blob = src.read_bytes()
    plaintext = decrypt(blob, password)  # raises before we touch dst
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(dst.name + ".part")
    try:
        tmp.write_bytes(plaintext)
        os.replace(tmp, dst)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
    return dst
