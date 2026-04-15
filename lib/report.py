"""Session persistence and indexing for the dashboard."""
import json
import os
import time
from pathlib import Path

from . import crypto

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"

# Cache of parsed session headers keyed by absolute path string. Values are
# (mtime, header_dict). list_sessions() stats each file and reuses the cache
# entry when mtime is unchanged, so re-indexing a large results/ directory
# no longer re-reads every file from disk on every save.
_HEADER_CACHE = {}

# Filename pattern produced by new_session(): `<ts>_<scan_type>_<safe_target>`
# where ts is `%Y%m%d-%H%M%S`. Used to synthesize an index entry for an
# encrypted session whose header we cannot read.
_FILENAME_TS_FMT = "%Y%m%d-%H%M%S"


def _parse_filename_meta(name):
    """Decode a `<ts>_<scan_type>_<safe_target>.json[.enc]` filename.

    Returns ``None`` if the name does not match the toolkit's own
    pattern (so foreign files in ``results/`` are still ignored).
    """
    stem = name
    for suffix in (".json.enc", ".json"):
        if stem.endswith(suffix):
            stem = stem[:-len(suffix)]
            break
    else:
        return None
    parts = stem.split("_", 2)
    if len(parts) != 3:
        return None
    ts, scan_type, target = parts
    try:
        epoch = int(time.mktime(time.strptime(ts, _FILENAME_TS_FMT)))
    except ValueError:
        return None
    return {
        "id": stem,
        "file": name,
        "target": target,
        "scan_type": scan_type,
        "created": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch)),
        "created_epoch": epoch,
    }


def _safe(value):
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in value)


def new_session(target, scan_type):
    RESULTS.mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    base = f"{ts}_{scan_type}_{_safe(target)}"
    # Guard against sub-second collisions. Two sessions with the same
    # target + scan_type that land in the same wall-clock second used to
    # overwrite each other on disk; the scheduler in particular can hit
    # this when a recurring job fires faster than the timestamp rolls.
    sid = base
    n = 2
    while (RESULTS / f"{sid}.json").exists():
        sid = f"{base}-{n}"
        n += 1
    return {
        "_id": sid,
        "_path": str(RESULTS / f"{sid}.json"),
        "target": target,
        "scan_type": scan_type,
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "created_epoch": int(time.time()),
    }


def save_session(session, *, encrypt_password=None):
    """Persist a session to disk.

    When ``encrypt_password`` is supplied the JSON is built in memory,
    encrypted with :func:`lib.crypto.encrypt`, and written to
    ``<session_path>.enc``. The plaintext path is removed if it
    already existed (e.g. an earlier unencrypted save), so flipping
    ``encrypt_results`` on does not leave stale cleartext behind.
    """
    path = Path(session["_path"])
    path.parent.mkdir(exist_ok=True)

    if encrypt_password:
        # Render JSON to bytes, encrypt, then atomic-replace .json.enc.
        data = json.dumps(session, indent=2, default=str).encode("utf-8")
        blob = crypto.encrypt(data, encrypt_password)
        enc_path = path.with_name(path.name + crypto.EXTENSION)
        tmp = enc_path.with_name(enc_path.name + ".part")
        try:
            tmp.write_bytes(blob)
            tmp.replace(enc_path)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass
        # Drop any stale plaintext for the same id so the encrypted
        # file is the sole on-disk representation.
        if path.exists():
            try:
                path.unlink()
            except OSError:
                pass
            _HEADER_CACHE.pop(str(path.resolve()), None)
        _HEADER_CACHE.pop(str(enc_path.resolve()), None)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(session, fh, indent=2, default=str)
        _HEADER_CACHE.pop(str(path.resolve()), None)

    update_index()


def _read_header(path):
    """Read just enough of a session file to build an index entry.

    Uses the mtime cache; re-reads only when the file has changed on disk.
    Encrypted sessions cannot be JSON-decoded, so we synthesize a
    minimal header from the filename pattern instead.
    """
    key = str(path.resolve())
    try:
        mtime = path.stat().st_mtime
    except OSError:
        _HEADER_CACHE.pop(key, None)
        return None
    cached = _HEADER_CACHE.get(key)
    if cached and cached[0] == mtime:
        return cached[1]

    encrypted = path.name.endswith(crypto.EXTENSION) or crypto.is_encrypted(path)
    if encrypted:
        meta = _parse_filename_meta(path.name)
        if meta is None:
            return None
        header = dict(meta)
        header["encrypted"] = True
    else:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            return None
        header = {
            "id": data.get("_id", path.stem),
            "file": path.name,
            "target": data.get("target"),
            "scan_type": data.get("scan_type"),
            "created": data.get("created"),
            "created_epoch": data.get("created_epoch", 0),
            "encrypted": False,
        }
    _HEADER_CACHE[key] = (mtime, header)
    return header


def list_sessions():
    """Return all session headers (newest first), including encrypted ones.

    When the same session id has both a plaintext ``.json`` and an
    encrypted ``.json.enc`` on disk (e.g. mid-rotation), the plaintext
    entry wins so existing dashboard / CLI flows keep working.
    """
    RESULTS.mkdir(exist_ok=True)
    seen = set()
    by_id = {}
    for path in list(RESULTS.glob("*.json")) + list(RESULTS.glob("*.json.enc")):
        if path.name == "index.json":
            continue
        header = _read_header(path)
        if header is None:
            continue
        sid = header.get("id")
        existing = by_id.get(sid)
        # Prefer the plaintext entry when both variants exist.
        if existing is None or (existing.get("encrypted") and not header.get("encrypted")):
            by_id[sid] = header
        seen.add(str(path.resolve()))
    # Drop cache entries for files that no longer exist so deleted sessions
    # do not linger in memory indefinitely.
    for stale_key in [k for k in _HEADER_CACHE if k not in seen]:
        _HEADER_CACHE.pop(stale_key, None)
    entries = list(by_id.values())
    entries.sort(key=lambda e: e.get("created_epoch", 0), reverse=True)
    return entries


def load_session(session_ref, *, password=None):
    """Load a session by id or path, transparently decrypting if needed.

    Resolution order: if ``session_ref`` is an existing file we read it
    directly; otherwise we look for ``<RESULTS>/<session_ref>.json`` and
    then ``<RESULTS>/<session_ref>.json.enc``. Encrypted variants are
    decrypted with ``password`` (defaulting to ``RECON_PASSWORD`` from
    the environment); a missing or wrong password raises
    :class:`lib.crypto.InvalidCiphertext`.
    """
    path = Path(session_ref)
    if not path.exists():
        for candidate in (
            RESULTS / f"{session_ref}.json",
            RESULTS / f"{session_ref}.json{crypto.EXTENSION}",
        ):
            if candidate.exists():
                path = candidate
                break
        else:
            raise FileNotFoundError(f"no such session: {session_ref}")

    if path.name.endswith(crypto.EXTENSION) or crypto.is_encrypted(path):
        pw = password or os.environ.get("RECON_PASSWORD")
        if not pw:
            raise crypto.InvalidCiphertext(
                f"{path.name} is encrypted but no password is available"
            )
        plaintext = crypto.decrypt(path.read_bytes(), pw)
        return json.loads(plaintext.decode("utf-8"))

    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def update_index():
    entries = list_sessions()
    with open(RESULTS / "index.json", "w", encoding="utf-8") as fh:
        json.dump({"sessions": entries, "generated": int(time.time())}, fh, indent=2)


def delete_session(session_id):
    """Delete a session JSON and any sibling artifacts (e.g. .nmap.xml).

    Returns the list of deleted absolute paths. Non-existent IDs return [].
    """
    RESULTS.mkdir(exist_ok=True)
    removed = []
    for path in list(RESULTS.glob(f"{session_id}*")):
        if path.name == "index.json":
            continue
        try:
            path.unlink()
            removed.append(str(path))
            _HEADER_CACHE.pop(str(path.resolve()), None)
        except OSError:
            pass
    if removed:
        update_index()
    return removed


def purge(older_than_epoch):
    """Delete every session older than the given epoch timestamp.

    Returns (count_deleted, list_of_ids).
    """
    victims = [s for s in list_sessions() if s.get("created_epoch", 0) < older_than_epoch]
    for v in victims:
        delete_session(v["id"])
    return len(victims), [v["id"] for v in victims]
