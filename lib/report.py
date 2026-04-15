"""Session persistence and indexing for the dashboard."""
import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"

# Cache of parsed session headers keyed by absolute path string. Values are
# (mtime, header_dict). list_sessions() stats each file and reuses the cache
# entry when mtime is unchanged, so re-indexing a large results/ directory
# no longer re-reads every file from disk on every save.
_HEADER_CACHE = {}


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


def save_session(session):
    path = Path(session["_path"])
    path.parent.mkdir(exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(session, fh, indent=2, default=str)
    # Invalidate this file's cache entry so the fresh content is picked up.
    _HEADER_CACHE.pop(str(path.resolve()), None)
    update_index()


def _read_header(path):
    """Read just enough of a session file to build an index entry.

    Uses the mtime cache; re-reads only when the file has changed on disk.
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
    }
    _HEADER_CACHE[key] = (mtime, header)
    return header


def list_sessions():
    RESULTS.mkdir(exist_ok=True)
    seen = set()
    entries = []
    for path in RESULTS.glob("*.json"):
        if path.name == "index.json":
            continue
        header = _read_header(path)
        if header is None:
            continue
        entries.append(header)
        seen.add(str(path.resolve()))
    # Drop cache entries for files that no longer exist so deleted sessions
    # do not linger in memory indefinitely.
    for stale_key in [k for k in _HEADER_CACHE if k not in seen]:
        _HEADER_CACHE.pop(stale_key, None)
    entries.sort(key=lambda e: e.get("created_epoch", 0), reverse=True)
    return entries


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
