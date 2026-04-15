"""Session persistence and indexing for the dashboard."""
import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def _safe(value):
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in value)


def new_session(target, scan_type):
    RESULTS.mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    sid = f"{ts}_{scan_type}_{_safe(target)}"
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
    update_index()


def list_sessions():
    RESULTS.mkdir(exist_ok=True)
    entries = []
    for path in RESULTS.glob("*.json"):
        if path.name == "index.json":
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            continue
        entries.append({
            "id": data.get("_id", path.stem),
            "file": path.name,
            "target": data.get("target"),
            "scan_type": data.get("scan_type"),
            "created": data.get("created"),
            "created_epoch": data.get("created_epoch", 0),
        })
    entries.sort(key=lambda e: e.get("created_epoch", 0), reverse=True)
    return entries


def update_index():
    entries = list_sessions()
    with open(RESULTS / "index.json", "w", encoding="utf-8") as fh:
        json.dump({"sessions": entries, "generated": int(time.time())}, fh, indent=2)
