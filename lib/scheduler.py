"""Recurring scan scheduler with auto-diff and optional auto-encrypt.

Persists entries to ``config/schedules.json`` and drives them from a
lightweight ``sched.scheduler`` plus a single daemon thread. Each fire
executes the configured workflow (``scan`` / ``dns`` / ``full``),
auto-diffs the result against the most recent previous session for the
same target via :mod:`lib.differ`, and writes the delta back into the
fresh session under ``diff_against_previous`` so the dashboard can
surface it in a "Changes" panel without any extra lookups.

Design notes
------------
* Intervals use a tiny "30s / 5m / 1h / 1d" string grammar so the
  schedules file is trivially hand-editable. A plain integer is treated
  as seconds.
* Missed fires are *not* replayed. On startup we schedule the next run
  relative to ``last_run_epoch + interval``; if that moment has already
  passed we simply push the next fire out by a few seconds to let the
  system settle, avoiding a thundering herd after a long offline gap.
* The scheduler is reload-friendly: every fire re-reads the schedule
  entry from disk so CLI edits (``recon schedule disable ...``) take
  effect without bouncing the process.
"""
import json
import os
import re
import sched
import threading
import time
from pathlib import Path

from . import (
    differ,
    dns_tools,
    logutil,
    nmap_runner,
    port_scan,
    report,
    subdomain,
    whois_tool,
)

log = logutil.get("scheduler")

ROOT = Path(__file__).resolve().parents[1]
SCHEDULES_PATH = ROOT / "config" / "schedules.json"
VALID_WORKFLOWS = ("scan", "dns", "full")

# Minimum startup delay (seconds) for a schedule whose next_run is already
# in the past. Keeps fresh boots from hammering targets before the user has
# had a chance to notice the scheduler is running.
_STARTUP_GRACE = 5.0


# --------------------------------------------------------------------------
# interval parsing
# --------------------------------------------------------------------------

_INTERVAL_RE = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$", re.IGNORECASE)
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_interval(spec):
    """Parse ``"30s"`` / ``"5m"`` / ``"1h"`` / ``"2d"`` into seconds.

    A plain int / float is treated as seconds. Raises ``ValueError`` on
    empty, negative, or otherwise unparseable inputs.
    """
    if isinstance(spec, bool):  # bool is an int subclass; reject explicitly
        raise ValueError(f"invalid interval: {spec!r}")
    if isinstance(spec, (int, float)):
        n = int(spec)
        if n <= 0:
            raise ValueError(f"interval must be positive: {spec!r}")
        return n
    if spec is None:
        raise ValueError("interval is required")
    m = _INTERVAL_RE.match(str(spec))
    if not m:
        raise ValueError(
            f"invalid interval (try 30s / 5m / 1h / 1d): {spec!r}"
        )
    n = int(m.group(1))
    if n <= 0:
        raise ValueError(f"interval must be positive: {spec!r}")
    return n * _UNITS[m.group(2).lower()]


def format_interval(seconds):
    """Render a second count as the shortest matching "Nu" token."""
    s = int(seconds)
    if s and s % 86400 == 0:
        return f"{s // 86400}d"
    if s and s % 3600 == 0:
        return f"{s // 3600}h"
    if s and s % 60 == 0:
        return f"{s // 60}m"
    return f"{s}s"


# --------------------------------------------------------------------------
# persistence
# --------------------------------------------------------------------------

def _slug(value):
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in str(value))


def load_schedules():
    """Return the list of schedule entries. Missing file -> ``[]``."""
    if not SCHEDULES_PATH.is_file():
        return []
    try:
        with open(SCHEDULES_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:  # noqa: BLE001 - robust against any corruption
        log.warning("Could not parse %s: %s", SCHEDULES_PATH, exc)
        return []
    if isinstance(data, dict):
        raw = data.get("schedules") or []
    elif isinstance(data, list):
        raw = data
    else:
        return []
    return [entry for entry in raw if isinstance(entry, dict)]


def save_schedules(schedules):
    """Atomically replace ``schedules.json`` with the supplied list."""
    SCHEDULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {"schedules": list(schedules), "generated": int(time.time())}
    tmp = SCHEDULES_PATH.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    tmp.replace(SCHEDULES_PATH)


def _generate_id(target, workflow, schedules):
    base = f"{workflow}-{_slug(target)}"
    existing = {s.get("id") for s in schedules}
    if base not in existing:
        return base
    i = 2
    while f"{base}-{i}" in existing:
        i += 1
    return f"{base}-{i}"


def add_schedule(target, workflow, interval, options=None, enabled=True):
    """Append a new schedule entry and persist. Returns the new entry."""
    if workflow not in VALID_WORKFLOWS:
        raise ValueError(
            f"workflow must be one of {'/'.join(VALID_WORKFLOWS)}: {workflow!r}"
        )
    if not target:
        raise ValueError("target is required")
    interval_seconds = parse_interval(interval)
    schedules = load_schedules()
    sid = _generate_id(target, workflow, schedules)
    now = int(time.time())
    entry = {
        "id": sid,
        "target": target,
        "workflow": workflow,
        "interval": format_interval(interval_seconds),
        "interval_seconds": interval_seconds,
        "options": dict(options or {}),
        "enabled": bool(enabled),
        "created_epoch": now,
        "last_run_epoch": 0,
        "last_session_id": None,
        "last_status": None,
        "run_count": 0,
    }
    schedules.append(entry)
    save_schedules(schedules)
    return entry


def remove_schedule(sid):
    schedules = load_schedules()
    kept = [s for s in schedules if s.get("id") != sid]
    if len(kept) == len(schedules):
        return False
    save_schedules(kept)
    return True


def set_enabled(sid, enabled):
    schedules = load_schedules()
    found = False
    for s in schedules:
        if s.get("id") == sid:
            s["enabled"] = bool(enabled)
            found = True
            break
    if found:
        save_schedules(schedules)
    return found


def get_schedule(sid):
    for s in load_schedules():
        if s.get("id") == sid:
            return s
    return None


def _update_entry(sid, **fields):
    schedules = load_schedules()
    for s in schedules:
        if s.get("id") == sid:
            s.update(fields)
            save_schedules(schedules)
            return True
    return False


# --------------------------------------------------------------------------
# workflow executors
# --------------------------------------------------------------------------

def _resolve_wordlist(arg):
    if not arg:
        return None
    wl = Path(arg)
    if not wl.is_file():
        wl = ROOT / arg
    return wl if wl.is_file() else None


def _exec_scan(session, target, opts):
    profile = opts.get("profile") or "default"
    ports = opts.get("ports")
    no_nmap = bool(opts.get("no_nmap"))
    if not no_nmap and nmap_runner.is_available():
        session["nmap"] = nmap_runner.scan(
            target, profile=profile, ports=ports, session_id=session["_id"]
        )
    else:
        session["port_scan"] = port_scan.scan(target, ports=ports or "1-1024")


def _exec_dns(session, target, opts):
    server = opts.get("server")
    session["dns"] = dns_tools.full_lookup(target, server=server)
    wl_path = _resolve_wordlist(opts.get("wordlist"))
    if wl_path:
        session["subdomains"] = subdomain.enumerate(
            target, str(wl_path), server=server
        )


def _exec_full(session, target, opts):
    profile = opts.get("profile") or "default"
    no_nmap = bool(opts.get("no_nmap"))
    wl_path = _resolve_wordlist(opts.get("wordlist"))
    try:
        session["dns"] = dns_tools.full_lookup(target)
    except Exception as exc:  # noqa: BLE001
        session["dns"] = {"error": str(exc)}
    try:
        session["whois"] = whois_tool.lookup(target)
    except Exception as exc:  # noqa: BLE001
        session["whois"] = {"error": str(exc)}
    if wl_path:
        try:
            wildcard = dns_tools.detect_wildcard(target)
        except Exception:  # noqa: BLE001
            wildcard = None
        try:
            session["subdomains"] = subdomain.enumerate(
                target, str(wl_path), wildcard=wildcard
            )
        except Exception as exc:  # noqa: BLE001
            session["subdomains"] = {"error": str(exc)}
    if not no_nmap and nmap_runner.is_available():
        session["nmap"] = nmap_runner.scan(
            target, profile=profile, session_id=session["_id"]
        )
    else:
        session["port_scan"] = port_scan.scan(target, ports="1-1024")


EXECUTORS = {
    "scan": _exec_scan,
    "dns": _exec_dns,
    "full": _exec_full,
}


# --------------------------------------------------------------------------
# auto-diff
# --------------------------------------------------------------------------

def _find_previous_session(target, exclude_id):
    """Return the most recent non-diff session for ``target`` (excluding id)."""
    for entry in report.list_sessions():
        if entry.get("id") == exclude_id:
            continue
        if entry.get("target") != target:
            continue
        if entry.get("scan_type") == "diff":
            continue
        return entry
    return None


def _diff_is_empty(result):
    if not result:
        return True
    if result["ports"]["added"] or result["ports"]["removed"]:
        return False
    if result.get("dns"):
        return False
    if result["subdomains"]["added"] or result["subdomains"]["removed"]:
        return False
    return True


def auto_diff(session):
    """Attach ``diff_against_previous`` to ``session`` when a peer exists.

    The caller must have already persisted ``session`` to disk because
    :func:`lib.differ.diff` reads by session id. Returns the diff dict
    (or ``None`` when there is nothing to compare against).
    """
    target = session.get("target")
    sid = session.get("_id")
    if not target or not sid:
        return None
    prev = _find_previous_session(target, sid)
    if not prev:
        return None
    try:
        result = differ.diff(prev["id"], sid)
    except FileNotFoundError:
        return None
    except ValueError as exc:
        session["diff_error"] = str(exc)
        return None
    session["diff_against_previous"] = result
    return result


# --------------------------------------------------------------------------
# one-shot executor
# --------------------------------------------------------------------------

def run_once(entry):
    """Execute a single scheduled entry and persist the session.

    Returns the saved session dict on success, ``None`` on unknown workflow.
    """
    target = entry.get("target")
    workflow = entry.get("workflow", "scan")
    opts = entry.get("options") or {}
    sid = entry.get("id")
    if workflow not in EXECUTORS:
        log.error("Schedule %s: unknown workflow %r", sid, workflow)
        return None
    if not target:
        log.error("Schedule %s: missing target", sid)
        return None

    log.info("Scheduled %s -> %s [%s]", workflow, target, sid or "-")
    session = report.new_session(target, workflow)
    session["scheduled"] = {"schedule_id": sid}

    # Honor RECON_PASSWORD for at-rest encryption of scheduled sessions.
    # The scheduler runs unattended, so an env-var-only opt-in is the
    # simplest deployment knob: set RECON_PASSWORD in the launcher and
    # every fire lands as <session>.json.enc instead of plaintext.
    encrypt_password = os.environ.get("RECON_PASSWORD") or None

    status = "ok"
    try:
        EXECUTORS[workflow](session, target, opts)
    except Exception as exc:  # noqa: BLE001
        log.error("Scheduled run %s failed: %s", sid, exc)
        session["error"] = str(exc)
        status = "error"

    # Save once so the differ can read us back from disk.
    report.save_session(session, encrypt_password=encrypt_password)

    # Compare against the previous peer for this target.
    diff_result = auto_diff(session)
    if diff_result is not None:
        report.save_session(session, encrypt_password=encrypt_password)
        if status == "ok":
            status = "unchanged" if _diff_is_empty(diff_result) else "changed"
        p = diff_result["ports"]
        s = diff_result["subdomains"]
        log.info(
            "Auto-diff %s: ports +%d -%d, subdomains +%d -%d, dns-types=%d",
            sid or "-",
            len(p["added"]), len(p["removed"]),
            len(s["added"]), len(s["removed"]),
            len(diff_result.get("dns") or {}),
        )

    if sid:
        _update_entry(
            sid,
            last_run_epoch=int(time.time()),
            last_session_id=session["_id"],
            last_status=status,
            run_count=int(entry.get("run_count", 0)) + 1,
        )

    return session


# --------------------------------------------------------------------------
# scheduler thread
# --------------------------------------------------------------------------

class Scheduler:
    """Thin wrapper around :class:`sched.scheduler` + a daemon thread."""

    _POLL_INTERVAL = 1.0  # seconds; cap on how long we sleep without checking stop()

    def __init__(self):
        self._sched = sched.scheduler(time.time, time.sleep)
        self._thread = None
        self._stop = threading.Event()
        self._events = {}  # id -> sched.Event
        self._lock = threading.Lock()

    # -- lifecycle --------------------------------------------------------

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._seed_from_disk()
        self._thread = threading.Thread(
            target=self._run_loop, name="recon-scheduler", daemon=True
        )
        self._thread.start()
        with self._lock:
            active = len(self._events)
        log.info("Scheduler started (%d active %s)",
                 active, "entry" if active == 1 else "entries")

    def stop(self, timeout=2.0):
        self._stop.set()
        with self._lock:
            for evt in list(self._events.values()):
                try:
                    self._sched.cancel(evt)
                except ValueError:
                    pass
            self._events.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def is_running(self):
        return bool(self._thread and self._thread.is_alive())

    # -- internals --------------------------------------------------------

    def _seed_from_disk(self):
        """Enqueue the next fire for every enabled entry on disk."""
        now = time.time()
        for entry in load_schedules():
            if not entry.get("enabled", True):
                continue
            sid = entry.get("id")
            if not sid:
                continue
            interval = int(entry.get("interval_seconds") or 3600)
            last = int(entry.get("last_run_epoch") or 0)
            if last:
                delay = max(_STARTUP_GRACE, (last + interval) - now)
            else:
                # Fresh schedule: wait at most 10s so the first run is
                # snappy during interactive use without firing instantly.
                delay = min(float(interval), 10.0)
            self._enqueue(sid, delay)

    def _enqueue(self, sid, delay):
        with self._lock:
            old = self._events.pop(sid, None)
            if old is not None:
                try:
                    self._sched.cancel(old)
                except ValueError:
                    pass
            evt = self._sched.enter(delay, 1, self._fire, argument=(sid,))
            self._events[sid] = evt

    def _fire(self, sid):
        if self._stop.is_set():
            return
        # Re-read from disk so CLI edits (disable/remove) take effect
        # without restarting the daemon.
        schedules = load_schedules()
        entry = next((e for e in schedules if e.get("id") == sid), None)
        if not entry or not entry.get("enabled", True):
            with self._lock:
                self._events.pop(sid, None)
            log.info("Schedule %s removed/disabled; not rescheduling", sid)
            return
        try:
            run_once(entry)
        except Exception as exc:  # noqa: BLE001
            log.error("Scheduled run %s crashed: %s", sid, exc)
        if self._stop.is_set():
            return
        interval = int(entry.get("interval_seconds") or 3600)
        self._enqueue(sid, float(interval))

    def _run_loop(self):
        while not self._stop.is_set():
            try:
                delay = self._sched.run(blocking=False)
            except Exception as exc:  # noqa: BLE001
                log.error("Scheduler loop error: %s", exc)
                delay = None
            if delay is None:
                self._stop.wait(self._POLL_INTERVAL)
            else:
                self._stop.wait(min(float(delay), self._POLL_INTERVAL))


# --------------------------------------------------------------------------
# module-level singleton helpers used by the dashboard
# --------------------------------------------------------------------------

_default = None
_default_lock = threading.Lock()


def start_default():
    """Start (or return) the process-wide scheduler singleton."""
    global _default
    with _default_lock:
        if _default is None:
            _default = Scheduler()
        _default.start()
        return _default


def stop_default(timeout=2.0):
    global _default
    with _default_lock:
        if _default is not None:
            _default.stop(timeout=timeout)
            _default = None
