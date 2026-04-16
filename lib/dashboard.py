"""Minimal HTTP server that serves the dashboard assets and result JSON."""
import http.server
import os
import posixpath
import secrets
import shutil
import subprocess
import threading
import urllib.parse
import webbrowser
from http import cookies
from pathlib import Path

from . import report

ROOT = Path(__file__).resolve().parents[1]

# Only these URL prefixes are served. Everything else returns 404, including
# lib/, bin/, .git/, config/, and any stray files at the repo root.
ALLOWED_PREFIXES = ("/dashboard/", "/results/")

# A narrow allow-list of exact config files the dashboard may read. The
# schedules file is surfaced here so the UI can render the Schedules panel
# without needing a full API layer - nothing else under config/ is served.
ALLOWED_EXACT = ("/config/schedules.json",)

# Headers that make the dashboard safer when accidentally bound to 0.0.0.0
# on a hostile network: deny embedding, lock down navigation, and pin the
# asset origin via CSP. Inline styles are disallowed, so edits to the JS/CSS
# bundle must stay in dashboard/*.
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'"
    ),
}


def _normalize(path):
    """Return the URL path with query/fragment stripped and `.` / `..` folded.

    Uses posixpath (not os.path) so Windows separators never slip in. The
    caller is responsible for rejecting any result that falls outside the
    whitelist.
    """
    # Strip query string & fragment before normalization.
    parsed = urllib.parse.urlparse(path)
    raw = urllib.parse.unquote(parsed.path or "/")
    # Reject NUL bytes and backslashes outright (Windows path separators).
    if "\x00" in raw or "\\" in raw:
        return None
    normalized = posixpath.normpath(raw)
    # posixpath.normpath collapses trailing slashes; keep a trailing slash if
    # the original had one so directory-ish URLs still match prefixes.
    if raw.endswith("/") and not normalized.endswith("/"):
        normalized = normalized + "/"
    # Leading `..` after normalization means traversal escape.
    if normalized.startswith(".."):
        return None
    return normalized


def _is_allowed(path):
    if path in ("/", ""):
        return True
    if path in ALLOWED_EXACT:
        return True
    return any(path == p.rstrip("/") or path.startswith(p) for p in ALLOWED_PREFIXES)


AUTH_COOKIE = "recon_token"


def _check_token(handler):
    """Validate the token from header/cookie/query-param.

    Returns (ok, set_cookie_value_or_None). When the token is presented via
    query string, the caller will set a cookie and strip the query so the
    URL bar does not leak it.
    """
    token = getattr(handler.server, "auth_token", None)
    if not token:
        return True, None

    # 1. Authorization header
    auth = handler.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        if secrets.compare_digest(auth[7:].strip(), token):
            return True, None

    # 2. Cookie
    cookie_header = handler.headers.get("Cookie", "")
    if cookie_header:
        try:
            jar = cookies.SimpleCookie()
            jar.load(cookie_header)
            if AUTH_COOKIE in jar and secrets.compare_digest(jar[AUTH_COOKIE].value, token):
                return True, None
        except Exception:
            pass

    # 3. Query param (one-shot; set a cookie and strip it next)
    parsed = urllib.parse.urlparse(handler.path)
    params = urllib.parse.parse_qs(parsed.query)
    supplied = params.get("token", [None])[0]
    if supplied and secrets.compare_digest(supplied, token):
        return True, token

    return False, None


class _Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def _gate(self, method):
        ok, set_cookie = _check_token(self)
        if not ok:
            self.send_response(401)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("WWW-Authenticate", 'Bearer realm="recon"')
            for name, value in SECURITY_HEADERS.items():
                self.send_header(name, value)
            body = b"Unauthorized\n"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if method == "GET":
                self.wfile.write(body)
            return None

        normalized = _normalize(self.path)
        if normalized is None or not _is_allowed(normalized):
            self.send_error(404, "Not Found")
            return None
        if normalized in ("/", ""):
            normalized = "/dashboard/index.html"
        self.path = normalized
        self._pending_cookie = set_cookie
        return normalized

    def do_GET(self):
        if self._gate("GET") is None:
            return
        return super().do_GET()

    def do_HEAD(self):
        if self._gate("HEAD") is None:
            return
        return super().do_HEAD()

    def end_headers(self):
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        if getattr(self, "_pending_cookie", None):
            cookie = cookies.SimpleCookie()
            cookie[AUTH_COOKIE] = self._pending_cookie
            cookie[AUTH_COOKIE]["path"] = "/"
            cookie[AUTH_COOKIE]["httponly"] = True
            cookie[AUTH_COOKIE]["samesite"] = "Strict"
            self.send_header("Set-Cookie", cookie[AUTH_COOKIE].OutputString())
            self._pending_cookie = None
        super().end_headers()

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass  # silence default access log


class _Server(http.server.ThreadingHTTPServer):
    """Threaded so one slow client cannot block the rest of the dashboard."""

    allow_reuse_address = True
    daemon_threads = True


def serve(host="127.0.0.1", port=8787, open_browser=True, token=None,
          require_auth=False, run_scheduler=False):
    """Serve the dashboard.

    token: if given, clients must present this token via either a Bearer
           header, a `recon_token` cookie, or a one-shot ?token=... query
           parameter. The cookie is set automatically after query-param
           auth so subsequent navigation does not leak the token.
    require_auth: if True and no token is provided, a random one is
           generated and printed once to stdout.
    run_scheduler: when True, start the in-process recurring-scan
           scheduler alongside the HTTP server. Missed fires are not
           replayed; see :mod:`lib.scheduler` for details.
    """
    (ROOT / "results").mkdir(exist_ok=True)
    report.update_index()

    if token is None and require_auth:
        token = secrets.token_urlsafe(24)

    httpd = _Server((host, port), _Handler)
    httpd.auth_token = token

    sched_instance = None
    if run_scheduler:
        # Lazy import so a broken scheduler never prevents the dashboard
        # from serving static assets.
        from . import scheduler as _scheduler
        sched_instance = _scheduler.start_default()
        active = len(_scheduler.load_schedules())
        print(f"[+] Scheduler: {active} schedule(s) loaded")

    try:
        url = f"http://{host}:{port}/"
        print(f"[+] Dashboard: {url}")
        if token:
            # Print to stdout directly, never through the log file handler,
            # so the token doesn't get persisted to disk by accident.
            print(f"[+] Auth token: {token}")
            print(f"[+] Open {url}?token={token} once to set the session cookie")
        print("[+] Press Ctrl+C to stop")
        if open_browser:
            open_url = f"{url}?token={token}" if token else url
            threading.Timer(0.4, lambda: _safe_open(open_url)).start()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[+] Dashboard stopped")
    finally:
        if sched_instance is not None:
            from . import scheduler as _scheduler
            _scheduler.stop_default(timeout=2.0)
        httpd.server_close()


def _safe_open(url):
    # On Android (Termux), the stdlib webbrowser module cannot reach the
    # system browser because the Termux sandbox has no $DISPLAY and no
    # X-session. The launch_android.sh wrapper exports RECON_ANDROID_OPEN
    # (usually "termux-open-url") so we can shell out to the termux-api
    # bridge instead. Fall back to webbrowser.open on any failure so
    # desktop users keep getting a seamless experience.
    opener = os.environ.get("RECON_ANDROID_OPEN")
    if opener:
        cmd = opener.split()
        if shutil.which(cmd[0]):
            try:
                subprocess.Popen(
                    cmd + [url],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                )
                return
            except Exception:
                pass
    try:
        webbrowser.open(url)
    except Exception:
        pass
