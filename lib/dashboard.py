"""Minimal HTTP server that serves the dashboard assets and result JSON."""
import http.server
import posixpath
import threading
import urllib.parse
import webbrowser
from pathlib import Path

from . import report

ROOT = Path(__file__).resolve().parents[1]

# Only these URL prefixes are served. Everything else returns 404, including
# lib/, bin/, .git/, config/, and any stray files at the repo root.
ALLOWED_PREFIXES = ("/dashboard/", "/results/")

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
    return any(path == p.rstrip("/") or path.startswith(p) for p in ALLOWED_PREFIXES)


class _Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self):
        normalized = _normalize(self.path)
        if normalized is None or not _is_allowed(normalized):
            self.send_error(404, "Not Found")
            return
        if normalized in ("/", ""):
            normalized = "/dashboard/index.html"
        self.path = normalized
        return super().do_GET()

    def do_HEAD(self):
        normalized = _normalize(self.path)
        if normalized is None or not _is_allowed(normalized):
            self.send_error(404, "Not Found")
            return
        if normalized in ("/", ""):
            normalized = "/dashboard/index.html"
        self.path = normalized
        return super().do_HEAD()

    def end_headers(self):
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        super().end_headers()

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass  # silence default access log


class _Server(http.server.ThreadingHTTPServer):
    """Threaded so one slow client cannot block the rest of the dashboard."""

    allow_reuse_address = True
    daemon_threads = True


def serve(host="127.0.0.1", port=8787, open_browser=True):
    (ROOT / "results").mkdir(exist_ok=True)
    report.update_index()

    with _Server((host, port), _Handler) as httpd:
        url = f"http://{host}:{port}/"
        print(f"[+] Dashboard: {url}")
        print("[+] Press Ctrl+C to stop")
        if open_browser:
            threading.Timer(0.4, lambda: _safe_open(url)).start()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[+] Dashboard stopped")


def _safe_open(url):
    try:
        webbrowser.open(url)
    except Exception:
        pass
