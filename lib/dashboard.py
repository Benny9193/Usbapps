"""Minimal HTTP server that serves the dashboard assets and result JSON."""
import http.server
import socketserver
import threading
import webbrowser
from pathlib import Path

from . import report

ROOT = Path(__file__).resolve().parents[1]


class _Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self):
        if self.path in ("/", ""):
            self.path = "/dashboard/index.html"
        return super().do_GET()

    def end_headers(self):
        # Disable caching so fresh scans appear without a hard refresh.
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass  # silence default access log


class _ReusableServer(socketserver.TCPServer):
    allow_reuse_address = True


def serve(host="127.0.0.1", port=8787, open_browser=True):
    (ROOT / "results").mkdir(exist_ok=True)
    report.update_index()

    with _ReusableServer((host, port), _Handler) as httpd:
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
