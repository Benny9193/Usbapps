#!/data/data/com.termux/files/usr/bin/env bash
# Portable Recon Toolkit launcher for Android (Termux).
#
# Wraps recon.py with Termux-aware conveniences:
#   * Uses the Termux Python build ($PREFIX/bin/python) when present.
#   * Falls back to the generic python3 on other Android shells (SSH to Linux
#     chroot, Andronix, UserLAnd, ...).
#   * Defaults the dashboard to 127.0.0.1:8787 and pops it open via
#     termux-open-url (from termux-api) when available.
#   * Skips scan types / profiles that need root on an unrooted device.
#
# Usage:
#   ./launch_android.sh                          # start the dashboard
#   ./launch_android.sh scan 10.0.0.1            # run a one-off scan
#   ./launch_android.sh full example.com --wordlist config/wordlists/subdomains.txt
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Prefer the Termux interpreter so we pick up its cert bundle and $PREFIX
# search paths automatically. Fall back to a system python3 for non-Termux
# Android shells (Debian chroot, Andronix, Kali-NetHunter, ...).
PY=""
if [ -n "${PREFIX:-}" ] && [ -x "$PREFIX/bin/python" ]; then
    PY="$PREFIX/bin/python"
elif [ -x "bin/python/bin/python3" ]; then
    PY="bin/python/bin/python3"
elif command -v python3 >/dev/null 2>&1; then
    PY="python3"
elif command -v python >/dev/null 2>&1; then
    PY="python"
else
    cat <<'ERR' >&2
[!] No Python interpreter found.

    On Termux:           pkg install python
    On Debian chroot:    apt install python3
    Or run ./setup_android.sh to install everything in one shot.
ERR
    exit 1
fi

PY_VERSION="$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo "?")"
echo "[+] Python $PY_VERSION ($PY)"

# Warn if Nmap is missing. The toolkit still works with the built-in pure-Python
# scanner, so this is informational only.
if ! command -v nmap >/dev/null 2>&1 && [ ! -x "bin/nmap" ]; then
    echo "[i] Nmap not found - scans will use the pure-Python fallback."
    echo "    Install it with: pkg install nmap"
fi

# Termux inherits the environment from the launching Intent, which often
# leaves TMPDIR unset. Several stdlib helpers (tempfile, subprocess) will then
# fall back to /tmp, which is not writable on Android. Point them at Termux's
# private scratch dir when needed.
if [ -n "${PREFIX:-}" ] && [ -z "${TMPDIR:-}" ]; then
    export TMPDIR="$PREFIX/tmp"
    mkdir -p "$TMPDIR"
fi

# Let the dashboard pick the right "open browser" command on Termux. The
# dashboard module checks RECON_ANDROID_OPEN before falling back to the stdlib
# webbrowser module (which cannot reach Android's browser from Termux).
if [ -z "${RECON_ANDROID_OPEN:-}" ] && command -v termux-open-url >/dev/null 2>&1; then
    export RECON_ANDROID_OPEN="termux-open-url"
fi

# Mark the process so lib/* can light up Android-specific code paths without
# having to sniff $PREFIX everywhere.
export RECON_ANDROID=1

if [ $# -eq 0 ]; then
    echo "[+] Launching dashboard on http://127.0.0.1:8787/ ..."
    echo "[+] Press Ctrl+C (or swipe Termux away) to stop."
    exec "$PY" "$SCRIPT_DIR/recon.py" dashboard --host 127.0.0.1 --port 8787
else
    exec "$PY" "$SCRIPT_DIR/recon.py" "$@"
fi
