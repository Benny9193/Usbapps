#!/data/data/com.termux/files/usr/bin/env bash
# Portable Recon Toolkit - one-time Android / Termux setup.
#
# Run this once from a fresh Termux install to pull in the Python interpreter,
# Nmap, and the optional termux-api bridge (needed so the toolkit can pop the
# dashboard open in Android's default browser). The script is idempotent - it
# only installs what is missing, so re-running it is safe.
#
# Usage:
#   ./setup_android.sh           # install everything
#   ./setup_android.sh --minimal # skip termux-api (no browser auto-open)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -z "${PREFIX:-}" ] || [ ! -d "$PREFIX" ]; then
    echo "[!] \$PREFIX is not set - this script is meant to run inside Termux."
    echo "    Install Termux from F-Droid (https://f-droid.org/en/packages/com.termux/)"
    echo "    and re-run ./setup_android.sh from the Termux shell."
    exit 1
fi

if ! command -v pkg >/dev/null 2>&1; then
    echo "[!] 'pkg' command not found. Are you really running in Termux?"
    exit 1
fi

MINIMAL=0
for arg in "$@"; do
    case "$arg" in
        --minimal) MINIMAL=1 ;;
        -h|--help)
            sed -n '2,15p' "$0"
            exit 0
            ;;
        *) echo "[!] Unknown flag: $arg"; exit 2 ;;
    esac
done

echo "[+] Refreshing Termux package index..."
pkg update -y >/dev/null
pkg upgrade -y >/dev/null

install_pkg() {
    local name="$1"
    if dpkg -s "$name" >/dev/null 2>&1; then
        echo "    [=] $name already installed"
    else
        echo "    [+] installing $name"
        pkg install -y "$name" >/dev/null
    fi
}

echo "[+] Installing core packages..."
install_pkg python
install_pkg nmap

if [ "$MINIMAL" -eq 0 ]; then
    echo "[+] Installing optional helpers..."
    install_pkg termux-api
    cat <<'NOTE'
    [i] termux-api installed. You also need the companion Android app:
        https://f-droid.org/en/packages/com.termux.api/
        Install it from F-Droid so 'termux-open-url' can reach the browser.
NOTE
fi

# Termux keeps user files on the per-app private partition by default. Running
# `termux-setup-storage` drops a ~/storage/ symlink tree that lets you share
# wordlists and results with the rest of Android. Skip silently if the user
# has not granted the permission yet.
if command -v termux-setup-storage >/dev/null 2>&1 && [ ! -d "$HOME/storage" ]; then
    echo "[+] Requesting shared storage access (accept the Android prompt)..."
    termux-setup-storage || true
fi

echo
echo "[+] Setup complete. Next steps:"
echo "    ./launch_android.sh                 # start the dashboard"
echo "    ./launch_android.sh scan 10.0.0.1   # run a one-off scan"
echo "    ./launch_android.sh full example.com"
echo
if [ "$(id -u)" -ne 0 ]; then
    echo "[i] Termux runs as an unprivileged user, so Nmap SYN scans (-sS / stealth"
    echo "    profile) will refuse to run. Stick to 'quick', 'default', 'full', or"
    echo "    'service' profiles, which use TCP connect scans."
fi
