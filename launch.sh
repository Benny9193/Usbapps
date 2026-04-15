#!/usr/bin/env bash
# Portable Recon Toolkit launcher (Linux / macOS)
# Defaults to starting the dashboard; forwards any arguments to recon.py.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PY=""
if [ -x "bin/python/bin/python3" ]; then
    PY="bin/python/bin/python3"
elif [ -x "bin/python/python3" ]; then
    PY="bin/python/python3"
elif command -v python3 >/dev/null 2>&1; then
    PY="python3"
elif command -v python >/dev/null 2>&1; then
    PY="python"
else
    echo "[!] Python 3 not found. Install python3 or drop a portable build under bin/python/."
    exit 1
fi

if [ $# -eq 0 ]; then
    echo "[+] Launching dashboard..."
    exec "$PY" "$SCRIPT_DIR/recon.py" dashboard
else
    exec "$PY" "$SCRIPT_DIR/recon.py" "$@"
fi
