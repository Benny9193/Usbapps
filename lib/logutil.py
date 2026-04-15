"""Shared logging setup for the recon toolkit.

Goal: replace the ad-hoc print(...) calls sprinkled through the CLI with a
real logger that supports -v/-q, optional file logging, and preserves the
"[+] / [!] / [-] / [x]" visual style the toolkit was originally printing.
"""
import logging
from pathlib import Path

_CONFIGURED = False

# Map log levels to the single-character prefix the CLI has always used so
# operators running the tool interactively still see the familiar output.
_PREFIX = {
    logging.DEBUG:    "[-]",
    logging.INFO:     "[+]",
    logging.WARNING:  "[!]",
    logging.ERROR:    "[x]",
    logging.CRITICAL: "[X]",
}


class _PrefixFormatter(logging.Formatter):
    def format(self, record):
        prefix = _PREFIX.get(record.levelno, f"[{record.levelname[0]}]")
        # Leave the raw message alone; callers use f-strings already.
        record.message = record.getMessage()
        return f"{prefix} {record.message}"


def setup(verbosity=0, quiet=False, log_file=None):
    """Configure the root logger. Idempotent so the dashboard command can be
    re-invoked in the same interpreter without stacking handlers.

    verbosity: 0 = INFO, 1 = DEBUG (+-v), negative under --quiet which shows
    only warnings/errors.
    """
    global _CONFIGURED

    if quiet:
        level = logging.WARNING
    elif verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.DEBUG
    else:
        level = logging.INFO

    root = logging.getLogger("recon")
    root.setLevel(level)
    root.propagate = False

    if _CONFIGURED:
        # Reconfigure level / handlers on a subsequent call.
        for h in list(root.handlers):
            root.removeHandler(h)

    stream = logging.StreamHandler()
    stream.setFormatter(_PrefixFormatter())
    stream.setLevel(level)
    root.addHandler(stream)

    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(path, encoding="utf-8")
        fh.setFormatter(_PrefixFormatter())
        fh.setLevel(logging.DEBUG)
        root.addHandler(fh)

    _CONFIGURED = True
    return root


def get(name=None):
    """Return a child logger under the `recon` namespace."""
    if name is None:
        return logging.getLogger("recon")
    return logging.getLogger(f"recon.{name}")
