Portable binaries go here
=========================

This directory is searched first for external tools. If a tool is not
found here the toolkit falls back to whatever is on your PATH (or to a
pure-Python equivalent where applicable).

Supported layouts:

    bin/
        nmap.exe            <- Windows, portable Nmap binary
        nmap/nmap.exe       <- Windows, extracted Nmap folder
        nmap                <- Linux/macOS
        python/python.exe   <- Windows, portable Python distribution
        python/bin/python3  <- Linux/macOS, portable Python

Recommended portable builds
---------------------------

Nmap (Windows)
    Download the "Latest stable release - Zip autoinstaller" or the portable
    binary package from https://nmap.org/download.html and extract nmap.exe
    plus its support DLLs into bin/ (or bin/nmap/).

Nmap (Linux / macOS)
    Use your distro package manager, or extract a statically linked build into
    bin/ and make it executable (chmod +x bin/nmap).

Python (Windows)
    Grab the "embeddable package" ZIP from https://www.python.org/downloads/
    and extract it under bin/python/. Launch.bat will detect it automatically.

Python (Linux / macOS)
    Either rely on the system python3, or drop a relocatable build under
    bin/python/bin/python3.

If you do not have Nmap available, the toolkit will silently fall back to a
pure-Python TCP connect scanner so scan, dns, whois and dashboard commands
still work end-to-end.
