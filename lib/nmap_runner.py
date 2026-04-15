"""Nmap wrapper - locates binary and parses XML output into JSON."""
import os
import platform
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin"

# Profile flags are appended to the nmap binary when the user selects them.
# Keep them intentionally modest so they run on unprivileged Windows/Linux
# Python builds (the TCP SYN scans require root/Administrator, so we fall back
# to connect scans via -sT when the caller passes --no-nmap).
PROFILES = {
    "quick":   ["-T4", "-F"],
    "default": ["-T4", "-sT", "-sV", "--top-ports", "1000"],
    "full":    ["-T4", "-sT", "-sV", "-p-"],
    "service": ["-T4", "-sV", "-sC"],
    "stealth": ["-T2", "-sS", "-f"],
}


def find_binary():
    """Return the path to an nmap binary: portable copy first, then PATH."""
    exe = "nmap.exe" if platform.system() == "Windows" else "nmap"
    local = BIN / exe
    if local.is_file():
        return str(local)
    # Portable distributions sometimes ship in bin/nmap/
    nested = BIN / "nmap" / exe
    if nested.is_file():
        return str(nested)
    return shutil.which("nmap")


def is_available():
    return find_binary() is not None


def scan(target, profile="default", ports=None):
    binary = find_binary()
    if not binary:
        return {"error": "Nmap not found. Place portable nmap in bin/ or install it."}

    flags = list(PROFILES.get(profile, PROFILES["default"]))
    if ports:
        # Strip any conflicting port flags from the profile.
        cleaned = []
        skip = False
        for flag in flags:
            if skip:
                skip = False
                continue
            if flag in ("-p", "--top-ports"):
                skip = True
                continue
            if flag.startswith("-p") or flag.startswith("--top-ports="):
                continue
            cleaned.append(flag)
        flags = cleaned + ["-p", ports]

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name

    cmd = [binary] + flags + ["-oX", xml_path, target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if proc.returncode not in (0, 1):
            return {
                "command": " ".join(cmd),
                "error": (proc.stderr or proc.stdout or "nmap failed").strip(),
                "returncode": proc.returncode,
            }
        result = parse_xml(xml_path)
        result["command"] = " ".join(cmd)
        result["profile"] = profile
        return result
    except subprocess.TimeoutExpired:
        return {"command": " ".join(cmd), "error": "nmap timeout (600s)"}
    except FileNotFoundError as exc:
        return {"command": " ".join(cmd), "error": str(exc)}
    finally:
        try:
            os.unlink(xml_path)
        except OSError:
            pass


def parse_xml(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        state = status.get("state") if status is not None else "unknown"

        addr = None
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr")
                break

        hostnames = []
        hn = host.find("hostnames")
        if hn is not None:
            for h in hn.findall("hostname"):
                hostnames.append(h.get("name"))

        ports = []
        pe = host.find("ports")
        if pe is not None:
            for p in pe.findall("port"):
                pstate = p.find("state")
                svc = p.find("service")
                scripts = []
                for s in p.findall("script"):
                    scripts.append({"id": s.get("id"), "output": s.get("output")})
                ports.append({
                    "port": int(p.get("portid")),
                    "protocol": p.get("protocol"),
                    "state": pstate.get("state") if pstate is not None else None,
                    "service": svc.get("name") if svc is not None else None,
                    "product": svc.get("product") if svc is not None else None,
                    "version": svc.get("version") if svc is not None else None,
                    "extra_info": svc.get("extrainfo") if svc is not None else None,
                    "scripts": scripts,
                })

        os_info = None
        oe = host.find("os")
        if oe is not None:
            match = oe.find("osmatch")
            if match is not None:
                os_info = {
                    "name": match.get("name"),
                    "accuracy": match.get("accuracy"),
                }

        hosts.append({
            "address": addr,
            "state": state,
            "hostnames": hostnames,
            "ports": ports,
            "os": os_info,
        })

    return {
        "hosts": hosts,
        "args": root.attrib.get("args"),
        "version": root.attrib.get("version"),
        "start": root.attrib.get("startstr"),
    }
