# Portable Recon Toolkit

A self-contained reconnaissance toolkit you can drop onto a USB drive and run
anywhere. Combines **Nmap**, pure-Python **DNS tools**, **WHOIS**, subdomain
enumeration, a fallback TCP port scanner, and a dark-themed **visual dashboard**
served from a tiny local HTTP server.

- No `pip install` needed - the Python side uses only the standard library.
- Offline dashboard - no CDNs, no external fonts, no telemetry.
- Works with portable Nmap under `bin/` or falls back to a pure-Python scanner.
- Every scan is written to `results/` as JSON; the dashboard reads it directly.

---

## Layout

```
Usbapps/
  Launch.bat          Windows one-click launcher (starts the dashboard)
  launch.sh           Linux / macOS launcher
  recon.py            CLI entry point
  lib/                Toolkit modules (stdlib-only Python)
    nmap_runner.py    Nmap wrapper + XML parser
    dns_tools.py      Pure-Python DNS resolver (A/AAAA/NS/MX/TXT/SOA/CAA...)
    port_scan.py      Threaded TCP connect scanner (Nmap fallback)
    whois_tool.py     WHOIS client with IANA referral chasing
    subdomain.py      Threaded subdomain brute force
    report.py         Session persistence / index for the dashboard
    dashboard.py      Local HTTP server
  dashboard/
    index.html        Single-page UI
    style.css         Dark hacker-style theme
    app.js            Vanilla JS client (no frameworks)
  bin/                Drop portable Nmap / Python binaries here
  config/
    wordlists/
      subdomains.txt  Built-in subdomain wordlist (~200 entries)
  results/            Per-scan JSON files + index.json (created on demand)
```

---

## Quick start

### Windows

1. Copy the `Usbapps/` folder onto your USB drive.
2. (Optional) Drop portable Nmap into `bin\nmap.exe` and portable Python under
   `bin\python\`. See `bin/README.txt` for where to get them.
3. Double-click `Launch.bat` - it opens the dashboard at
   <http://127.0.0.1:8787/>.
4. From a separate terminal run scans:
   ```
   Launch.bat full example.com --wordlist config\wordlists\subdomains.txt
   Launch.bat scan 10.0.0.1
   Launch.bat dns example.com
   ```
   Refresh the browser (it also auto-refreshes every 10s) to see new sessions.

### Linux / macOS

```bash
cd Usbapps
./launch.sh                                 # opens the dashboard
./launch.sh full example.com                # full recon workflow
./launch.sh dns example.com --wordlist config/wordlists/subdomains.txt
./launch.sh scan 10.0.0.1 --profile quick
```

You can also invoke the Python entry point directly:

```bash
python3 recon.py dashboard
python3 recon.py full example.com
```

---

## CLI reference

```
recon scan TARGET [--profile {quick,default,full,service,stealth}]
                  [--ports 1-1024|22,80,443] [--no-nmap]

recon dns  TARGET [--server 1.1.1.1] [--wordlist PATH]

recon whois TARGET

recon full TARGET [--profile ...] [--wordlist PATH] [--no-nmap]

recon dashboard [--host 127.0.0.1] [--port 8787] [--no-browser]

recon list
```

Nmap profiles:

| Profile   | Flags                                         | Notes                         |
|-----------|-----------------------------------------------|-------------------------------|
| `quick`   | `-T4 -F`                                      | Top 100 ports, very fast      |
| `default` | `-T4 -sT -sV --top-ports 1000`                | Connect scan + service detect |
| `full`    | `-T4 -sT -sV -p-`                             | All 65535 ports               |
| `service` | `-T4 -sV -sC`                                 | Service + default scripts     |
| `stealth` | `-T2 -sS -f`                                  | SYN scan, needs root          |

Pass `--no-nmap` (or simply do not place an Nmap binary on the system) to use
the Python TCP connect scanner. It supports banner grabs and the most common
service mappings.

## Dashboard

- **Summary** - target, stats, service distribution bar chart
- **Nmap** - per-host ports, services, versions, OS guess, script output
- **Ports** - aggregated open port table across Nmap and the Python scanner
- **DNS** - A/AAAA/NS/MX/TXT/CNAME/SOA/CAA + reverse PTR
- **Subdomains** - wordlist brute-force results
- **WHOIS** - parsed fields + raw response
- **Raw JSON** - the full session document for scripting / grepping

The sidebar search filters sessions by target or type. Sessions auto-refresh
every 10 seconds so live scans populate without manual reloads.

---

## Responsible use

This toolkit is intended for authorised security testing, CTF practice and
learning. Only run it against systems you own or have explicit permission to
test.
