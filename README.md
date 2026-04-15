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
    nmap_runner.py    Nmap wrapper + rich XML parser (archives raw XML)
    dns_tools.py      Pure-Python DNS resolver (EDNS0, TCP fallback,
                      wildcard detection, AXFR, DMARC/SPF)
    port_scan.py      Threaded TCP/UDP scanner (IPv4 + IPv6)
    whois_tool.py     WHOIS client - IP-aware, chases referrals
    subdomain.py      Threaded subdomain brute force with wildcard filter
    report.py         Session persistence with mtime-cached index
    dashboard.py      Threaded local HTTP server (whitelisted, optional auth)
    logutil.py        Central logger with [+] / [!] / [-] prefixes
    differ.py         Session-to-session diff
    scheduler.py      Recurring scans + auto-diff (stdlib sched + thread)
    exporters.py      Markdown / HTML / CSV renderers
    netproxy.py       Optional HTTP CONNECT proxy client
  dashboard/
    index.html        Single-page UI
    style.css         Dark hacker-style theme
    app.js            Vanilla JS client (no frameworks)
  bin/                Drop portable Nmap / Python binaries here
  config/
    recon.toml        Optional defaults (TOML, Python 3.11+)
    schedules.json    Recurring scan definitions (managed by `recon schedule`)
    wordlists/
      subdomains.txt  Built-in subdomain wordlist (~200 entries)
  results/            Per-scan JSON files + nmap XML + index.json
  tests/              stdlib unittest suite - `python -m unittest discover -s tests`
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

Top-level flags (apply to every subcommand):

```
recon [-v | -q] [--log-file PATH] <subcommand> ...
```

Subcommands:

```
recon scan TARGET [-iL file] [--profile {quick,default,full,service,stealth}]
                  [--ports 1-1024|22,80,443] [--no-nmap]

recon dns  TARGET [-iL file] [--server 1.1.1.1] [--wordlist PATH]

recon whois TARGET [-iL file]

recon full TARGET [-iL file] [--profile ...] [--wordlist PATH] [--no-nmap]

recon dashboard [--host 127.0.0.1] [--port 8787] [--no-browser]
                [--token TOKEN | --auth] [--scheduler]

recon list
recon diff   <session-id-a> <session-id-b>
recon export <session-id> [--format {md,html,csv}] [-o FILE]
recon delete <session-id> [<session-id> ...]
recon purge  --older-than-days N [--dry-run]

recon schedule add    TARGET {scan,dns,full} --every 30s|5m|1h|1d
                      [--profile ...] [--wordlist PATH] [--ports PORTS]
                      [--server IP] [--no-nmap] [--disabled]
recon schedule list
recon schedule remove  <id>
recon schedule enable  <id>
recon schedule disable <id>
recon schedule run    [<id>]            # run now (all, or a specific entry)
recon schedule daemon                   # foreground scheduler (Ctrl+C to stop)
```

`TARGET` may be a hostname, an IPv4/IPv6 address, a CIDR block
(`10.0.0.0/24`), or a comma-separated list. `-iL FILE` reads one target
per line (# comments are allowed). Multiple targets produce one session
per host. The CLI returns exit code 0 on success, 2 if any module
reports an `error` field, 130 on Ctrl-C.

`recon full` now runs DNS, WHOIS, and subdomain brute-force concurrently
and pre-computes the wildcard answer set once so the workers share a
consistent baseline. Nmap still runs last.

Nmap profiles:

| Profile   | Flags                                         | Notes                         |
|-----------|-----------------------------------------------|-------------------------------|
| `quick`   | `-T4 -F`                                      | Top 100 ports, very fast      |
| `default` | `-T4 -sT -sV --top-ports 1000`                | Connect scan + service detect |
| `full`    | `-T4 -sT -sV -p-`                             | All 65535 ports               |
| `service` | `-T4 -sV -sC`                                 | Service + default scripts     |
| `stealth` | `-T2 -sS -f`                                  | SYN scan, needs root          |

Pass `--no-nmap` (or simply do not place an Nmap binary on the system) to use
the Python TCP connect scanner. It supports IPv4+IPv6, protocol-aware
banner grabs (HTTP HEAD, SMTP EHLO, ...), and a UDP probe mode for
DNS/NTP/SNMP/IKEv1/SSDP via `--protocol udp`.

## Scheduled scans & auto-diff

Turn the toolkit into a low-touch monitoring station by persisting
recurring jobs to `config/schedules.json`:

```bash
python3 recon.py schedule add example.com full --every 1h \
    --wordlist config/wordlists/subdomains.txt
python3 recon.py schedule list
python3 recon.py dashboard --scheduler    # starts the daemon alongside the UI
```

Each fire runs the configured workflow (`scan` / `dns` / `full`) and
auto-diffs the result against the most recent previous session for the
same target using `lib/differ.py`. The delta is written back into the
fresh session under `diff_against_previous`, so the dashboard's
**Changes** tab surfaces new/removed ports, subdomain churn, DNS record
deltas, and WHOIS expiry shifts without any extra lookups.

The scheduler is a simple in-process `sched.scheduler` driven by a
daemon thread - no cron, no systemd, no OS privileges. Missed fires
(e.g. laptop was asleep) are intentionally not replayed; on startup each
entry is scheduled relative to `last_run_epoch + interval_seconds`,
falling forward if that moment is already in the past. Every fire
re-reads `schedules.json`, so `recon schedule disable ...` takes effect
without restarting the daemon.

Run the scheduler without the HTTP UI:

```bash
python3 recon.py schedule daemon          # foreground, Ctrl+C to stop
python3 recon.py schedule run <id>        # trigger once, now
```

## Configuration file

`config/recon.toml` is optional. When present, it is loaded at startup
(Python 3.11+) and its values become argparse defaults, so explicit
flags still win. See the shipped sample for the honored keys.

## HTTP proxy

The WHOIS client honours `HTTPS_PROXY` / `ALL_PROXY`, speaking HTTP
CONNECT through the proxy. UDP-based paths (DNS, UDP port scanner)
stay direct because CONNECT cannot tunnel UDP.

## Dashboard

- **Summary** - target, stats, service distribution bar chart
- **Changes** - auto-diff vs. the previous session for the same target
  (ports added/removed, subdomain churn, DNS record deltas, WHOIS expiry shift)
- **Nmap** - per-host ports, services, versions, OS guess, script output
- **Ports** - aggregated open port table across Nmap and the Python scanner
- **DNS** - A/AAAA/NS/MX/TXT/CNAME/SOA/CAA + reverse PTR
- **Subdomains** - wordlist brute-force results
- **WHOIS** - parsed fields + raw response
- **Raw JSON** - the full session document for scripting / grepping

The sidebar also surfaces active **Schedules** with a status dot
(green = unchanged, amber = changed, red = error). Clicking a schedule
jumps to its most recent session.

The sidebar search filters sessions by target or type. Sessions auto-refresh
every 10 seconds so live scans populate without manual reloads.

The dashboard only serves `/dashboard/` and `/results/`; everything else
returns 404, path traversal is rejected, and strict security headers
(CSP, X-Frame-Options, Referrer-Policy, no-sniff) are sent on every
response. Passing `--auth` to `recon dashboard` generates a bearer
token and requires it via header, cookie, or one-shot `?token=...` URL
parameter before serving anything.

---

## Tests

```
python -m unittest discover -s tests -v
```

The suite uses stdlib `unittest` only and never reaches the network;
resolvers and sockets are either monkey-patched or point at 127.0.0.1
listeners started inside the tests.

---

## Responsible use

This toolkit is intended for authorised security testing, CTF practice and
learning. Only run it against systems you own or have explicit permission to
test.
