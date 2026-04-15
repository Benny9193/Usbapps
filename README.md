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
  LaunchAdminCmd.bat  Self-elevating admin command prompt launcher
  autorun.inf         Windows AutoPlay descriptor (opens admin CMD)
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
    crypto.py         Password-based AEAD for results (scrypt + HMAC-SHA256)
    password_crack.py Hash auditor (md5/sha*/ntlm/$id$, dict + brute-force)
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

1. Copy the `Usbapps/` folder onto the **root** of your USB drive (so
   `autorun.inf` and `LaunchAdminCmd.bat` sit at `X:\`).
2. (Optional) Drop portable Nmap into `bin\nmap.exe` and portable Python under
   `bin\python\`. See `bin/README.txt` for where to get them.
3. Plug the drive in. Windows AutoPlay surfaces **"Launch Portable Recon
   Toolkit (Administrator CMD)"** as the top option - click it and
   approve the UAC prompt to drop straight into an elevated command
   prompt rooted at the drive. (On hosts where AutoRun from USB is still
   enabled, the admin prompt opens without any click.)
4. From that elevated prompt, run scans or start the dashboard:
   ```
   Launch.bat                                          :: opens the dashboard
   Launch.bat full example.com --wordlist config\wordlists\subdomains.txt
   Launch.bat scan 10.0.0.1
   Launch.bat dns example.com
   ```
   Refresh the browser (it also auto-refreshes every 10s) to see new sessions.

> **Why the AutoPlay click?** Since Windows 7, Microsoft disabled
> silent AutoRun execution from removable drives as an anti-malware
> measure. `autorun.inf` still controls the drive's label, icon, and
> the entry Windows advertises in the AutoPlay dialog, so a single
> click launches `LaunchAdminCmd.bat`, which then self-elevates via
> UAC. If you need zero-click behavior on a specific machine you
> trust, either re-enable AutoRun through Group Policy
> (`gpedit.msc` -> Computer Configuration -> Administrative Templates
> -> Windows Components -> AutoPlay Policies) or register a Task
> Scheduler trigger on drive-arrival events.

You can also launch the admin prompt manually at any time by
double-clicking `LaunchAdminCmd.bat`, or by right-clicking it and
choosing **Run as administrator**. The script checks its own token
with `net session`, re-launches itself via
`Start-Process -Verb RunAs` if it was started unelevated, and then
hands you an interactive `cmd.exe` session with the toolkit
directories prepended to `PATH`.

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

recon crack   [--hash HASH ...] [--hash-file FILE]
              [--wordlist PATH] [--algorithm {auto,md5,sha1,sha224,sha256,sha384,sha512,ntlm}]
              [--salt SALT] [--rules]
              [--brute-force --charset CHARS --min-length N --max-length N]
              [--timeout SECS] [--max-candidates N] [--target-label NAME]

recon encrypt [<session-id|path> ...] [--all | --older-than-days N]
              [--password-file FILE] [--output-dir DIR] [--keep]
recon decrypt [<session-id|path> ...] [--all | --older-than-days N]
              [--password-file FILE] [--output-dir DIR] [--keep]
recon rekey   [<session-id|path> ...] [--all | --older-than-days N]
              [--old-password-file FILE] [--new-password-file FILE]

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

## Encrypting results at rest

Reconnaissance output is sensitive: open ports, internal hostnames,
WHOIS contacts, subdomain inventories. When the toolkit lives on a USB
drive, that drive can be lost, stolen, or borrowed. `recon encrypt`
turns any session into a self-contained, password-protected blob you
can safely leave on shared media.

```bash
# Encrypt a session by id (matches the JSON and any nmap XML siblings)
python3 recon.py encrypt 20260415-094812_full_example.com

# Or point at any file directly, and stash the ciphertext elsewhere
python3 recon.py encrypt results/scan.json -o /mnt/usb/encrypted/

# Decrypt it back in place
python3 recon.py decrypt 20260415-094812_full_example.com
```

The password is read from `--password-file PATH`, the `RECON_PASSWORD`
environment variable, or an interactive `getpass` prompt (with
confirmation on encrypt). By default the source file is removed once
its `.enc` counterpart is written; pass `--keep` to leave the
plaintext in place.

The on-disk format is built on stdlib primitives so it works with the
portable Python builds the rest of the toolkit targets:

| Component       | Construction                                       |
|-----------------|----------------------------------------------------|
| Key derivation  | `hashlib.scrypt`, N=2^14 r=8 p=1, 16-byte salt     |
| Cipher          | HMAC-SHA256 in counter mode (PRF stream cipher)    |
| Authentication  | HMAC-SHA256 over `header \|\| ciphertext` (encrypt-then-MAC) |
| Nonce           | 16 random bytes per file                           |
| Tag             | 32 bytes, verified in constant time before decrypt |

A wrong password, tampered ciphertext, or even a single flipped salt
byte is rejected with `InvalidCiphertext` before any plaintext is
produced. See `lib/crypto.py` for the format header and proof
sketch.

### Bulk operations and rotation

```bash
# Encrypt every plaintext session under results/ in one shot
RECON_PASSWORD=hunter2 python3 recon.py encrypt --all

# Rotate only the stale stuff (mirrors `recon purge`)
python3 recon.py encrypt --older-than-days 30 --password-file pw.txt

# Bulk decrypt the same way
RECON_PASSWORD=hunter2 python3 recon.py decrypt --all

# Change the password without ever writing plaintext to disk.
# Old password is read from --old-password-file (or RECON_OLD_PASSWORD,
# or interactive prompt); new one with --new-password-file (or
# RECON_NEW_PASSWORD, or interactive prompt with confirmation).
python3 recon.py rekey --all \
    --old-password-file old.txt --new-password-file new.txt
```

`recon rekey` decrypts each blob into a Python `bytes` object,
re-encrypts it with the new key, and atomically replaces the file via
`os.replace`. The plaintext never touches disk and the source file is
only overwritten after the new password's tag has been computed, so a
wrong old password leaves the original file untouched.

### Always-on encryption

To keep sessions from ever landing as plaintext on the USB drive:

```toml
# config/recon.toml
encrypt_results = true
```

```bash
export RECON_PASSWORD=hunter2
python3 recon.py scan example.com         # writes <session>.json.enc
python3 recon.py dashboard --scheduler    # scheduler honors RECON_PASSWORD too
```

When `encrypt_results = true` is set and `RECON_PASSWORD` is missing,
`recon scan/dns/whois/full` refuse to run rather than silently leaving
plaintext on disk. `recon list` surfaces encrypted entries with an
`[enc]` marker (the timestamp, scan type, and target are recovered
from the canonical filename pattern even when the body is opaque).
`differ` and the `export` command transparently decrypt encrypted
sessions when `RECON_PASSWORD` is set, so `recon diff` and
`recon export` keep working under always-on mode.

### Known gaps

- The dashboard does not yet decrypt sessions on the fly. Sessions
  encrypted at rest still appear in the sidebar (with the `encrypted`
  flag) but clicking through requires `recon decrypt` first.
- Nmap XML siblings (`<session>.nmap.xml`) are encrypted by
  `recon encrypt <session-id>` but are not yet covered by the
  always-on `save_session` path. Run `recon encrypt --all`
  periodically to sweep them up.

## Password hash audits

`recon crack` walks a wordlist (and optionally a bounded brute-force
charset) against one or more hashes to flag weak credentials during an
authorised password-policy audit. Everything runs on the standard
library - `hashlib` for raw digests, `crypt(3)` for Unix `$id$` entries
when the platform still ships it. No hashcat, no John, no GPU.

```bash
# One-off hash, auto-detected as MD5 by its 32-char length
python3 recon.py crack \
    --hash 5f4dcc3b5aa765d61d8327deb882cf99 \
    --wordlist config/wordlists/subdomains.txt

# A shadow-style file with salted crypt entries, plus mangling rules
python3 recon.py crack \
    --hash-file /tmp/shadow.txt \
    --wordlist rockyou.txt --rules

# Fall back to brute force after the wordlist is exhausted
python3 recon.py crack \
    --hash $(echo -n 42 | sha1sum | awk '{print $1}') \
    --brute-force --charset 0123456789 --max-length 3
```

Accepted hash-file line formats (one per line, `#` starts a comment):

| Form                              | Example                                         |
|-----------------------------------|-------------------------------------------------|
| Bare hex hash                     | `5f4dcc3b5aa765d61d8327deb882cf99`              |
| Labeled hash                      | `alice:5f4dcc3b5aa765d61d8327deb882cf99`        |
| Labeled hash + salt               | `bob:5ebe2294ecd0e0f08eab7690d2a6ee69:NaCl`     |
| `/etc/shadow`-style crypt entry   | `root:$6$salt$digest:19000:0:99999:7:::`        |
| Bare crypt entry                  | `$1$salt$digest`                                |

Supported algorithms are auto-detected by length (`md5`, `sha1`,
`sha224`, `sha256`, `sha384`, `sha512`). Unix crypt entries are
identified from their `$id$` prefix (`$1$` md5crypt, `$5$` sha256crypt,
`$6$` sha512crypt, `$2[aby]$` bcrypt) and delegated to the stdlib
`crypt` module when present; on Python 3.13+ and Windows those hashes
are parsed and surfaced as `uncracked` with a `reason` instead. NTLM
hashes share a length with MD5, so select them explicitly with
`--algorithm ntlm`. Salts from `--salt` or per-line `label:hash:salt`
are tried in both append and prepend positions without extra
configuration.

The rule set (`--rules`) is intentionally compact: each wordlist entry
is combined with lower/upper/capitalize/reverse variants and a small
set of trailing tokens (`!`, `1`, `123`, `!@#`, recent years), which
catches the typical `Summer2025!` policy bypass without exploding a
large dictionary. Brute force is capped at eight characters and
supports `--min-length`, `--max-length`, `--timeout`, and
`--max-candidates` as guard rails so a bad charset cannot run away
with the machine.

Every run persists a regular session under `results/` with
`scan_type = "crack"`, so `recon list`, the dashboard sidebar, the
encrypt/decrypt commands and the markdown/HTML/CSV exporters all keep
working. Set `RECON_PASSWORD` before invoking `recon crack` to
auto-encrypt the results on save - handy because a cracked-password
report is precisely the sort of thing you do not want plaintext on a
USB drive.

> Authorised use only. `recon crack` exists to let operators report
> weak credentials during pentests, red-team engagements, and CTF
> practice. Only run it against hashes you own or have written
> permission to test.

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
