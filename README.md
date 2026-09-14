# nids - a small Snort-style NIDS

A live network intrusion detection tool. Sniffs traffic with Scapy, checks
every packet against alert rules in [`rules.txt`](rules.txt), and layers on
a couple of built-in detectors (port scans, ARP spoofing) that don't need a
rule written for them. GUI's built with FreeSimpleGUI: watch alerts come
in, dig into TCP/HTTP2 streams, pull HTTP objects out of captured traffic.
Anything downloaded over plain HTTP also gets checked against whatever's in
[`yara_rules/`](yara_rules).

## Before you run this on a real network

This captures and stores *everything* crossing the interface you pick. Only
run it on a network you actually own or have explicit permission to
monitor; watching traffic you're not authorized to see can be illegal
depending on where you are. The app asks you to confirm this every single
launch, not just the first time, because being cleared to monitor one
network doesn't mean you're cleared on the next one. There's no way to
skip that prompt, on purpose.

## Requirements

- Python 3.10+
- [Npcap](https://npcap.com/) (Windows) so Scapy can actually capture traffic
- [Wireshark](https://www.wireshark.org/) installed, for `tshark` (pyshark
  needs it for the stream inspector)
- `pip install -r requirements.txt` - versions are pinned to whatever this
  has actually been tested against

Live capture needs Administrator rights on Windows, basically always.

## Running

```
python nids.py
```

Confirm the authorization prompt, pick your capture interface from the
dropdown (defaults to whichever adapter has a real routable IPv4 address),
hit **STARTCAP**. **ALERT PACKETS** / **ALL PACKETS** start filling in.
**STOPCAP** actually stops it now. If the capture thread dies on its own
(adapter got unplugged, driver hiccup) the app notices and resets itself
instead of just sitting there showing "Capturing..." with nothing actually
happening. Type into the **Filter** box to narrow both lists down to
whatever you're looking for - an IP, a port, doesn't matter.

## Rules

Rules, the port-scan detector, and alert storage all handle IPv4 and IPv6
the same way. An IPv4-only rule won't ever match an IPv6 address by
accident, and vice versa; `any` and CIDR fields work fine for either.

Each `alert`-prefixed line in `rules.txt` is one rule:

```
alert <protocol> <src ip> <src port> -> <dst ip> <dst port> <message...>
```

Any field can just be `any`. IPs take CIDR ranges (`192.168.1.0/24`), ports
take ranges too, written `low:high` (leave either side blank for 0 or
65535). Example:

```
alert udp any any -> any 53 DNS ALERT
alert tcp 10.0.0.0/24 any -> any 4444:4450 Possible reverse shell
```

**REFRESH RULES** reloads `rules.txt` without restarting capture. **ADD
RULE** opens a small form for building one instead of hand-editing the
file - it just appends to `rules.txt` and reloads.

### Content matching

Tack `content:"some substring"` onto a rule and it'll only match packets
whose TCP/UDP payload actually contains that text. Good for catching
cleartext protocols doing something specific:

```
alert tcp any any -> any 21 Possible cleartext FTP credentials content:"PASS " redact
```

### Redacting sensitive matches

Add a bare `redact` flag (see the FTP rule above) and when that rule fires,
the payload doesn't get stored or shown anywhere - not the GUI's payload
pane, not `alerts.db`. You get a placeholder instead. Use it on anything
whose `content:` is fishing for an actual secret, so the secret itself
doesn't end up sitting around in plaintext later. The built-in FTP rule
already does this.

### Rate-based rules (thresholds)

`threshold: count N, seconds T` turns a rule from "alert on every match"
into "alert once the same source IP has hit this N times in T seconds"
(then it resets). Keeps brute-force attempts and query floods from turning
into one alert per packet:

```
alert tcp any any -> any 22 Possible SSH brute force threshold: count 10, seconds 30
```

`content:`, `redact`, and `threshold:` can all show up on the same rule at once.

### Alert deduplication

Separately from thresholds: the same alert firing repeatedly (same
message, same source/destination) within `ALERT_DEDUP_WINDOW_SECONDS`
(15s by default) gets collapsed into one row with a running `(xN)` count
instead of spamming the list. A burst of DNS lookups to the same resolver
just shows up as one alert that keeps ticking up.

### Built-in port-scan detector

Not a rule, just always on: if a single source IP touches enough distinct
destination ports in a short window (15 ports in 5 seconds by default) it
raises a "Possible port scan from..." alert on its own. Tune
`PORTSCAN_DISTINCT_PORTS`/`PORTSCAN_WINDOW_SECONDS` near the top of
`nids.py` if that's too twitchy or not twitchy enough for your network.

### Built-in ARP-spoof detector

Also always on: if the same IP suddenly gets claimed by a different MAC
address in ARP traffic, that's the classic ARP-poisoning/MITM pattern, and
it fires a "Possible ARP spoofing" alert automatically.

## Malware scanning (YARA)

Anything `read_http()` pulls out of captured plain-HTTP traffic (via
**LOAD HTTP STREAMS**) gets scanned against every `.yar`/`.yara` file in
[`yara_rules/`](yara_rules). A match turns into a real alert: shows up in
**ALERT PACKETS**, triggers the beep/webhook, gets saved to `alerts.db`,
same treatment as anything from `rules.txt`.

Drop your own rules into `yara_rules/` and hit **REFRESH YARA RULES** to
pick them up without restarting. Two ship as a starting point
([`yara_rules/starter.yara`](yara_rules/starter.yara)):

- `PE_FILE_HEADER` - catches embedded/extracted Windows executables
- `EICAR_Test_File` - the industry-standard AV test string, not real
  malware, just handy for confirming the whole scan pipeline actually
  works. [EICAR's test file](https://www.eicar.org/download-anti-malware-testfile/)
  exists exactly for this

Only reconstructed files get scanned, not every raw packet. That's on
purpose - YARA's meant for whole-file matching, and running it against
every single packet would just be slow for no benefit. If `yara-python`
isn't installed, or `yara_rules/` is empty, scanning just quietly turns
itself off; you'll see a warning in the log and nothing else changes.

One real gotcha worth knowing about: there's an old, abandoned PyPI
package literally called `yara` (not `yara-python`) that installs the same
top-level `yara` module name. If it's ever installed alongside the real
one, Python can silently import the wrong one and scanning breaks with
confusing errors. Quick check: `import yara; yara.__version__` should
start with `4.`. If it doesn't, `pip uninstall yara` (no `-python`) and
reinstall from `requirements.txt`.

## Alert history

Every alert, whether it came from `rules.txt` or one of the built-in
detectors, gets written to a local SQLite database (`alerts.db`) as it
happens. Unlike the in-memory list in the GUI, this survives restarting
the app. **ALERT HISTORY** shows the last 200 across every past session.
Rows older than `NIDS_ALERTS_RETENTION_DAYS` (90 by default) get pruned
automatically on startup so the file doesn't just grow forever; set it to
`0` if you want to keep everything.

## Getting notified without watching the window

- **Sound** - every genuinely new alert (dedup repeats don't count) plays
  a Windows system sound.
- **Webhook** - point the `NIDS_WEBHOOK_URL` environment variable at a
  Slack/Discord/Teams incoming-webhook URL, or really any endpoint that'll
  accept a JSON POST, and every new alert gets sent there too:
  `{"text": "...", "message": "...", "src_ip": "...", "dst_ip": "..."}`.
  Runs on its own thread, so a dead endpoint just logs a warning instead
  of stalling capture.

## Logs

Everything gets logged to `nids.log` next to `nids.py` as well as the
console (rotating at 2MB, 5 backups), so there's still a record even if
this ends up running with no terminal attached.

## Running unattended / at startup

`nids.py` needs a desktop and live capture access, so it can't run as an
actual headless Windows service (services live in session 0, no desktop,
no capture). [`install-autostart.ps1`](install-autostart.ps1) sets up a
per-user Scheduled Task that launches it at logon instead, which is about
as close as a GUI app can get:

```powershell
.\install-autostart.ps1              # register
.\install-autostart.ps1 -Uninstall   # remove
```

You'll still have to click through the authorization prompt and STARTCAP
yourself - that's intentional, so it never starts monitoring anything
without a person actively confirming it on that specific launch.

## TLS-decrypted HTTP/2 stream inspection

HTTP/2 is almost always over TLS, so the HTTP/2 stream list is usually
just empty unless pyshark can decrypt it. Set `NIDS_SSLKEYLOGFILE` to a
TLS key log file (the same kind `SSLKEYLOGFILE` produces from a browser)
before launching, and it can.

## Tests

```
pip install -r requirements.txt   # includes pytest
pytest
```

[`tests/test_nids.py`](tests/test_nids.py) covers rule parsing and
matching (IPv6, port ranges, content matching, redaction, all of it), the
threshold/port-scan/ARP-spoof detectors including their stale-entry
cleanup, HTTP object extraction plus the YARA scanning on top of it, alert
dedup, retention pruning, and the webhook notifier. All built with
hand-made Scapy packets, temp files, and a throwaway local HTTP server -
none of it needs a live capture or admin rights to run.

## Packaging as a standalone executable

Didn't do this part - a bundled GUI + Npcap + tshark executable isn't
something I can verify without an actual desktop session in front of it,
so rather than hand over an untested binary, here's just how to build your
own:

```
pip install pyinstaller
pyinstaller --noconfirm --onedir --name nids --add-data "rules.txt;." --add-data "yara_rules;yara_rules" nids.py
```

`--onedir`, not `--onefile`, so Npcap/tshark can still be found on PATH at
runtime instead of needing to be bundled in. Actually run the built
`dist/nids/nids.exe` yourself before trusting it - check STARTCAP still
works as Administrator, and that `rules.txt`, `yara_rules/`, `temp/`,
`savedpcap/`, `alerts.db`, and `nids.log` all show up next to the `.exe`.
Should happen automatically since everything resolves relative to its own
file location, but worth double-checking after a fresh build.

## Known limitations

- `PacketStore` caps how many raw packets it holds in memory
  (`MAX_STORED_PACKETS`, 20000 by default), dropping the oldest once it's
  full, so a long capture on a busy link doesn't just eat all the RAM. The
  in-memory alert list isn't capped the same way - dedup and thresholds
  already keep its volume down - but a genuinely noisy ruleset over a
  really long session could still grow it. Use **SAVE ALERT** and restart
  capture periodically if that ever becomes an issue. The detectors' own
  per-IP tracking dicts get swept for stale entries roughly every 5
  minutes, so watching a lot of distinct source IPs over a long deployment
  doesn't grow those forever either.
- Rules match on protocol, IP/CIDR, port/port-range, and an optional
  literal payload substring. No regex, no multi-step attack patterns
  beyond the two built-in detectors.
- Files this writes (`alerts.db`, `savedpcap/*.pcap`, `nids.log`) use
  whatever the default OS permissions are, nothing locked down to just
  your account. Fine on a personal machine. On a shared one, worth
  remembering that any rule without `redact` set stores its real payload
  in plaintext, and so does any saved pcap.
- Windows-only (`scapy.arch.windows` gets imported unconditionally) and
  GUI-only, so no running this headless on a server.
