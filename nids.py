"""
nids.py - my little Snort-style NIDS.

Basic idea: sniff live traffic with Scapy, run every packet past the rules
in rules.txt, show whatever gets flagged in a FreeSimpleGUI window. Also
lets me dig into TCP streams / HTTP2 streams / dropped HTTP objects after
the fact.

Needs Npcap installed (Windows) to actually capture anything, and tshark
on PATH if I want the stream-inspector buttons to work. Have to run as
admin or capture just refuses to start.
"""

import binascii
import codecs
import ipaddress
import json
import logging
import logging.handlers
import os
import re
import socket
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
import winsound
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple

import FreeSimpleGUI as sg
import pyshark
import scapy.all as scp
import scapy.arch.windows as scpwinarch

try:
    import yara
except ImportError:
    yara = None  # YARA scanning just quietly disables itself if this isn't installed

# everything relative to this file, not cwd - otherwise running it from a
# different folder breaks all the paths below
BASE_DIR = Path(__file__).resolve().parent
RULES_FILE = BASE_DIR / "rules.txt"
TEMP_DIR = BASE_DIR / "temp"
SAVED_PCAP_DIR = BASE_DIR / "savedpcap"
YARA_RULES_DIR = BASE_DIR / "yara_rules"
TEMP_DIR.mkdir(exist_ok=True)
SAVED_PCAP_DIR.mkdir(exist_ok=True)
YARA_RULES_DIR.mkdir(exist_ok=True)

TCP_STREAM_PCAP = TEMP_DIR / "tcpstreamread.pcap"
HTTP_STREAM_PCAP = TEMP_DIR / "httpstreamread.pcap"

# log to console AND a rotating file - console output disappears if this
# is ever launched without a terminal attached, and I want a record of
# what happened even then. 2MB/5 backups is overkill but whatever
LOG_FILE_PATH = BASE_DIR / "nids.log"

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
log = logging.getLogger("nids")
log.setLevel(logging.INFO)
_log_formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")

_console_handler = logging.StreamHandler()
_console_handler.setFormatter(_log_formatter)
log.addHandler(_console_handler)

_file_handler = logging.handlers.RotatingFileHandler(
    str(LOG_FILE_PATH), maxBytes=2 * 1024 * 1024, backupCount=5, encoding="utf-8"
)
_file_handler.setFormatter(_log_formatter)
log.addHandler(_file_handler)

sg.theme("BluePurple")

# alerts get written here as they happen, so I still have history after
# closing the app (the in-memory list resets every time capture restarts)
ALERTS_DB_PATH = BASE_DIR / "alerts.db"

# don't want alerts.db growing forever, so anything older than this gets
# cleaned out on startup. set to 0 if you want to keep everything
ALERTS_RETENTION_DAYS = float(os.environ.get("NIDS_ALERTS_RETENTION_DAYS", "90"))

# packet list gets capped at this many entries (oldest dropped first) -
# without this a long capture on a busy connection just eats all your RAM
MAX_STORED_PACKETS = 20000

# point this at a TLS keylog file if you want pyshark to be able to decrypt
# HTTPS/HTTP2 streams when inspecting them later - empty means don't bother
SSLLOGFILEPATH = os.environ.get("NIDS_SSLKEYLOGFILE", "")

# same alert firing over and over (think a burst of DNS lookups) gets
# collapsed into one row with a counter instead of spamming the list
ALERT_DEDUP_WINDOW_SECONDS = 15.0

# port scan detection - not a rule, just built in. if one IP hits this many
# different ports in this many seconds, that's a scan as far as I'm concerned
PORTSCAN_DISTINCT_PORTS = 15
PORTSCAN_WINDOW_SECONDS = 5.0

# set this to a Slack/Discord/whatever webhook URL and every new alert gets
# POSTed there too, so I don't have to be staring at the GUI to notice
# something. runs on its own thread, so a dead webhook can't hang capture
WEBHOOK_URL = os.environ.get("NIDS_WEBHOOK_URL", "")

# every ~5 min (1200 ticks * 250ms) sweep out old tracking entries from the
# detectors below so they don't just accumulate forever if I leave this running
MAINTENANCE_INTERVAL_TICKS = 1200


def _tls_prefs() -> dict:
    if SSLLOGFILEPATH and os.path.exists(SSLLOGFILEPATH):
        return {"ssl.keylog_file": SSLLOGFILEPATH}
    return {}


def send_webhook_notification(message: str, src_ip: Optional[str], dst_ip: Optional[str]) -> None:
    # fire-and-forget POST to WEBHOOK_URL - runs on its own thread so a
    # slow endpoint can't stall capture
    if not WEBHOOK_URL:
        return

    def _send():
        payload = json.dumps(
            {"text": f"[NIDS] {message}", "message": message, "src_ip": src_ip, "dst_ip": dst_ip}
        ).encode("utf-8")
        req = urllib.request.Request(
            WEBHOOK_URL, data=payload, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            urllib.request.urlopen(req, timeout=5).close()
        except (urllib.error.URLError, OSError) as exc:
            log.warning("Webhook notification failed: %s", exc)

    threading.Thread(target=_send, daemon=True).start()


# Rule format, basically ripped off from Snort:
#   alert <proto> <srcip> <srcport> -> <destip> <destport> <message...>
#
# any field can just be "any". IPs take CIDR (192.168.1.0/24), ports take
# ranges like low:high (either side can be blank -> 0 or 65535).
#
# message can also have, in whatever order:
#   content:"text"   only match if this literal string shows up in the
#                    TCP/UDP payload, e.g. content:"PASS " for FTP creds
#   threshold: count N, seconds T
#                    don't alert on every hit, only once the same source
#                    IP has hit this rule N times in T seconds (then it
#                    resets). good for brute force / flood type stuff
#                    where a single hit is normal
#   redact           bare flag, no value. if this rule fires don't save or
#                    show the actual payload anywhere (GUI, alerts.db) -
#                    show a placeholder instead. use it on anything that's
#                    grabbing a password/secret via content: so it doesn't
#                    end up sitting around in plaintext later
_CONTENT_CLAUSE_RE = re.compile(r'content\s*:\s*"((?:[^"\\]|\\.)*)"')
REDACTED_PLACEHOLDER = "<payload redacted by rule - see 'redact' in README>"


@dataclass
class Rule:
    protocol: str
    src_ip: str
    src_port: str
    dst_ip: str
    dst_port: str
    message: str
    threshold_count: Optional[int] = None
    threshold_seconds: Optional[float] = None
    content: Optional[bytes] = None
    redact: bool = False

    @staticmethod
    def _ip_matches(rule_value: str, packet_ip: str) -> bool:
        if rule_value == "any":
            return True
        try:
            network = ipaddress.ip_network(rule_value, strict=False)
            return ipaddress.ip_address(packet_ip) in network
        except ValueError:
            return rule_value == packet_ip

    @staticmethod
    def _port_matches(rule_value: str, packet_port) -> bool:
        if rule_value == "any":
            return True
        if packet_port is None:
            return False
        if ":" in rule_value:
            lo_s, _, hi_s = rule_value.partition(":")
            try:
                lo = int(lo_s) if lo_s else 0
                hi = int(hi_s) if hi_s else 65535
            except ValueError:
                return False
            return lo <= int(packet_port) <= hi
        return rule_value == str(packet_port)

    def matches(self, proto: str, src_ip: str, src_port, dst_ip: str, dst_port, payload: bytes = b"") -> bool:
        if self.content is not None and self.content not in payload:
            return False
        return (
            (self.protocol == "any" or self.protocol == proto)
            and self._port_matches(self.src_port, src_port)
            and self._port_matches(self.dst_port, dst_port)
            and self._ip_matches(self.src_ip, src_ip)
            and self._ip_matches(self.dst_ip, dst_ip)
        )


def _read_rule_lines(rules_file: Path) -> List[str]:
    try:
        with open(rules_file, "r") as rf:
            lines = rf.readlines()
    except FileNotFoundError:
        log.warning("Rules file %s not found - no rules loaded.", rules_file)
        return []
    return [line for line in lines if line.strip().startswith("alert")]


def _parse_threshold_tokens(tokens: List[str]) -> Tuple[Optional[int], Optional[float]]:
    count = None
    seconds = None
    for i, tok in enumerate(tokens):
        clean = tok.strip(",").lower()
        if clean == "count" and i + 1 < len(tokens):
            try:
                count = int(tokens[i + 1].strip(","))
            except ValueError:
                pass
        elif clean == "seconds" and i + 1 < len(tokens):
            try:
                seconds = float(tokens[i + 1].strip(","))
            except ValueError:
                pass
    return count, seconds


def _parse_rule(line: str) -> Optional[Rule]:
    working = line.strip()

    # gotta grab content:"..." with regex first since it can have spaces in
    # it - can't just .split() the whole line or it'd get chopped up
    content: Optional[bytes] = None
    content_match = _CONTENT_CLAUSE_RE.search(working)
    if content_match:
        content = content_match.group(1).encode("utf-8", "replace")
        working = (working[: content_match.start()] + working[content_match.end():]).strip()

    words = working.split()
    if len(words) < 7 or words[4] != "->":
        log.warning("Skipping malformed rule: %r", line.strip())
        return None

    message_words = words[7:]

    # need to strip "redact" out before the threshold parsing below, since
    # that assumes everything after "threshold:" is its own
    redact = False
    filtered_words = []
    for w in message_words:
        if not redact and w.strip(",").lower() == "redact":
            redact = True
            continue
        filtered_words.append(w)
    message_words = filtered_words

    threshold_count = threshold_seconds = None
    if "threshold:" in message_words:
        idx = message_words.index("threshold:")
        threshold_count, threshold_seconds = _parse_threshold_tokens(message_words[idx + 1:])
        message_words = message_words[:idx]
        if threshold_count is None or threshold_seconds is None:
            log.warning("Ignoring malformed threshold clause in rule: %r", line.strip())
            threshold_count = threshold_seconds = None

    return Rule(
        protocol=words[1].lower(),
        src_ip=words[2].lower(),
        src_port=words[3],
        dst_ip=words[5].lower(),
        dst_port=words[6].lower(),
        message=" ".join(message_words),
        threshold_count=threshold_count,
        threshold_seconds=threshold_seconds,
        content=content,
        redact=redact,
    )


def load_rules(rules_file: Path = RULES_FILE) -> List[Rule]:
    rules = [r for r in (_parse_rule(line) for line in _read_rule_lines(rules_file)) if r is not None]
    log.info("Loaded %d rule(s) from %s", len(rules), rules_file)
    return rules


_rules_lock = threading.Lock()
_rules: List[Rule] = load_rules()


class RuleTracker:
    # keeps hit timestamps per (rule, source ip) for threshold: rules,
    # so a rule can wait until it's been hit N times before actually firing

    def __init__(self):
        self._lock = threading.Lock()
        self._hits: Dict[Tuple[int, str], Deque[float]] = defaultdict(deque)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()

    def hit(self, rule: Rule, src_ip: str, now: float) -> bool:
        # returns True the moment the threshold is actually hit
        key = (id(rule), src_ip)
        cutoff = now - rule.threshold_seconds
        with self._lock:
            dq = self._hits[key]
            dq.append(now)
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= rule.threshold_count:
                dq.clear()
                return True
            return False

    def purge_stale(self, max_age: float = 3600.0) -> int:
        # clears out entries nobody's hit in a while so this doesn't just
        # grow forever if I leave it running against a busy network.
        # thresholds are seconds/minutes normally so an hour of nothing
        # means it's safe to assume the entry is dead, not mid-count
        cutoff = time.time() - max_age
        with self._lock:
            stale_keys = []
            for key, dq in self._hits.items():
                while dq and dq[0] < cutoff:
                    dq.popleft()
                if not dq:
                    stale_keys.append(key)
            for key in stale_keys:
                del self._hits[key]
            return len(stale_keys)


_rule_tracker = RuleTracker()


def refresh_rules() -> None:
    global _rules
    new_rules = load_rules()
    with _rules_lock:
        _rules = new_rules
    _rule_tracker.reset()


def _current_rules() -> List[Rule]:
    with _rules_lock:
        return list(_rules)


# build this lookup once instead of scanning vars(socket) on every packet
_PROTO_NUMBERS: Dict[int, str] = {
    num: name[len("IPPROTO_"):].lower() for name, num in vars(socket).items() if name.startswith("IPPROTO_")
}


def proto_name_by_num(proto_num: int) -> str:
    return _PROTO_NUMBERS.get(proto_num, "unknown")


def ip_endpoints(pkt) -> Optional[Tuple[str, str, str]]:
    # handles v4 and v6 in one place. found out the hard way that scapy's
    # "IP" layer is v4-only - IPv6 packets are a totally separate "IPv6"
    # layer with a different field name for the protocol (nh, not proto),
    # so without this every rule was silently just ignoring all IPv6 traffic
    try:
        if pkt.haslayer("IP"):
            ip = pkt["IP"]
            return ip.src, ip.dst, proto_name_by_num(ip.proto)
        if pkt.haslayer("IPv6"):
            ip6 = pkt["IPv6"]
            return ip6.src, ip6.dst, proto_name_by_num(ip6.nh)
    except Exception:
        log.exception("Failed to read IP header fields")
    return None


# SQLite-backed alert log. unlike PacketStore below (which wipes itself
# every time you hit STARTCAP) this sticks around across restarts, so I can
# actually look back at what fired last week
class AlertLog:
    def __init__(self, db_path: Path):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    message TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    count INTEGER NOT NULL,
                    payload_text TEXT
                )
                """
            )
            self._conn.commit()
        self.prune(ALERTS_RETENTION_DAYS)

    def prune(self, retention_days: float) -> int:
        # gets called on startup automatically. pass 0 or less to skip it
        if retention_days <= 0:
            return 0
        cutoff = time.time() - retention_days * 86400
        with self._lock:
            cur = self._conn.execute("DELETE FROM alerts WHERE last_seen < ?", (cutoff,))
            self._conn.commit()
            deleted = cur.rowcount or 0
        if deleted:
            log.info("Pruned %d alert(s) older than %.0f days from alerts.db", deleted, retention_days)
        return deleted

    def insert(self, alert: "Alert", src_ip: Optional[str], dst_ip: Optional[str]) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts (first_seen, last_seen, message, summary, src_ip, dst_ip, count, payload_text) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (alert.last_seen, alert.last_seen, alert.message, alert.summary, src_ip, dst_ip, alert.count, alert.payload_text),
            )
            self._conn.commit()
            return cur.lastrowid

    def update_count(self, db_id: int, alert: "Alert") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE alerts SET last_seen = ?, message = ?, count = ?, payload_text = ? WHERE id = ?",
                (alert.last_seen, alert.message, alert.count, alert.payload_text, db_id),
            )
            self._conn.commit()

    def recent(self, limit: int = 200) -> List[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)))

    def close(self) -> None:
        with self._lock:
            self._conn.close()


alert_log = AlertLog(ALERTS_DB_PATH)


# pkt_process() below runs on the sniffer's own thread, GUI reads the same
# data on a timer - everything here goes through a lock so the two don't
# trip over each other
@dataclass
class Alert:
    index: int
    packet_index: int
    summary: str
    message: str
    payload_text: str
    packet: object
    count: int = 1
    last_seen: float = field(default_factory=time.time)
    db_id: Optional[int] = None

    def list_label(self) -> str:
        suffix = f"  (x{self.count})" if self.count > 1 else ""
        return f"[{self.index}] pkt#{self.packet_index} {self.summary}  ALERT: {self.message}{suffix}"


class PacketStore:
    def __init__(self):
        self._lock = threading.Lock()
        self.packets: Deque[object] = deque(maxlen=MAX_STORED_PACKETS)
        self.summaries: Deque[str] = deque(maxlen=MAX_STORED_PACKETS)
        self.alerts: List[Alert] = []
        self._next_packet_seq = 0
        # dedup key -> whichever Alert is currently soaking up repeats of it
        self._recent: Dict[tuple, Alert] = {}

    def reset(self) -> None:
        with self._lock:
            self.packets.clear()
            self.summaries.clear()
            self.alerts.clear()
            self._recent.clear()
            self._next_packet_seq = 0

    def add_packet(self, pkt) -> int:
        with self._lock:
            self.packets.append(pkt)
            self.summaries.append(pkt.summary())
            seq = self._next_packet_seq
            self._next_packet_seq += 1
            return seq

    def add_alert(
        self,
        packet_index: int,
        pkt,
        message: str,
        payload_text: str,
        dedup_key: Optional[tuple] = None,
    ) -> Alert:
        now = time.time()
        endpoints = ip_endpoints(pkt)
        src_ip, dst_ip = (endpoints[0], endpoints[1]) if endpoints is not None else (None, None)
        with self._lock:
            if dedup_key is not None:
                existing = self._recent.get(dedup_key)
                if existing is not None and (now - existing.last_seen) <= ALERT_DEDUP_WINDOW_SECONDS:
                    existing.count += 1
                    existing.last_seen = now
                    existing.message = message
                    existing.payload_text = payload_text
                    existing.packet = pkt
                    existing.packet_index = packet_index
                    if existing.db_id is not None:
                        alert_log.update_count(existing.db_id, existing)
                    return existing

            alert = Alert(
                index=len(self.alerts),
                packet_index=packet_index,
                summary=pkt.summary(),
                message=message,
                payload_text=payload_text,
                packet=pkt,
                last_seen=now,
            )
            self.alerts.append(alert)
            if dedup_key is not None:
                self._recent[dedup_key] = alert
            alert.db_id = alert_log.insert(alert, src_ip, dst_ip)
            return alert

    def snapshot(self) -> Tuple[List[str], List[Alert]]:
        with self._lock:
            return list(self.summaries), list(self.alerts)

    def get_packet(self, index: int):
        with self._lock:
            return self.packets[index] if 0 <= index < len(self.packets) else None

    def get_alert(self, index: int) -> Optional[Alert]:
        with self._lock:
            return self.alerts[index] if 0 <= index < len(self.alerts) else None

    def all_packets(self) -> List[object]:
        with self._lock:
            return list(self.packets)


store = PacketStore()


def _raw_payload_bytes(pkt) -> bytes:
    try:
        if pkt.haslayer("TCP"):
            return bytes(pkt["TCP"].payload)
        if pkt.haslayer("UDP"):
            return bytes(pkt["UDP"].payload)
    except Exception:
        log.exception("Failed to read raw TCP/UDP payload")
    return b""


def extract_payload_text(payload_bytes: bytes) -> str:
    if not payload_bytes:
        return "<no TCP/UDP payload>"
    try:
        return payload_bytes.decode("utf-8", "replace")
    except Exception:
        log.exception("Failed to decode payload")
        return "<error decoding payload>"


def check_rules_warning(pkt, now: float) -> Optional[Tuple[str, str]]:
    # this is the core rule-matching function, everything else builds on
    # it. returns (message, payload_text) if something matched, else None.
    # threshold rules won't return anything until RuleTracker says the
    # count's actually been hit
    endpoints = ip_endpoints(pkt)
    if endpoints is None:
        return None
    src, dst, proto = endpoints

    if pkt.haslayer("TCP"):
        sport, dport = pkt["TCP"].sport, pkt["TCP"].dport
    elif pkt.haslayer("UDP"):
        sport, dport = pkt["UDP"].sport, pkt["UDP"].dport
    else:
        sport, dport = None, None

    payload_bytes = _raw_payload_bytes(pkt)

    for rule in _current_rules():
        if not rule.matches(proto, src, sport, dst, dport, payload_bytes):
            continue

        if rule.threshold_count and rule.threshold_seconds:
            if not _rule_tracker.hit(rule, src, now):
                continue  # below threshold so far - not an alert yet
            message = (
                f"{rule.message} (threshold: {rule.threshold_count} hits in "
                f"{rule.threshold_seconds:.0f}s from {src})"
            )
        else:
            message = rule.message

        payload_text = REDACTED_PLACEHOLDER if rule.redact else extract_payload_text(payload_bytes)
        return message, payload_text

    return None


class PortScanDetector:
    # doesn't need a rule for this - if one IP touches a bunch of different
    # ports in a short window, that's a scan, flag it

    def __init__(self, distinct_ports: int = PORTSCAN_DISTINCT_PORTS, window: float = PORTSCAN_WINDOW_SECONDS):
        self.distinct_ports = distinct_ports
        self.window = window
        self._lock = threading.Lock()
        self._seen: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)

    def reset(self) -> None:
        with self._lock:
            self._seen.clear()

    def hit(self, src_ip: str, dport: int, now: float) -> Optional[int]:
        cutoff = now - self.window
        with self._lock:
            dq = self._seen[src_ip]
            dq.append((now, dport))
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            distinct = {p for _, p in dq}
            if len(distinct) >= self.distinct_ports:
                dq.clear()
                return len(distinct)
        return None

    def purge_stale(self, max_age: Optional[float] = None) -> int:
        # same idea as RuleTracker.purge_stale - default window is 12x the
        # detection window, should be plenty of margin
        cutoff = time.time() - (max_age if max_age is not None else self.window * 12)
        with self._lock:
            stale_keys = []
            for key, dq in self._seen.items():
                while dq and dq[0][0] < cutoff:
                    dq.popleft()
                if not dq:
                    stale_keys.append(key)
            for key in stale_keys:
                del self._seen[key]
            return len(stale_keys)


_portscan_detector = PortScanDetector()


class ArpSpoofDetector:
    # remembers which MAC claimed each IP over ARP. if that ever changes
    # for the same IP, that's classic ARP poisoning / MITM behavior

    def __init__(self):
        self._lock = threading.Lock()
        self._bindings: Dict[str, str] = {}  # ip -> mac

    def reset(self) -> None:
        with self._lock:
            self._bindings.clear()

    def hit(self, pkt) -> Optional[Tuple[str, str, str]]:
        if not pkt.haslayer("ARP"):
            return None
        arp = pkt["ARP"]
        if arp.op not in (1, 2):  # 1=who-has, 2=is-at, ignore anything else
            return None
        ip, mac = arp.psrc, arp.hwsrc
        if not ip or ip == "0.0.0.0" or not mac:
            return None
        with self._lock:
            previous = self._bindings.get(ip)
            self._bindings[ip] = mac
            if previous is not None and previous.lower() != mac.lower():
                return ip, previous, mac
        return None


_arp_spoof_detector = ArpSpoofDetector()


def _notify_new_alert(message: str, src_ip: Optional[str], dst_ip: Optional[str]) -> None:
    # only fires for genuinely new alerts, not dedup repeats - beep plus
    # webhook if I've bothered to set one up
    try:
        winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
    except Exception:
        log.debug("Alert beep failed", exc_info=True)
    send_webhook_notification(message, src_ip, dst_ip)


def _emit_alert(packet_index: int, pkt, message: str, payload_text: str, dedup_key: Optional[tuple] = None) -> None:
    endpoints = ip_endpoints(pkt)
    if dedup_key is None and endpoints is not None:
        dedup_key = (message, endpoints[0], endpoints[1])
    alert = store.add_alert(packet_index, pkt, message, payload_text, dedup_key=dedup_key)
    if alert.count > 1:
        log.info("ALERT (x%d) pkt#%d %s -- %s", alert.count, packet_index, pkt.summary(), message)
    else:
        log.info("ALERT pkt#%d %s -- %s", packet_index, pkt.summary(), message)
        src_ip, dst_ip = (endpoints[0], endpoints[1]) if endpoints is not None else (None, None)
        _notify_new_alert(message, src_ip, dst_ip)


def pkt_process(pkt) -> None:
    packet_index = store.add_packet(pkt)
    now = time.time()

    match = check_rules_warning(pkt, now)
    if match is not None:
        message, payload_text = match
        _emit_alert(packet_index, pkt, message, payload_text)

    endpoints = ip_endpoints(pkt)
    if endpoints is not None:
        if pkt.haslayer("TCP"):
            dport = pkt["TCP"].dport
        elif pkt.haslayer("UDP"):
            dport = pkt["UDP"].dport
        else:
            dport = None
        if dport is not None:
            src_ip = endpoints[0]
            distinct = _portscan_detector.hit(src_ip, dport, now)
            if distinct is not None:
                message = f"Possible port scan from {src_ip}: {distinct} distinct ports in {PORTSCAN_WINDOW_SECONDS:.0f}s"
                _emit_alert(
                    packet_index,
                    pkt,
                    message,
                    extract_payload_text(_raw_payload_bytes(pkt)),
                    dedup_key=("portscan", src_ip),
                )

    arp_hit = _arp_spoof_detector.hit(pkt)
    if arp_hit is not None:
        ip, old_mac, new_mac = arp_hit
        message = f"Possible ARP spoofing: {ip} now claims to be {new_mac} (was {old_mac})"
        _emit_alert(
            packet_index,
            pkt,
            message,
            f"ARP: {ip} switched from {old_mac} to {new_mac}",
            dedup_key=("arpspoof", ip),
        )


sniffer: Optional["scp.AsyncSniffer"] = None  # set once STARTCAP is clicked, see start_capture below


def _has_routable_ipv4(iface: dict) -> bool:
    for ip in iface.get("ips", []):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.version == 4 and not addr.is_link_local and not addr.is_loopback:
            return True
    return False


def list_capture_interfaces() -> Tuple[List[str], Dict[str, str], List[str]]:
    raw = scpwinarch.get_windows_if_list()
    with_ip = [i for i in raw if i.get("ips")]
    chosen = with_ip or raw
    labels: List[str] = []
    label_to_name: Dict[str, str] = {}
    preferred: List[str] = []
    for iface in chosen:
        label = f"{iface['description']} ({iface['name']})"
        labels.append(label)
        label_to_name[label] = iface["name"]
        if _has_routable_ipv4(iface):
            preferred.append(label)
    return labels, label_to_name, preferred


IFACE_LABELS, IFACE_LABEL_TO_NAME, IFACE_PREFERRED_LABELS = list_capture_interfaces()


def default_iface_label() -> str:
    # Windows lists like 40 virtual/pseudo adapters alongside the real one,
    # so try to default to whichever has an actual LAN address instead of
    # making the user hunt for "Wi-Fi" in a huge dropdown
    if IFACE_PREFERRED_LABELS:
        return IFACE_PREFERRED_LABELS[0]
    for label, name in IFACE_LABEL_TO_NAME.items():
        if "loopback" not in name.lower():
            return label
    return IFACE_LABELS[0] if IFACE_LABELS else ""


def start_capture(iface_name: str) -> None:
    global sniffer
    store.reset()
    _rule_tracker.reset()
    _portscan_detector.reset()
    _arp_spoof_detector.reset()
    sniffer = scp.AsyncSniffer(prn=pkt_process, filter="", iface=iface_name, store=False)
    sniffer.start()
    log.info("Capture started on interface: %s", iface_name)


def stop_capture() -> None:
    global sniffer
    if sniffer is not None and sniffer.running:
        sniffer.stop()
        log.info("Capture stopped")
    sniffer = None


# drop .yar/.yara files in yara_rules/ and anything read_http() pulls out
# of captured HTTP traffic gets scanned against them
_yara_rules_lock = threading.Lock()


def load_yara_rules(rules_dir: Path = YARA_RULES_DIR):
    # returns a compiled ruleset, or None if yara isn't installed / there's
    # nothing to compile - callers just treat None as "don't bother scanning"
    if yara is None:
        log.warning("yara-python isn't installed - YARA scanning is disabled")
        return None
    rule_files = sorted(list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara")))
    if not rule_files:
        log.info("No YARA rule files in %s - YARA scanning is disabled", rules_dir)
        return None
    try:
        compiled = yara.compile(filepaths={f.stem: str(f) for f in rule_files})
    except yara.Error:
        log.exception("Failed to compile YARA rules")
        return None
    log.info("Compiled %d YARA rule file(s) from %s", len(rule_files), rules_dir)
    return compiled


def refresh_yara_rules() -> None:
    global _yara_rules
    new_rules = load_yara_rules()
    with _yara_rules_lock:
        _yara_rules = new_rules


_yara_rules = load_yara_rules()


def scan_with_yara(data: bytes) -> List[str]:
    # names of whatever rules matched, empty list if nothing matched (or
    # there's nothing loaded to match against)
    with _yara_rules_lock:
        rules = _yara_rules
    if rules is None or not data:
        return []
    try:
        return [m.rule for m in rules.match(data=data)]
    except yara.Error:
        log.exception("YARA scan failed")
        return []


# pulls headers out of a raw HTTP response so read_http() can check the
# Content-Type and decide if there's a file worth grabbing
def get_http_headers(http_payload: bytes) -> Optional[Dict[bytes, bytes]]:
    try:
        header_end = http_payload.index(b"\r\n\r\n")
    except ValueError:
        return None

    headers: Dict[bytes, bytes] = {}
    for line in http_payload[:header_end].split(b"\r\n")[1:]:
        if b":" not in line:
            continue
        name, _, value = line.partition(b":")
        headers[name.strip().lower()] = value.strip()

    if b"content-type" not in headers:
        return None
    return headers


def extract_object(headers: Dict[bytes, bytes], http_payload: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
    content_type_filters = (b"application/x-msdownload", b"application/octet-stream")
    content_type = headers.get(b"content-type", b"")
    if not any(marker in content_type for marker in content_type_filters):
        return None, None
    try:
        header_end = http_payload.index(b"\r\n\r\n")
    except ValueError:
        return None, None
    body = http_payload[header_end + 4:]
    if not body:
        return None, None
    return body, content_type


def read_http(pkts: List[object]) -> Tuple[List[int], List[bytes], List[bytes]]:
    # rebuilds plain HTTP sessions and grabs anything that looks like a
    # downloaded file. called via perform_long_operation, not on the GUI thread
    objectlist: List[int] = []
    objectsactual: List[bytes] = []
    objectsactualtypes: List[bytes] = []

    try:
        os.remove(HTTP_STREAM_PCAP)
    except FileNotFoundError:
        pass
    scp.wrpcap(str(HTTP_STREAM_PCAP), pkts)
    sessions_all = scp.rdpcap(str(HTTP_STREAM_PCAP)).sessions()

    for session in sessions_all:
        http_payload = bytes()
        for pkt in sessions_all[session]:
            if not pkt.haslayer("TCP"):
                continue
            tcp = pkt["TCP"]
            if tcp.sport in (80, 8080) or tcp.dport in (80, 8080):
                if tcp.payload:
                    http_payload += scp.raw(tcp.payload)

        if not http_payload:
            continue
        headers = get_http_headers(http_payload)
        if headers is None:
            continue
        obj, obj_type = extract_object(headers, http_payload)
        if obj is None:
            continue
        objectlist.append(len(objectlist))
        objectsactual.append(obj)
        objectsactualtypes.append(obj_type)

        matches = scan_with_yara(obj)
        if matches:
            rep_pkt = sessions_all[session][0]  # just need something with an IP layer for the alert
            message = f"YARA match on downloaded file: {', '.join(matches)}"
            payload_text = f"{obj_type.decode('ascii', 'replace')}, {len(obj)} bytes, matched: {', '.join(matches)}"
            _emit_alert(-1, rep_pkt, message, payload_text)

    return objectlist, objectsactual, objectsactualtypes


# stream inspection stuff below uses pyshark instead of scapy - none of
# these touch the GUI directly, which matters because that means I can run
# them off perform_long_operation on a worker thread without things
# breaking, and just hand the result back to the main thread after
def build_tcp_and_http2_stream_lists(pkts: List[object]) -> Tuple[List[int], List[str]]:
    try:
        os.remove(TCP_STREAM_PCAP)
    except FileNotFoundError:
        pass
    scp.wrpcap(str(TCP_STREAM_PCAP), pkts)

    highest_stream = -1
    cap1 = pyshark.FileCapture(
        str(TCP_STREAM_PCAP),
        display_filter="tcp.seq==1 && tcp.ack==1 && tcp.len==0",
        keep_packets=True,
    )
    try:
        for pkt in cap1:
            if pkt.highest_layer.lower() in ("tcp", "tls"):
                highest_stream = max(highest_stream, int(pkt.tcp.stream))
    finally:
        cap1.close()
    tcpstreams = list(range(highest_stream + 1))

    http2streams: List[str] = []
    cap2 = pyshark.FileCapture(
        str(TCP_STREAM_PCAP),
        display_filter="http2.streamid",
        keep_packets=True,
        override_prefs=_tls_prefs(),
    )
    try:
        for pkt in cap2:
            try:
                stream_ids = {v for k, v in pkt.http2._all_fields.items() if k == "http2.streamid"}
            except AttributeError:
                continue
            for sid in stream_ids:
                if sid not in http2streams:
                    http2streams.append(sid)
    finally:
        cap2.close()

    return tcpstreams, http2streams


def build_tcp_stream_text(stream_number: int) -> str:
    cap = pyshark.FileCapture(
        str(TCP_STREAM_PCAP),
        display_filter=f"tcp.stream eq {stream_number}",
        override_prefs=_tls_prefs(),
    )
    decode_hex = codecs.getdecoder("hex_codec")
    data = b""
    try:
        for pkt in cap:
            try:
                payload = pkt.tcp.payload
            except AttributeError:
                continue
            try:
                data += decode_hex(payload.replace(":", ""))[0]
            except (binascii.Error, ValueError) as ex:
                log.debug("Could not hex-decode TCP payload: %s", ex)
    finally:
        cap.close()
    return data.decode("ascii", "replace")


def build_http2_stream_text(stream_id: str) -> str:
    cap = pyshark.FileCapture(
        str(TCP_STREAM_PCAP),
        display_filter=f"http2.streamid eq {stream_id}",
        override_prefs=_tls_prefs(),
    )
    frames: List[str] = []
    try:
        for pkt in cap:
            if not hasattr(pkt, "http2"):
                continue
            fields = [f"{field.split('.')[-1]}: {val}" for field, val in pkt.http2._all_fields.items()]
            frames.append("\n".join(fields))
    finally:
        cap.close()
    if not frames:
        return (
            "No HTTP/2 frame data found for this stream.\n"
            "If this traffic is TLS-encrypted, set the NIDS_SSLKEYLOGFILE "
            "environment variable to a TLS key log file before starting capture."
        )
    return "\n\n---\n\n".join(frames)


# ===== GUI stuff from here down =====

def _safe(func):
    # perform_long_operation just silently kills the thread if the function
    # raises - wrapping it like this means I actually get the exception
    # back as a value instead of it vanishing into nothing
    def wrapper():
        try:
            return func()
        except Exception as exc:  # yeah this is broad on purpose
            log.exception("Background operation failed")
            return exc

    return wrapper


def show_tcp_stream_openwin(tcpstreamtext: str) -> None:
    layout = [[sg.Multiline(tcpstreamtext, size=(100, 50), key="tcpnewwintext")]]
    win = sg.Window("TCP STREAM", layout, modal=True, size=(1200, 600), resizable=True)
    while True:
        event, _values = win.read()
        if event in (sg.WIN_CLOSED, "Exit"):
            break
    win.close()


def show_http2_stream_openwin(tcpstreamtext: str) -> None:
    layout = [[sg.Multiline(tcpstreamtext, size=(100, 50), key="tcpnewwintext")]]
    win = sg.Window("HTTP2 STREAM", layout, modal=True, size=(1200, 600), resizable=True)
    while True:
        event, _values = win.read()
        if event in (sg.WIN_CLOSED, "Exit"):
            break
    win.close()


def prompt_new_rule() -> Optional[str]:
    # little form for building a rule line without hand-editing rules.txt.
    # returns the finished line, or None if they closed/cancelled it
    layout = [
        [sg.Text("Protocol"), sg.Combo(["any", "tcp", "udp", "icmp"], default_value="any", key="proto", size=(8, 1))],
        [sg.Text("Source IP"), sg.Input("any", key="srcip", size=(20, 1)), sg.Text("Source port"), sg.Input("any", key="srcport", size=(10, 1))],
        [sg.Text("Dest IP"), sg.Input("any", key="dstip", size=(20, 1)), sg.Text("Dest port"), sg.Input("any", key="dstport", size=(10, 1))],
        [sg.Text("Message"), sg.Input(key="message", size=(40, 1))],
        [sg.Text("Payload contains (optional)"), sg.Input(key="content", size=(30, 1))],
        [
            sg.Text("Threshold: fire after"),
            sg.Input(key="tcount", size=(5, 1)),
            sg.Text("hits within"),
            sg.Input(key="tsec", size=(5, 1)),
            sg.Text("seconds (both optional)"),
        ],
        [sg.Button("Add", key="add", bind_return_key=True), sg.Button("Cancel", key="cancel")],
    ]
    win = sg.Window("New rule", layout, modal=True)
    line: Optional[str] = None
    try:
        while True:
            event, values = win.read()
            if event in (sg.WIN_CLOSED, "cancel"):
                break
            if event == "add":
                message = values["message"].strip()
                if not message:
                    sg.popup_error("A message is required.")
                    continue
                parts = [
                    "alert",
                    (values["proto"].strip() or "any"),
                    (values["srcip"].strip() or "any"),
                    (values["srcport"].strip() or "any"),
                    "->",
                    (values["dstip"].strip() or "any"),
                    (values["dstport"].strip() or "any"),
                    message,
                ]
                content = values["content"].strip()
                if content:
                    parts.append(f'content:"{content}"')
                tcount, tsec = values["tcount"].strip(), values["tsec"].strip()
                if tcount and tsec:
                    parts.append(f"threshold: count {tcount}, seconds {tsec}")
                elif tcount or tsec:
                    sg.popup_error("Threshold needs both a hit count and a number of seconds.")
                    continue
                line = " ".join(parts)
                if _parse_rule(line) is None:
                    sg.popup_error("That didn't parse as a valid rule - check the fields.")
                    line = None
                    continue
                break
    finally:
        win.close()
    return line


def show_alert_history_openwin() -> None:
    rows = alert_log.recent(limit=200)
    headings = ["id", "first_seen", "last_seen", "count", "src_ip", "dst_ip", "message"]
    data = [
        [
            r["id"],
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["first_seen"])),
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["last_seen"])),
            r["count"],
            r["src_ip"] or "",
            r["dst_ip"] or "",
            r["message"],
        ]
        for r in rows
    ]
    layout = [
        [sg.Text(f"Last {len(rows)} alert(s) from {ALERTS_DB_PATH.name} (persists across restarts)")],
        [sg.Table(values=data, headings=headings, auto_size_columns=True, size=(120, 25), key="table")],
        [sg.Button("Close")],
    ]
    win = sg.Window("Alert history", layout, modal=True, resizable=True)
    while True:
        event, _values = win.read()
        if event in (sg.WIN_CLOSED, "Close"):
            break
    win.close()


def build_layout():
    return [
        [
            sg.Text("Interface:"),
            sg.Combo(
                IFACE_LABELS,
                default_value=default_iface_label(),
                key="-iface-",
                size=(55, 1),
                readonly=True,
            ),
            sg.Button("STARTCAP", key="-startcap-"),
            sg.Button("STOPCAP", key="-stopcap-", disabled=True),
            sg.Button("SAVE ALERT", key="-savepcap-"),
            sg.Button("REFRESH RULES", key="-refreshrules-"),
            sg.Button("ADD RULE", key="-addrulebtn-"),
            sg.Button("REFRESH YARA RULES", key="-refreshyarabtn-"),
            sg.Button("ALERT HISTORY", key="-alerthistorybtn-"),
        ],
        [
            sg.Button("LOAD TCP/HTTP2 STREAMS", key="-showtcpstreamsbtn-"),
            sg.Button("LOAD HTTP STREAMS", key="-showhttpstreamsbtn-"),
            sg.Text("Filter:"),
            sg.Input(key="-filter-", size=(30, 1)),
            sg.Text("", key="-status-", size=(45, 1)),
        ],
        [
            sg.Text("ALERT PACKETS", font=("Arial Bold", 14), size=(60, None), justification="left"),
            sg.Text("ALL PACKETS", font=("Arial Bold", 14), size=(60, None), justification="left"),
        ],
        [
            sg.Listbox(key="-pkts-", size=(100, 20), enable_events=True, values=[]),
            sg.Listbox(key="-pktsall-", size=(100, 20), enable_events=True, values=[]),
        ],
        [
            sg.Text("PAYLOAD / PACKET DETAIL", font=("Arial Bold", 14), size=(35, None), justification="left"),
            sg.Text("HTTP2 STREAMS", font=("Arial Bold", 14), justification="left"),
            sg.Text("TCP STREAMS", font=("Arial Bold", 14), justification="left"),
            sg.Text("HTTP OBJECTS", font=("Arial Bold", 14), justification="left"),
        ],
        [
            sg.Multiline(size=(60, 20), key="-payloaddecoded-"),
            sg.Listbox(key="-http2streams-", size=(20, 20), values=[], enable_events=True),
            sg.Listbox(key="-tcpstreams-", size=(20, 20), values=[], enable_events=True),
            sg.Listbox(key="-httpobjects-", size=(20, 20), values=[], enable_events=True),
        ],
        [sg.Button("EXIT", key="-exit-")],
    ]


AUTHORIZATION_NOTICE = (
    "This NIDS captures and stores network traffic on whatever interface "
    "you select, including any cleartext data matched by your rules.\n\n"
    "Only run this on a network you own or are explicitly authorized to "
    "monitor - monitoring traffic you don't have authorization to observe "
    "can be illegal in most jurisdictions, and this makes no attempt to "
    "verify that for you.\n\n"
    "Do you confirm you are authorized to monitor this network?"
)


def confirm_authorization() -> bool:
    # deliberately asking this every single launch, not just once - being
    # allowed to monitor one network doesn't mean I'm allowed on the next
    # one this happens to run on
    return sg.popup_yes_no(AUTHORIZATION_NOTICE, title="Authorization required", keep_on_top=True) == "Yes"


def run_gui() -> None:
    if not confirm_authorization():
        log.info("Authorization not confirmed - exiting without starting.")
        return

    window = sg.Window("NIDS", build_layout(), size=(1600, 800), resizable=True)

    capturing = False
    tick_count = 0
    httpobjectactuals: List[bytes] = []
    httpobjecttypes: List[bytes] = []

    try:
        while True:
            event, values = window.read(timeout=250)

            if event in (sg.WIN_CLOSED, "-exit-"):
                break

            if event == sg.TIMEOUT_EVENT:
                tick_count += 1

                if capturing and sniffer is not None and not sniffer.running:
                    # sniffer thread can just die on its own (adapter got
                    # unplugged, driver hiccup, whatever) without me ever
                    # clicking STOPCAP - catch that instead of sitting here
                    # showing "Capturing..." while nothing's happening
                    log.warning("Capture thread stopped unexpectedly")
                    stop_capture()
                    capturing = False
                    window["-startcap-"].update(disabled=False)
                    window["-stopcap-"].update(disabled=True)
                    window["-iface-"].update(disabled=False)
                    window["-status-"].update(
                        "Capture stopped unexpectedly (adapter disconnected or driver error?)."
                    )

                if capturing:
                    summaries, alerts = store.snapshot()
                    filter_text = (values.get("-filter-") or "").strip().lower()
                    if filter_text:
                        summaries = [s for s in summaries if filter_text in s.lower()]
                        alert_labels = [
                            a.list_label() for a in alerts if filter_text in a.list_label().lower()
                        ]
                    else:
                        alert_labels = [a.list_label() for a in alerts]
                    window["-pktsall-"].update(summaries, scroll_to_index=max(0, len(summaries) - 1))
                    window["-pkts-"].update(alert_labels, scroll_to_index=max(0, len(alert_labels) - 1))
                    window.set_title(f"NIDS  [{len(alerts)} alert(s)]" if alerts else "NIDS")

                if tick_count % MAINTENANCE_INTERVAL_TICKS == 0:
                    dropped = _rule_tracker.purge_stale() + _portscan_detector.purge_stale()
                    if dropped:
                        log.info("Maintenance: purged %d stale detector-tracking entrie(s)", dropped)
                continue

            if event == "-refreshrules-":
                refresh_rules()
                window["-status-"].update(f"Rules reloaded ({len(_current_rules())} active).")

            elif event == "-addrulebtn-":
                line = prompt_new_rule()
                if line:
                    with open(RULES_FILE, "a") as rf:
                        rf.write("\n" + line + "\n")
                    refresh_rules()
                    window["-status-"].update(f"Added rule ({len(_current_rules())} active).")

            elif event == "-refreshyarabtn-":
                refresh_yara_rules()
                loaded = _yara_rules is not None
                window["-status-"].update(
                    "YARA rules reloaded." if loaded else "No YARA rules loaded (check yara_rules/)."
                )

            elif event == "-alerthistorybtn-":
                show_alert_history_openwin()

            elif event == "-startcap-":
                label = values["-iface-"]
                iface_name = IFACE_LABEL_TO_NAME.get(label)
                if not iface_name:
                    sg.popup_error("Choose a capture interface first.")
                else:
                    try:
                        start_capture(iface_name)
                    except Exception as exc:
                        log.exception("Failed to start capture")
                        sg.popup_error(
                            f"Could not start capture on {iface_name}:\n{exc}\n\n"
                            "On Windows this usually means Npcap isn't installed, "
                            "or nids.py isn't running as Administrator."
                        )
                    else:
                        capturing = True
                        window["-startcap-"].update(disabled=True)
                        window["-stopcap-"].update(disabled=False)
                        window["-iface-"].update(disabled=True)
                        window["-status-"].update(f"Capturing on {iface_name}...")

            elif event == "-stopcap-":
                stop_capture()
                capturing = False
                window["-startcap-"].update(disabled=False)
                window["-stopcap-"].update(disabled=True)
                window["-iface-"].update(disabled=False)
                window["-status-"].update("Capture stopped.")

            elif event == "-savepcap-":
                alerts = store.snapshot()[1]
                if not alerts:
                    sg.popup_auto_close("No alert packets captured yet.")
                else:
                    name = sg.popup_get_text("Save alert packets as:", default_text="alerts") or "alerts"
                    outfile = SAVED_PCAP_DIR / f"{name}.pcap"
                    scp.wrpcap(str(outfile), [a.packet for a in alerts])
                    window["-status-"].update(f"Saved {len(alerts)} alert packet(s) to {outfile}")

            elif event == "-pkts-":
                idx = window["-pkts-"].get_indexes()
                if idx:
                    alert = store.get_alert(idx[0])
                    if alert is not None:
                        window["-payloaddecoded-"].update(value=alert.payload_text)

            elif event == "-pktsall-":
                idx = window["-pktsall-"].get_indexes()
                if idx:
                    pkt = store.get_packet(idx[0])
                    if pkt is not None:
                        window["-payloaddecoded-"].update(value=pkt.show(dump=True))

            elif event == "-showtcpstreamsbtn-":
                window["-showtcpstreamsbtn-"].update(disabled=True)
                window["-status-"].update("Loading TCP/HTTP2 streams...")
                pkts = store.all_packets()
                window.perform_long_operation(
                    _safe(lambda: build_tcp_and_http2_stream_lists(pkts)), "-streamsloaded-"
                )

            elif event == "-streamsloaded-":
                window["-showtcpstreamsbtn-"].update(disabled=False)
                result = values[event]
                if isinstance(result, Exception):
                    sg.popup_error(f"Failed to load streams:\n{result}")
                    window["-status-"].update("Failed to load streams.")
                else:
                    tcpstreams, http2streams = result
                    window["-tcpstreams-"].update(values=tcpstreams)
                    window["-http2streams-"].update(values=http2streams)
                    window["-status-"].update(f"Loaded {len(tcpstreams)} TCP stream(s).")

            elif event == "-tcpstreams-":
                idx = window["-tcpstreams-"].get_indexes()
                if idx:
                    stream_no = idx[0]
                    window.perform_long_operation(
                        _safe(lambda: build_tcp_stream_text(stream_no)), "-tcpstreamtextloaded-"
                    )

            elif event == "-tcpstreamtextloaded-":
                text = values[event]
                if isinstance(text, Exception):
                    sg.popup_error(f"Failed to load TCP stream:\n{text}")
                elif not text.strip():
                    sg.popup_auto_close("No data")
                else:
                    show_tcp_stream_openwin(text)

            elif event == "-http2streams-":
                selected = values[event]
                if selected:
                    stream_id = selected[0]
                    window.perform_long_operation(
                        _safe(lambda: build_http2_stream_text(stream_id)), "-http2streamtextloaded-"
                    )

            elif event == "-http2streamtextloaded-":
                text = values[event]
                if isinstance(text, Exception):
                    sg.popup_error(f"Failed to load HTTP/2 stream:\n{text}")
                else:
                    show_http2_stream_openwin(text)

            elif event == "-showhttpstreamsbtn-":
                window["-showhttpstreamsbtn-"].update(disabled=True)
                window["-status-"].update("Extracting HTTP objects...")
                pkts = store.all_packets()
                window.perform_long_operation(_safe(lambda: read_http(pkts)), "-httpobjectsloaded-")

            elif event == "-httpobjectsloaded-":
                window["-showhttpstreamsbtn-"].update(disabled=False)
                result = values[event]
                if isinstance(result, Exception):
                    sg.popup_error(f"Failed to extract HTTP objects:\n{result}")
                    window["-status-"].update("Failed to extract HTTP objects.")
                else:
                    httpobjectindexes, httpobjectactuals, httpobjecttypes = result
                    window["-httpobjects-"].update(values=httpobjectindexes)
                    window["-status-"].update(f"Found {len(httpobjectindexes)} HTTP object(s).")

            elif event == "-httpobjects-":
                idx = window["-httpobjects-"].get_indexes()
                if idx and idx[0] < len(httpobjectactuals):
                    i = idx[0]
                    preview = httpobjectactuals[i][:900]
                    content_type = httpobjecttypes[i].decode("ascii", "replace")
                    show_http2_stream_openwin(f"Content-Type: {content_type}\n\n{preview!r}")
    finally:
        stop_capture()
        window.close()
        alert_log.close()


if __name__ == "__main__":
    run_gui()
    sys.exit(0)
