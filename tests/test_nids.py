"""
tests for nids.py - just run `pytest` from the project folder (or really
anywhere, this file adds the project root to sys.path itself so imports
work regardless of where you run it from).

everything here builds packets by hand with scapy and calls the detection
functions directly - no live capture, since that needs Npcap + admin and
a test suite shouldn't depend on that kind of thing to run.
"""

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scapy.all as scp

import nids


# --- parsing rule lines ---
def test_load_rules_parses_basic_fields(tmp_path):
    rules_file = tmp_path / "rules.txt"
    rules_file.write_text("alert udp any any -> any 53 DNS ALERT\n")
    rules = nids.load_rules(rules_file)
    assert len(rules) == 1
    r = rules[0]
    assert (r.protocol, r.src_ip, r.src_port, r.dst_ip, r.dst_port, r.message) == (
        "udp", "any", "any", "any", "53", "DNS ALERT",
    )


def test_load_rules_skips_malformed_lines(tmp_path):
    rules_file = tmp_path / "rules.txt"
    rules_file.write_text(
        "alert udp any any -> any 53 DNS ALERT\n"
        "alert tcp only-three-fields\n"  # too few fields
        "alert tcp any any BAD any 80 missing arrow\n"  # arrow in wrong place
        "not a rule line at all\n"
        "alert udp any any -> any 1900 SSDP ALERT\n"
    )
    rules = nids.load_rules(rules_file)
    assert [r.message for r in rules] == ["DNS ALERT", "SSDP ALERT"]


def test_load_rules_missing_file_returns_empty(tmp_path):
    assert nids.load_rules(tmp_path / "does-not-exist.txt") == []


def test_threshold_clause_parses_and_strips_from_message():
    rule = nids._parse_rule(
        "alert tcp any any -> any 22 Possible SSH brute force threshold: count 10, seconds 30"
    )
    assert rule.message == "Possible SSH brute force"
    assert rule.threshold_count == 10
    assert rule.threshold_seconds == 30.0


def test_malformed_threshold_clause_is_ignored_not_fatal():
    rule = nids._parse_rule("alert tcp any any -> any 22 SSH threshold: count banana")
    assert rule is not None
    assert rule.threshold_count is None
    assert rule.threshold_seconds is None


def test_content_clause_parses_and_strips_from_message():
    rule = nids._parse_rule(
        'alert tcp any any -> any 21 Cleartext creds content:"PASS "'
    )
    assert rule.content == b"PASS "
    assert rule.message == "Cleartext creds"


def test_content_and_threshold_together():
    rule = nids._parse_rule(
        'alert tcp any any -> any 21 Cleartext creds content:"PASS " threshold: count 3, seconds 10'
    )
    assert rule.content == b"PASS "
    assert rule.threshold_count == 3
    assert rule.message == "Cleartext creds"


def test_redact_flag_parses_and_strips_from_message():
    rule = nids._parse_rule('alert tcp any any -> any 21 Cleartext creds content:"PASS " redact')
    assert rule.redact is True
    assert rule.message == "Cleartext creds"
    assert rule.content == b"PASS "


def test_redact_flag_works_combined_with_threshold():
    rule = nids._parse_rule(
        "alert tcp any any -> any 22 Brute force redact threshold: count 5, seconds 10"
    )
    assert rule.redact is True
    assert rule.threshold_count == 5
    assert rule.message == "Brute force"


def test_rule_without_redact_defaults_false():
    rule = nids._parse_rule("alert udp any any -> any 53 DNS ALERT")
    assert rule.redact is False


def test_redacted_rule_never_stores_real_payload(monkeypatch):
    rule = nids._parse_rule(
        'alert tcp any any -> any 21 Cleartext creds content:"PASS " redact'
    )
    monkeypatch.setattr(nids, "_rules", [rule])

    pkt = scp.IP(src="1.1.1.1", dst="2.2.2.2") / scp.TCP(sport=1111, dport=21) / b"PASS hunter2\r\n"
    message, payload_text = nids.check_rules_warning(pkt, time.time())
    assert message == "Cleartext creds"
    assert payload_text == nids.REDACTED_PLACEHOLDER
    assert "hunter2" not in payload_text


def test_non_redacted_rule_still_shows_real_payload(monkeypatch):
    rule = nids._parse_rule('alert tcp any any -> any 21 Cleartext creds content:"PASS "')
    monkeypatch.setattr(nids, "_rules", [rule])

    pkt = scp.IP(src="1.1.1.1", dst="2.2.2.2") / scp.TCP(sport=1111, dport=21) / b"PASS hunter2\r\n"
    message, payload_text = nids.check_rules_warning(pkt, time.time())
    assert "hunter2" in payload_text


# --- does Rule.matches actually match right ---
def test_rule_matches_any_fields():
    rule = nids.Rule("any", "any", "any", "any", "any", "msg")
    assert rule.matches("tcp", "1.2.3.4", 1111, "5.6.7.8", 22)


def test_rule_matches_exact_fields():
    rule = nids.Rule("udp", "10.0.0.5", "any", "any", "53", "msg")
    assert rule.matches("udp", "10.0.0.5", 4000, "8.8.8.8", 53)
    assert not rule.matches("udp", "10.0.0.6", 4000, "8.8.8.8", 53)
    assert not rule.matches("tcp", "10.0.0.5", 4000, "8.8.8.8", 53)


def test_rule_matches_cidr():
    rule = nids.Rule("any", "192.168.1.0/24", "any", "any", "any", "msg")
    assert rule.matches("tcp", "192.168.1.42", 1, "1.1.1.1", 1)
    assert not rule.matches("tcp", "192.168.2.42", 1, "1.1.1.1", 1)


@pytest.mark.parametrize(
    "rule_port,packet_port,expected",
    [
        ("any", 12345, True),
        ("80", 80, True),
        ("80", 81, False),
        ("1024:2048", 1500, True),
        ("1024:2048", 1023, False),
        ("1024:2048", 2048, True),
        (":1024", 500, True),
        (":1024", 2000, False),
        ("60000:", 65000, True),
    ],
)
def test_rule_port_matches(rule_port, packet_port, expected):
    assert nids.Rule._port_matches(rule_port, packet_port) is expected


def test_rule_matches_ipv6_cidr():
    rule = nids.Rule("any", "2001:db8::/32", "any", "any", "any", "msg")
    assert rule.matches("udp", "2001:db8::1", 1, "::2", 53)
    assert not rule.matches("udp", "2001:db9::1", 1, "::2", 53)


def test_ipv4_rule_does_not_cross_match_ipv6_traffic():
    rule = nids.Rule("any", "192.168.1.0/24", "any", "any", "any", "msg")
    assert not rule.matches("udp", "::1", 1, "::2", 53)


def test_rule_content_gates_match():
    rule = nids.Rule("tcp", "any", "any", "any", "21", "msg", content=b"PASS ")
    assert rule.matches("tcp", "1.1.1.1", 1, "2.2.2.2", 21, payload=b"PASS secret\r\n")
    assert not rule.matches("tcp", "1.1.1.1", 1, "2.2.2.2", 21, payload=b"USER bob\r\n")


# --- RuleTracker, the threshold: state machine ---
def test_rule_tracker_fires_only_at_threshold_then_resets():
    rule = nids.Rule("tcp", "any", "any", "any", "22", "msg", threshold_count=3, threshold_seconds=5.0)
    tracker = nids.RuleTracker()
    now = time.time()
    results = [tracker.hit(rule, "1.2.3.4", now + i * 0.1) for i in range(5)]
    assert results == [False, False, True, False, False]


def test_rule_tracker_expires_old_hits_outside_window():
    rule = nids.Rule("tcp", "any", "any", "any", "22", "msg", threshold_count=2, threshold_seconds=1.0)
    tracker = nids.RuleTracker()
    now = time.time()
    assert tracker.hit(rule, "1.2.3.4", now) is False
    # second hit arrives after the window - shouldn't combine with the first
    assert tracker.hit(rule, "1.2.3.4", now + 10) is False


def test_rule_tracker_reset_clears_state():
    rule = nids.Rule("tcp", "any", "any", "any", "22", "msg", threshold_count=2, threshold_seconds=5.0)
    tracker = nids.RuleTracker()
    now = time.time()
    assert tracker.hit(rule, "1.2.3.4", now) is False
    tracker.reset()
    assert tracker.hit(rule, "1.2.3.4", now + 0.1) is False  # counter restarted, not at 2 yet


# --- port scan detector ---
def test_portscan_detector_fires_at_distinct_port_threshold():
    det = nids.PortScanDetector(distinct_ports=5, window=10.0)
    now = time.time()
    fired = [det.hit("9.9.9.9", port, now) for port in range(1, 8)]
    assert fired[:4] == [None, None, None, None]
    assert fired[4] == 5  # fires on the 5th distinct port
    assert fired[5] is None  # counter reset after firing


def test_portscan_detector_ignores_repeated_same_port():
    det = nids.PortScanDetector(distinct_ports=3, window=10.0)
    now = time.time()
    for _ in range(10):
        assert det.hit("9.9.9.9", 80, now) is None  # always the same port - never distinct enough


# --- arp spoof detector ---
def test_arp_spoof_detector_flags_mac_change():
    det = nids.ArpSpoofDetector()
    first = scp.Ether() / scp.ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa")
    changed = scp.Ether() / scp.ARP(op=2, psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:bb")
    assert det.hit(first) is None
    result = det.hit(changed)
    assert result == ("10.0.0.1", "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb")


def test_arp_spoof_detector_ignores_repeat_of_same_mac():
    det = nids.ArpSpoofDetector()
    pkt = scp.Ether() / scp.ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa")
    assert det.hit(pkt) is None
    assert det.hit(pkt) is None  # same MAC again - not a spoof


def test_arp_spoof_detector_ignores_non_arp_packets():
    det = nids.ArpSpoofDetector()
    pkt = scp.IP(src="1.1.1.1", dst="2.2.2.2") / scp.ICMP()
    assert det.hit(pkt) is None


# --- HTTP header/object parsing ---
def test_get_http_headers_parses_content_type():
    body = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 5\r\n\r\nHELLO"
    headers = nids.get_http_headers(body)
    assert headers[b"content-type"] == b"application/octet-stream"
    assert headers[b"content-length"] == b"5"


def test_get_http_headers_returns_none_without_content_type():
    body = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nbody"
    assert nids.get_http_headers(body) is None


def test_get_http_headers_returns_none_without_terminator():
    assert nids.get_http_headers(b"not a full http response") is None


def test_extract_object_matches_content_type_filters():
    body = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\nBINARYDATA"
    headers = nids.get_http_headers(body)
    obj, obj_type = nids.extract_object(headers, body)
    assert obj == b"BINARYDATA"
    assert obj_type == b"application/octet-stream"


def test_extract_object_ignores_uninteresting_content_type():
    body = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
    headers = nids.get_http_headers(body)
    obj, obj_type = nids.extract_object(headers, body)
    assert obj is None and obj_type is None


# --- PacketStore: dedup + the memory cap ---
@pytest.fixture
def isolated_alert_log(tmp_path, monkeypatch):
    # points nids.alert_log at a throwaway db so these tests don't touch
    # my actual alerts.db
    log = nids.AlertLog(tmp_path / "test-alerts.db")
    monkeypatch.setattr(nids, "alert_log", log)
    yield log
    log.close()


def _dns_pkt():
    return scp.IP(src="1.2.3.4", dst="5.6.7.8") / scp.UDP(sport=1234, dport=53) / b"q"


def test_add_alert_dedups_within_window(isolated_alert_log):
    store = nids.PacketStore()
    pkt = _dns_pkt()
    key = ("DNS ALERT", "1.2.3.4", "5.6.7.8")
    for _ in range(5):
        store.add_alert(0, pkt, "DNS ALERT", "payload", dedup_key=key)
    alerts = store.snapshot()[1]
    assert len(alerts) == 1
    assert alerts[0].count == 5
    assert "(x5)" in alerts[0].list_label()


def test_add_alert_reopens_new_row_after_window_expires(isolated_alert_log):
    store = nids.PacketStore()
    pkt = _dns_pkt()
    key = ("DNS ALERT", "1.2.3.4", "5.6.7.8")
    store.add_alert(0, pkt, "DNS ALERT", "payload", dedup_key=key)
    alerts = store.snapshot()[1]
    alerts[0].last_seen -= nids.ALERT_DEDUP_WINDOW_SECONDS + 1
    store.add_alert(1, pkt, "DNS ALERT", "payload", dedup_key=key)
    assert len(store.snapshot()[1]) == 2


def test_packet_store_bounds_memory(monkeypatch):
    monkeypatch.setattr(nids, "MAX_STORED_PACKETS", 5)
    store = nids.PacketStore()
    for _ in range(10):
        store.add_packet(scp.IP(src="1.1.1.1", dst="2.2.2.2") / scp.ICMP())
    assert len(store.all_packets()) == 5


def test_packet_store_reset_clears_dedup_state(isolated_alert_log):
    store = nids.PacketStore()
    pkt = _dns_pkt()
    key = ("DNS ALERT", "1.2.3.4", "5.6.7.8")
    store.add_alert(0, pkt, "DNS ALERT", "payload", dedup_key=key)
    store.reset()
    store.add_alert(1, pkt, "DNS ALERT", "payload", dedup_key=key)
    alerts = store.snapshot()[1]
    assert len(alerts) == 1
    assert alerts[0].count == 1  # fresh row, not merged with the pre-reset one


# --- alert log actually persists stuff ---
def test_alert_log_insert_and_update(tmp_path):
    log = nids.AlertLog(tmp_path / "alerts.db")
    try:
        alert = nids.Alert(
            index=0, packet_index=0, summary="s", message="m",
            payload_text="p", packet=None, last_seen=time.time(),
        )
        db_id = log.insert(alert, "1.2.3.4", "5.6.7.8")
        assert db_id is not None

        alert.count = 4
        alert.message = "m updated"
        log.update_count(db_id, alert)

        rows = log.recent()
        assert len(rows) == 1
        assert rows[0]["count"] == 4
        assert rows[0]["message"] == "m updated"
        assert rows[0]["src_ip"] == "1.2.3.4"
    finally:
        log.close()


def test_alert_log_persists_across_reopen(tmp_path):
    db_path = tmp_path / "alerts.db"
    log1 = nids.AlertLog(db_path)
    alert = nids.Alert(
        index=0, packet_index=0, summary="s", message="m",
        payload_text="p", packet=None, last_seen=time.time(),
    )
    log1.insert(alert, "1.1.1.1", "2.2.2.2")
    log1.close()

    log2 = nids.AlertLog(db_path)
    try:
        rows = log2.recent()
        assert len(rows) == 1
        assert rows[0]["src_ip"] == "1.1.1.1"
    finally:
        log2.close()


# --- full pipeline, check_rules_warning + pkt_process together ---
def test_check_rules_warning_matches_and_ignores(monkeypatch):
    rule = nids.Rule("udp", "any", "any", "any", "53", "DNS ALERT")
    monkeypatch.setattr(nids, "_rules", [rule])

    dns_pkt = scp.IP(src="10.0.0.5", dst="8.8.8.8") / scp.UDP(sport=51234, dport=53) / b"fakedns"
    other_pkt = scp.IP(src="10.0.0.5", dst="1.1.1.1") / scp.TCP(sport=443, dport=51234) / b"hello"

    now = time.time()
    assert nids.check_rules_warning(dns_pkt, now) == ("DNS ALERT", "fakedns")
    assert nids.check_rules_warning(other_pkt, now) is None


def test_check_rules_warning_sees_ipv6_traffic(monkeypatch):
    # regression test - rule matching used to only check scapy's "IP" layer,
    # which is v4 only, so IPv6 traffic just never matched anything, silently
    rule = nids.Rule("udp", "any", "any", "any", "53", "DNS ALERT")
    monkeypatch.setattr(nids, "_rules", [rule])

    dns_pkt_v6 = scp.IPv6(src="::1", dst="::2") / scp.UDP(sport=1234, dport=53) / b"ipv6dns"
    now = time.time()
    assert nids.check_rules_warning(dns_pkt_v6, now) == ("DNS ALERT", "ipv6dns")


def test_portscan_detector_sees_ipv6_sources(monkeypatch, isolated_alert_log):
    monkeypatch.setattr(nids, "_rules", [])
    monkeypatch.setattr(nids, "store", nids.PacketStore())
    nids._portscan_detector.reset()
    nids._rule_tracker.reset()
    nids._arp_spoof_detector.reset()

    now = time.time()
    for port in range(1, 20):
        pkt = scp.IPv6(src="2001:db8::dead", dst="2001:db8::beef") / scp.TCP(sport=4000, dport=port)
        nids.pkt_process(pkt)

    alerts = nids.store.snapshot()[1]
    assert any("port scan" in a.message.lower() for a in alerts)


def test_pkt_process_end_to_end(monkeypatch, isolated_alert_log):
    rule = nids.Rule("udp", "any", "any", "any", "53", "DNS ALERT")
    monkeypatch.setattr(nids, "_rules", [rule])
    monkeypatch.setattr(nids, "store", nids.PacketStore())
    nids._rule_tracker.reset()
    nids._portscan_detector.reset()
    nids._arp_spoof_detector.reset()

    pkt = scp.IP(src="10.0.0.5", dst="8.8.8.8") / scp.UDP(sport=51234, dport=53) / b"fakedns"
    nids.pkt_process(pkt)

    alerts = nids.store.snapshot()[1]
    assert len(alerts) == 1
    assert alerts[0].message == "DNS ALERT"


# --- stuff I added later: retention pruning, stale-entry cleanup, webhook ---
def test_alert_log_prune_removes_only_old_rows(tmp_path):
    log = nids.AlertLog(tmp_path / "alerts.db")
    try:
        old = nids.Alert(
            index=0, packet_index=0, summary="s", message="old",
            payload_text="p", packet=None, last_seen=time.time() - 200 * 86400,
        )
        recent = nids.Alert(
            index=1, packet_index=1, summary="s", message="recent",
            payload_text="p", packet=None, last_seen=time.time(),
        )
        log.insert(old, "1.1.1.1", "2.2.2.2")
        log.insert(recent, "1.1.1.1", "2.2.2.2")

        deleted = log.prune(retention_days=90)
        assert deleted == 1
        remaining = [dict(r)["message"] for r in log.recent()]
        assert remaining == ["recent"]
    finally:
        log.close()


def test_alert_log_prune_disabled_when_non_positive(tmp_path):
    log = nids.AlertLog(tmp_path / "alerts.db")
    try:
        old = nids.Alert(
            index=0, packet_index=0, summary="s", message="old",
            payload_text="p", packet=None, last_seen=time.time() - 999 * 86400,
        )
        log.insert(old, "1.1.1.1", "2.2.2.2")
        assert log.prune(retention_days=0) == 0
        assert len(log.recent()) == 1
    finally:
        log.close()


def test_rule_tracker_purge_stale_drops_old_entries():
    rule = nids.Rule("tcp", "any", "any", "any", "22", "msg", threshold_count=5, threshold_seconds=5.0)
    tracker = nids.RuleTracker()
    old_now = time.time() - 7200  # 2 hours ago
    tracker.hit(rule, "1.2.3.4", old_now)
    assert len(tracker._hits) == 1

    dropped = tracker.purge_stale(max_age=3600.0)
    assert dropped == 1
    assert len(tracker._hits) == 0


def test_rule_tracker_purge_stale_keeps_recent_entries():
    rule = nids.Rule("tcp", "any", "any", "any", "22", "msg", threshold_count=5, threshold_seconds=5.0)
    tracker = nids.RuleTracker()
    tracker.hit(rule, "1.2.3.4", time.time())
    assert tracker.purge_stale(max_age=3600.0) == 0
    assert len(tracker._hits) == 1


def test_portscan_detector_purge_stale_drops_old_entries():
    det = nids.PortScanDetector(distinct_ports=15, window=5.0)
    old_now = time.time() - 3600
    det.hit("9.9.9.9", 80, old_now)
    assert len(det._seen) == 1

    dropped = det.purge_stale(max_age=60.0)
    assert dropped == 1
    assert len(det._seen) == 0


def test_send_webhook_notification_posts_expected_json(monkeypatch):
    import http.server
    import threading as _threading

    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers["Content-Length"])
            import json as _json
            received.append(_json.loads(self.rfile.read(length)))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_port
    server_thread = _threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        monkeypatch.setattr(nids, "WEBHOOK_URL", f"http://127.0.0.1:{port}/hook")
        nids.send_webhook_notification("Test alert", "1.2.3.4", "5.6.7.8")
        # the POST happens on a background thread - give it a moment
        for _ in range(50):
            if received:
                break
            time.sleep(0.05)
        assert received
        assert received[0]["message"] == "Test alert"
        assert received[0]["src_ip"] == "1.2.3.4"
    finally:
        server.shutdown()


def test_send_webhook_notification_noop_when_unconfigured(monkeypatch):
    monkeypatch.setattr(nids, "WEBHOOK_URL", "")
    # Should simply return without raising or starting a thread.
    nids.send_webhook_notification("Test alert", "1.2.3.4", "5.6.7.8")


# --- YARA scanning of extracted HTTP objects ---
_TEST_YARA_SOURCE = """
rule test_eicar {
    strings:
        $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $a
}

rule test_pe {
    strings:
        $mz = { 4D 5A 40 00 }
    condition:
        $mz
}
"""


def test_load_yara_rules_compiles_directory(tmp_path):
    (tmp_path / "test.yara").write_text(_TEST_YARA_SOURCE)
    compiled = nids.load_yara_rules(tmp_path)
    assert compiled is not None
    matches = compiled.match(data=b"this contains EICAR-STANDARD-ANTIVIRUS-TEST-FILE somewhere")
    assert [m.rule for m in matches] == ["test_eicar"]


def test_load_yara_rules_returns_none_for_empty_dir(tmp_path):
    assert nids.load_yara_rules(tmp_path) is None


def test_load_yara_rules_returns_none_for_bad_syntax(tmp_path):
    (tmp_path / "broken.yara").write_text("this is not valid yara syntax {{{")
    assert nids.load_yara_rules(tmp_path) is None


def test_scan_with_yara_returns_matched_rule_names(tmp_path, monkeypatch):
    (tmp_path / "test.yara").write_text(_TEST_YARA_SOURCE)
    compiled = nids.load_yara_rules(tmp_path)
    monkeypatch.setattr(nids, "_yara_rules", compiled)

    assert nids.scan_with_yara(b"has EICAR-STANDARD-ANTIVIRUS-TEST-FILE inside") == ["test_eicar"]
    assert nids.scan_with_yara(b"nothing interesting here") == []


def test_scan_with_yara_returns_empty_when_nothing_loaded(monkeypatch):
    monkeypatch.setattr(nids, "_yara_rules", None)
    assert nids.scan_with_yara(b"anything at all") == []


def test_read_http_yara_match_creates_alert(tmp_path, monkeypatch, isolated_alert_log):
    (tmp_path / "test.yara").write_text(_TEST_YARA_SOURCE)
    monkeypatch.setattr(nids, "_yara_rules", nids.load_yara_rules(tmp_path))
    monkeypatch.setattr(nids, "store", nids.PacketStore())

    eicar_ish = b"X5O!P%@AP[4]EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    body = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: " + str(len(eicar_ish)).encode() + b"\r\n\r\n" + eicar_ish
    )
    ip = lambda s, d: scp.IP(src=s, dst=d)
    c, s = "10.0.0.5", "10.0.0.9"
    pkts = [
        ip(c, s) / scp.TCP(sport=51000, dport=80, flags="S", seq=0),
        ip(s, c) / scp.TCP(sport=80, dport=51000, flags="SA", seq=0, ack=1),
        ip(c, s) / scp.TCP(sport=51000, dport=80, flags="A", seq=1, ack=1),
        ip(s, c) / scp.TCP(sport=80, dport=51000, flags="PA", seq=1, ack=1) / body,
    ]

    objectlist, actuals, types = nids.read_http(pkts)
    assert len(objectlist) == 1

    alerts = nids.store.snapshot()[1]
    yara_alerts = [a for a in alerts if "YARA" in a.message]
    assert len(yara_alerts) == 1
    assert "test_eicar" in yara_alerts[0].message


def test_read_http_no_yara_alert_for_clean_download(tmp_path, monkeypatch, isolated_alert_log):
    (tmp_path / "test.yara").write_text(_TEST_YARA_SOURCE)
    monkeypatch.setattr(nids, "_yara_rules", nids.load_yara_rules(tmp_path))
    monkeypatch.setattr(nids, "store", nids.PacketStore())

    clean_body_data = b"just a boring harmless download, nothing malicious in here"
    body = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: " + str(len(clean_body_data)).encode() + b"\r\n\r\n" + clean_body_data
    )
    ip = lambda s, d: scp.IP(src=s, dst=d)
    c, s = "10.0.0.5", "10.0.0.9"
    pkts = [
        ip(c, s) / scp.TCP(sport=51000, dport=80, flags="S", seq=0),
        ip(s, c) / scp.TCP(sport=80, dport=51000, flags="SA", seq=0, ack=1),
        ip(c, s) / scp.TCP(sport=51000, dport=80, flags="A", seq=1, ack=1),
        ip(s, c) / scp.TCP(sport=80, dport=51000, flags="PA", seq=1, ack=1) / body,
    ]

    objectlist, actuals, types = nids.read_http(pkts)
    assert len(objectlist) == 1  # still extracted, just shouldn't trigger a YARA alert

    alerts = nids.store.snapshot()[1]
    assert not [a for a in alerts if "YARA" in a.message]
