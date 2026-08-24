"""Parser tests driven by crafted packets.

Synthetic packets appear ONLY here. The application itself never fabricates
traffic — these fixtures exist so that a parser can be proven to extract the
right fields from a known input.
"""
from __future__ import annotations

import pytest

scapy = pytest.importorskip("scapy.all")
from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, IPv6, Raw, TCP, UDP  # noqa: E402

from packetpulse.sensor import sensor  # noqa: E402


# ── HTTP parsing ─────────────────────────────────────────────────────────────

def test_http_request_fields_extracted():
    payload = (
        b"POST /account/login HTTP/1.1\r\n"
        b"Host: shop.example.com\r\n"
        b"User-Agent: Mozilla/5.0 (TestAgent)\r\n"
        b"Referer: https://shop.example.com/cart\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"user=alice&pass=hunter2"
    )
    parsed = sensor._parse_http(payload)
    assert parsed is not None
    assert parsed["type"] == "REQUEST"
    assert parsed["method"] == "POST"
    assert parsed["path"] == "/account/login"
    assert parsed["host"] == "shop.example.com"
    assert parsed["user_agent"] == "Mozilla/5.0 (TestAgent)"
    assert parsed["referer"] == "https://shop.example.com/cart"
    assert "alice" in parsed["body"]


def test_http_response_fields_extracted():
    payload = (
        b"HTTP/1.1 301 Moved Permanently\r\n"
        b"Server: nginx/1.24.0\r\n"
        b"Content-Type: text/html\r\n"
        b"Set-Cookie: sid=abc123\r\n"
        b"\r\n"
    )
    parsed = sensor._parse_http(payload)
    assert parsed["type"] == "RESPONSE"
    assert parsed["status_code"] == "301"
    assert parsed["server"] == "nginx/1.24.0"
    assert parsed["set_cookie"] == "sid=abc123"


def test_non_http_payload_returns_none():
    assert sensor._parse_http(b"\x16\x03\x01\x00\xa5binarygarbage") is None
    assert sensor._parse_http(b"") is None


# ── DNS parsing ──────────────────────────────────────────────────────────────

def test_dns_query_parsed():
    pkt = IP() / UDP() / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    parsed = sensor._parse_dns_pkt(pkt)
    assert parsed["type"] == "QUERY"
    assert parsed["query"] == "example.com"
    assert parsed["qtype"] == "A"


def test_dns_response_answers_parsed():
    pkt = IP() / UDP() / DNS(
        qr=1, qd=DNSQR(qname="example.com"),
        an=DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34"),
    )
    parsed = sensor._parse_dns_pkt(pkt)
    assert parsed["type"] == "RESPONSE"
    assert parsed["answers"]
    assert parsed["answers"][0]["data"] == "93.184.216.34"


def test_dns_nxdomain_rcode_preserved():
    pkt = IP() / UDP() / DNS(qr=1, rcode=3, qd=DNSQR(qname="nope.invalid"))
    assert sensor._parse_dns_pkt(pkt)["rcode"] == 3


# ── Layer extraction through the real packet path ────────────────────────────

def _process(pkt):
    """Push a packet through the real processing path and return its record."""
    sensor._reset_session_state()
    sensor._process_packet(pkt)
    records = list(sensor._packet_log)
    assert records, "packet produced no record"
    return records[-1]


def test_ipv4_tcp_layers_recorded():
    pkt = (Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
           / IP(src="10.0.0.5", dst="93.184.216.34", ttl=57)
           / TCP(sport=51000, dport=443, flags="S", window=64240, seq=1000))
    rec = _process(pkt)
    assert rec["proto"] == "TCP"
    assert rec["src_ip"] == "10.0.0.5"
    assert rec["dst_ip"] == "93.184.216.34"
    assert rec["ttl"] == 57
    assert rec["src_port"] == 51000 and rec["dst_port"] == 443
    assert "SYN" in rec["tcp_flags"]
    assert rec["window"] == 64240
    assert rec["mac_src"] == "aa:bb:cc:dd:ee:ff"


def test_ipv6_recorded():
    pkt = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=1, dport=2)
    rec = _process(pkt)
    assert rec["src_ip"] == "2001:db8::1"
    assert rec["proto"] == "UDP"


def test_arp_recorded():
    from scapy.all import ARP
    pkt = Ether() / ARP(psrc="192.168.1.10", pdst="192.168.1.1")
    rec = _process(pkt)
    assert rec["proto"] == "ARP"
    assert rec["src_ip"] == "192.168.1.10"


def test_icmp_recorded():
    from scapy.all import ICMP
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
    rec = _process(pkt)
    assert rec["proto"] == "ICMP"


def test_cleartext_http_promotes_protocol_and_counts():
    payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt = (Ether() / IP(src="10.0.0.5", dst="93.184.216.34")
           / TCP(sport=51000, dport=80) / Raw(load=payload))
    rec = _process(pkt)
    assert rec["proto"] == "HTTP"
    assert rec["http"]["host"] == "example.com"
    assert sensor._stats["http"] == 1


# ── TLS SNI extraction ───────────────────────────────────────────────────────

def _client_hello(hostname: bytes) -> bytes:
    """Minimal but structurally valid TLS ClientHello carrying an SNI."""
    sni_host = hostname
    server_name = b"\x00" + len(sni_host).to_bytes(2, "big") + sni_host
    sni_list = len(server_name).to_bytes(2, "big") + server_name
    ext_sni = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    extensions = len(ext_sni).to_bytes(2, "big") + ext_sni

    body = (
        b"\x03\x03"          # client version
        + b"\x00" * 32       # random
        + b"\x00"            # session id length
        + b"\x00\x02\x13\x01"  # cipher suites
        + b"\x01\x00"        # compression methods
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def test_sni_extracted_from_client_hello():
    from packetpulse.urlscan import url_scanner
    assert url_scanner._extract_sni_from_tls(_client_hello(b"secure.example.org")) == "secure.example.org"


def test_sni_extraction_rejects_non_tls():
    from packetpulse.urlscan import url_scanner
    assert url_scanner._extract_sni_from_tls(b"GET / HTTP/1.1\r\n\r\n") is None
    assert url_scanner._extract_sni_from_tls(b"") is None
    # Truncated record must not raise.
    assert url_scanner._extract_sni_from_tls(_client_hello(b"x.example")[:20]) is None


def test_http_url_extracted_from_request():
    from packetpulse.urlscan import url_scanner
    raw = b"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    assert url_scanner._extract_url_from_http(raw) == "http://example.com/path?q=1"
    assert url_scanner._extract_url_from_http(b"garbage") is None
